//! Actual SDK/WebSocket regression: partial receipts must survive exact retries.
use std::net::SocketAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use cgka_traits::TransportEndpoint;
use nostr::{Event, Kind};
use nostr_relay_builder::prelude::{
    BoxedFuture, LocalRelay, PolicyResult, RelayBuilder, WritePolicy,
};
use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};
use transport_nostr_peeler::NostrTransportEvent;

use crate::preparation::{ExactPublisher, publish_pending, tests::JournaledFixture};

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    phase: usize,
    bytes: Vec<u8>,
    accepted: bool,
}

#[derive(Debug)]
struct AlternatingPolicy {
    relay: usize,
    phase: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Observation>>>,
}
impl WritePolicy for AlternatingPolicy {
    fn admit_event<'a>(
        &'a self,
        event: &'a Event,
        _: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let phase = self.phase.load(Ordering::SeqCst);
            let accepted = (phase == 1 && self.relay == 0) || (phase == 2 && self.relay == 1);
            if event.kind == Kind::Custom(30443) {
                event.verify().unwrap();
                let original = NostrTransportEvent::from_nostr_event(event).unwrap();
                self.seen.lock().unwrap().push(Observation {
                    phase,
                    bytes: serde_json::to_vec(&original).unwrap(),
                    accepted,
                });
            }
            if accepted {
                PolicyResult::Accept
            } else {
                PolicyResult::Reject("blocked: alternating fixture".into())
            }
        })
    }
}

#[tokio::test]
async fn actual_sdk_partial_receipts_union_promotes_only_after_exact_retry() {
    let phase = Arc::new(AtomicUsize::new(0));
    let seen = [
        Arc::new(Mutex::new(Vec::new())),
        Arc::new(Mutex::new(Vec::new())),
    ];
    let mut relays = Vec::new();
    let mut endpoints = Vec::new();
    for (relay, log) in seen.iter().enumerate() {
        let server = LocalRelay::new(RelayBuilder::default().write_policy(AlternatingPolicy {
            relay,
            phase: phase.clone(),
            seen: log.clone(),
        }));
        server.run().await.unwrap();
        endpoints.push(TransportEndpoint(server.url().await.to_string()));
        relays.push(server);
    }
    // No signer belongs to the SDK adapter: both attempts must use the one
    // native retained private package and its already signed original event.
    let sdk = Arc::new(NostrSdkRelayClient::new(
        nostr_sdk::Client::builder().build(),
    ));
    let fixture =
        JournaledFixture::create(endpoints.clone(), sdk.clone(), 2, Duration::from_secs(5)).await;
    for artifact in &fixture.setup {
        let event = serde_json::from_slice(&artifact.bytes).unwrap();
        for stage in [1, 2] {
            phase.store(stage, Ordering::SeqCst);
            let outcome = fixture
                .relay
                .publish_event(&endpoints, &event, 2)
                .await
                .unwrap();
            assert_eq!(outcome.accepted.len(), stage);
        }
    }
    assert!(fixture.relay.published(&fixture._generation).await.is_err());
    let original = fixture.prepared.artifact.bytes.clone();
    let publisher = || {
        ExactPublisher::new(
            fixture.prepared.clone(),
            fixture.relay.clone(),
            2,
            Duration::from_secs(5),
        )
        .unwrap()
    };

    phase.store(1, Ordering::SeqCst);
    assert!(
        publish_pending(&fixture.database, &fixture.key, &fixture.keys, publisher())
            .await
            .is_err()
    );
    let records = fixture.records();
    let partial = records.last().unwrap();
    assert_eq!(partial["attempt"]["state"], "reported");
    assert_eq!(
        partial["accepted"][2],
        serde_json::json!([endpoints[0].as_str()])
    );
    assert!(fixture.relay.published(&fixture._generation).await.is_err());
    assert!(
        fixture
            .records()
            .iter()
            .all(|record| record["phase"] != "published")
    );

    phase.store(2, Ordering::SeqCst);
    publish_pending(&fixture.database, &fixture.key, &fixture.keys, publisher())
        .await
        .unwrap();
    let records = fixture.records();
    let cumulative = records.last().unwrap()["accepted"][2].as_array().unwrap();
    assert_eq!(cumulative.len(), 2);
    for endpoint in &endpoints {
        assert!(cumulative.contains(&serde_json::json!(endpoint.as_str())));
    }
    // This transition independently reopens native SQLCipher lifecycle and
    // compares current package, private material, retained signed event+slot.
    fixture.relay.published(&fixture._generation).await.unwrap();
    assert_eq!(fixture.records().last().unwrap()["phase"], "published");
    for (relay, log) in seen.iter().enumerate() {
        let actual = log.lock().unwrap();
        // SDK quorum-one completion may cancel the other relay's send.
        // Assert the actual positive causal receipt, not scheduling of rejection.
        assert!(actual.iter().any(|o| o.accepted && o.phase == relay + 1));
        for observation in actual.iter() {
            assert_eq!(observation.bytes, original);
            assert_eq!(
                observation.accepted,
                (observation.phase == 1 && relay == 0) || (observation.phase == 2 && relay == 1)
            );
        }
    }
    assert_eq!(sdk.relay_health().await.total_relays, 0);
    for relay in relays {
        relay.shutdown();
    }
}

#[derive(Debug)]
struct SlowPositive {
    delay: Duration,
    received: Arc<AtomicUsize>,
}
impl WritePolicy for SlowPositive {
    fn admit_event<'a>(
        &'a self,
        event: &'a Event,
        _: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            if event.kind == Kind::Custom(30443) {
                self.received.fetch_add(1, Ordering::SeqCst);
            }
            tokio::time::sleep(self.delay).await;
            PolicyResult::Accept
        })
    }
}
#[tokio::test]
async fn actual_sdk_slow_positive_is_retried_without_resending_fast_accepted_endpoint() {
    let received = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let mut relays = Vec::new();
    let mut endpoints = Vec::new();
    for (ordinal, count) in received.iter().enumerate() {
        let relay = LocalRelay::new(RelayBuilder::default().write_policy(SlowPositive {
            delay: Duration::from_millis(if ordinal == 0 { 0 } else { 250 }),
            received: count.clone(),
        }));
        relay.run().await.unwrap();
        endpoints.push(TransportEndpoint(relay.url().await.to_string()));
        relays.push(relay);
    }
    let sdk = Arc::new(NostrSdkRelayClient::new(
        nostr_sdk::Client::builder().build(),
    ));
    let fixture = JournaledFixture::create(endpoints.clone(), sdk, 2, Duration::from_secs(5)).await;
    for artifact in &fixture.setup {
        let event = serde_json::from_slice(&artifact.bytes).unwrap();
        for _ in 0..2 {
            if fixture
                .relay
                .publish_event(&endpoints, &event, 2)
                .await
                .unwrap()
                .accepted
                .len()
                == 2
            {
                break;
            }
        }
    }
    let original = fixture.prepared.artifact.bytes.clone();
    for _ in 0..2 {
        let publisher = ExactPublisher::new(
            fixture.prepared.clone(),
            fixture.relay.clone(),
            2,
            Duration::from_secs(5),
        )
        .unwrap();
        if publish_pending(&fixture.database, &fixture.key, &fixture.keys, publisher)
            .await
            .is_ok()
        {
            break;
        }
    }
    assert_eq!(fixture.prepared.artifact.bytes, original);
    assert_eq!(
        received[0].load(Ordering::SeqCst),
        1,
        "retained fast positive must not be resent"
    );
    assert!(received[1].load(Ordering::SeqCst) >= 1);
    let count = received.each_ref().map(|n| n.load(Ordering::SeqCst));
    let event = serde_json::from_slice(&original).unwrap();
    assert_eq!(
        fixture
            .relay
            .publish_event(&endpoints, &event, 2)
            .await
            .unwrap()
            .accepted
            .len(),
        2
    );
    assert_eq!(
        received.each_ref().map(|n| n.load(Ordering::SeqCst)),
        count,
        "complete retained union is readback-only"
    );
    fixture.relay.published(&fixture._generation).await.unwrap();
    drop(relays);
}
