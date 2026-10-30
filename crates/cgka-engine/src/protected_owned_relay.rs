//! Ephemeral FIFO decouples relay replay from native/journal latency. It is not
//! retained authority: loss, I/O error or SDK notification lag still ends intake.
use super::*;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Notify;

const MAX_NOTIFICATION: usize = 2 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
enum Item {
    Event {
        endpoint: TransportEndpoint,
        subscription: String,
        event: transport_nostr_peeler::NostrTransportEvent,
    },
    Eose {
        endpoint: TransportEndpoint,
        subscription: String,
    },
}
pub(super) fn anonymous(directory: &File) -> Result<File, ReceiverHold> {
    let meta = directory
        .metadata()
        .map_err(|_| ReceiverHold::Configuration)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o777 != 0o700 {
        return Err(ReceiverHold::Configuration);
    }
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(ReceiverHold::Journal);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
struct Spool {
    file: File,
    end: AtomicU64,
    dispatched: AtomicU64,
    ready: Notify,
}
impl Spool {
    fn append(&self, item: &Item) -> Result<(), ReceiverHold> {
        let bytes = serde_json::to_vec(item).map_err(|_| ReceiverHold::Malformed)?;
        if bytes.len() > MAX_NOTIFICATION {
            return Err(ReceiverHold::Capacity);
        }
        let at = self.end.load(Ordering::Relaxed);
        let end = at
            .checked_add(bytes.len() as u64 + 4)
            .ok_or(ReceiverHold::Capacity)?;
        self.file
            .write_all_at(&(bytes.len() as u32).to_be_bytes(), at)
            .and_then(|_| self.file.write_all_at(&bytes, at + 4))
            .map_err(|_| ReceiverHold::Journal)?;
        self.end.store(end, Ordering::Release);
        self.ready.notify_one();
        Ok(())
    }
    async fn next(&self, at: &mut u64) -> Result<Item, ReceiverHold> {
        loop {
            let ready = self.ready.notified();
            if *at < self.end.load(Ordering::Acquire) {
                break;
            }
            ready.await;
        }
        let mut length = [0; 4];
        self.file
            .read_exact_at(&mut length, *at)
            .map_err(|_| ReceiverHold::Journal)?;
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_NOTIFICATION {
            return Err(ReceiverHold::Journal);
        }
        let mut bytes = vec![0; length];
        self.file
            .read_exact_at(&mut bytes, *at + 4)
            .map_err(|_| ReceiverHold::Journal)?;
        *at = at
            .checked_add(length as u64 + 4)
            .ok_or(ReceiverHold::Capacity)?;
        serde_json::from_slice(&bytes).map_err(|_| ReceiverHold::Journal)
    }
}
struct Drain(tokio::task::JoinHandle<()>);
impl Drop for Drain {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) struct Forwarder {
    task: tokio::task::JoinHandle<()>,
    spool: Arc<Spool>,
}
impl Forwarder {
    pub(super) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
    pub(super) fn is_drained(&self) -> bool {
        self.spool.dispatched.load(Ordering::Acquire) == self.spool.end.load(Ordering::Acquire)
    }
    pub(super) fn abort(&self) {
        self.task.abort();
    }
}
impl std::future::Future for Forwarder {
    type Output = Result<(), tokio::task::JoinError>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.task).poll(cx)
    }
}
impl Drop for Forwarder {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(super) fn forward(
    mut notifications: tokio::sync::broadcast::Receiver<nostr_sdk::RelayPoolNotification>,
    adapter: NostrTransportAdapter,
    file: File,
) -> Forwarder {
    let spool = Arc::new(Spool {
        file,
        end: AtomicU64::new(0),
        dispatched: AtomicU64::new(0),
        ready: Notify::new(),
    });
    let writer = spool.clone();
    let task = tokio::spawn(async move {
        let spool = writer;
        let reader = spool.clone();
        let mut drain = Drain(tokio::spawn(async move {
            let mut at = 0;
            while let Ok(item) = reader.next(&mut at).await {
                match item {
                    Item::Event {
                        endpoint,
                        subscription,
                        event,
                    } => {
                        if matches!(
                            adapter
                                .handle_relay_event(transport_nostr_adapter::NostrRelayEvent {
                                    endpoint,
                                    subscription_id: Some(subscription),
                                    event
                                })
                                .await,
                            Err(cgka_traits::TransportAdapterError::Closed)
                        ) {
                            return;
                        }
                    }
                    Item::Eose {
                        endpoint,
                        subscription,
                    } => adapter.handle_relay_eose(endpoint, subscription).await,
                }
                reader.dispatched.store(at, Ordering::Release);
            }
        }));
        let mut rejected = 0u64;
        loop {
            let notification = tokio::select! {
                _ = &mut drain.0 => return,
                result = notifications.recv() => match result { Ok(value) => value, Err(_) => return },
            };
            let item = match notification {
                nostr_sdk::RelayPoolNotification::Event {
                    relay_url,
                    subscription_id,
                    event,
                } => {
                    let Ok(event) =
                        transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&event)
                    else {
                        rejected = rejected.saturating_add(1);
                        continue;
                    };
                    // No native effect has occurred; larger DTOs cannot be admitted
                    // by the receiver's per-wire bound. Do not fill the spool.
                    if event.content.len() > 1024 * 1024 {
                        rejected = rejected.saturating_add(1);
                        continue;
                    }
                    Item::Event {
                        endpoint: TransportEndpoint(relay_url.to_string()),
                        subscription: subscription_id.to_string(),
                        event,
                    }
                }
                nostr_sdk::RelayPoolNotification::Message {
                    relay_url,
                    message: nostr::RelayMessage::EndOfStoredEvents(subscription),
                } => Item::Eose {
                    endpoint: TransportEndpoint(relay_url.to_string()),
                    subscription: subscription.to_string(),
                },
                nostr_sdk::RelayPoolNotification::Shutdown => return,
                _ => continue,
            };
            if spool.append(&item).is_err() {
                return;
            }
            tracing::trace!(target: "cgka_engine::protected_receiver", rejected, "relay notification spooled");
        }
    });
    Forwarder { task, spool }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stalled_adapter_spools_history_beyond_both_old_buffers_without_losing_eose() {
        use nostr::{EventBuilder, Kind, Tag, TagKind};
        let (factory, _, _, relay) = super::super::super::tests::fixture().await;
        let adapter = factory.transport.clone();
        adapter
            .activate_account(TransportAccountActivation {
                account_id: factory.receiver.engine.self_id(),
                inbox_endpoints: vec![],
                group_subscriptions: vec![TransportGroupSubscription {
                    group_id: factory.receiver.group.clone(),
                    transport_group_id: vec![7; 32],
                    endpoints: factory.endpoints.clone(),
                }],
                since: None,
            })
            .await
            .unwrap();
        let subscriptions = relay.subscriptions.lock().unwrap().clone();
        let subscription = subscriptions[0].subscription_id().to_owned();
        let expected_count = 5200 + subscriptions.len();
        let file = tempfile::tempfile().unwrap();
        let inspect = file.try_clone().unwrap();
        let (tx, rx) = tokio::sync::broadcast::channel(4096);
        let forwarder = forward(rx, adapter.clone(), file);
        let key = nostr::Keys::generate();
        let mut expected = Vec::new();
        for index in 0..5200 {
            let event = EventBuilder::new(Kind::MlsGroupMessage, index.to_string())
                .tags([Tag::custom(TagKind::custom("h"), [hex::encode([7; 32])])])
                .sign_with_keys(&key)
                .unwrap();
            expected.push(event.id.to_hex());
            tx.send(nostr_sdk::RelayPoolNotification::Event {
                relay_url: "wss://semantic.invalid".parse().unwrap(),
                subscription_id: nostr::SubscriptionId::new(&subscription),
                event: Box::new(event),
            })
            .unwrap();
            // A cooperative relay sender can outrun native fsync without
            // overrunning an otherwise unblocked SDK notification reader.
            if index % 16 == 0 {
                tokio::task::yield_now().await;
            }
        }
        for subscription in subscriptions {
            tx.send(nostr_sdk::RelayPoolNotification::Message {
                relay_url: "wss://semantic.invalid".parse().unwrap(),
                message: nostr::RelayMessage::EndOfStoredEvents(std::borrow::Cow::Owned(
                    nostr::SubscriptionId::new(subscription.subscription_id()),
                )),
            })
            .unwrap();
        }
        // Do not receive any adapter delivery until all notifications are
        // actually on disk. The former direct forwarder blocks at 1024 here.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                assert!(!forwarder.is_finished());
                let mut at = 0;
                let mut count = 0;
                let end = inspect.metadata().unwrap().len();
                while at + 4 <= end {
                    let mut len = [0; 4];
                    inspect.read_exact_at(&mut len, at).unwrap();
                    let next = at + 4 + u64::from(u32::from_be_bytes(len));
                    if next > end {
                        break;
                    }
                    at = next;
                    count += 1;
                }
                if count == expected_count {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            !adapter
                .account_subscription_eose(&factory.receiver.engine.self_id())
                .await
                .complete()
        );
        for expected_id in expected {
            let delivery = tokio::time::timeout(Duration::from_secs(2), adapter.receive())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(hex::encode(delivery.message.id.as_slice()), expected_id);
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while !adapter
                .account_subscription_eose(&factory.receiver.engine.self_id())
                .await
                .complete()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "EOSE status {:?}, drained {}",
                futures::executor::block_on(
                    adapter.account_subscription_eose(&factory.receiver.engine.self_id())
                ),
                forwarder.is_drained()
            )
        });
        assert!(!forwarder.is_finished());
        forwarder.abort();
    }
    #[tokio::test]
    async fn spool_write_failure_ends_intake_without_eose() {
        let (factory, _, _, _) = super::super::super::tests::fixture().await;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("readonly");
        std::fs::write(&path, []).unwrap();
        let file = File::open(path).unwrap();
        let (tx, rx) = tokio::sync::broadcast::channel(2);
        let forwarder = forward(rx, factory.transport.clone(), file);
        tx.send(nostr_sdk::RelayPoolNotification::Message {
            relay_url: "wss://semantic.invalid".parse().unwrap(),
            message: nostr::RelayMessage::EndOfStoredEvents(std::borrow::Cow::Owned(
                nostr::SubscriptionId::new("x"),
            )),
        })
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), forwarder)
            .await
            .unwrap()
            .unwrap();
    }
    #[test]
    fn anonymous_spool_requires_private_directory_and_has_no_directory_entry() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::open(root.path()).unwrap();
        let spool = anonymous(&directory).unwrap();
        assert_eq!(spool.metadata().unwrap().nlink(), 0);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(anonymous(&directory).is_err());
    }
}
