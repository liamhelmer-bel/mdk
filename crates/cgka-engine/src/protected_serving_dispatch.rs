use super::*;
fn required<'a>(v: &'a Value, key: &str, max: usize) -> Result<&'a str, ReceiverHold> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= max)
        .ok_or(ReceiverHold::Malformed)
}
fn checked(request: &Value, profile: &ServingProfile) -> Result<String, ReceiverHold> {
    let kind = required(request, "type", 64)?;
    let common = [
        "type",
        "id",
        "auth_token",
        "marmot_agent_control",
        "account_id_hex",
        "group_id_hex",
    ];
    let extra: &[&str] = match kind {
        "group_info" | "subscribe_inbound" => &[],
        "send_final" => &["text", "reply_to_message_id_hex", "idempotency_key"],
        "send_reaction" => &["target_message_id_hex", "emoji"],
        _ => return Err(ReceiverHold::Configuration),
    };
    if request.as_object().is_none_or(|m| {
        m.keys()
            .any(|k| !common.contains(&k.as_str()) && !extra.contains(&k.as_str()))
    }) || required(request, "account_id_hex", 64)? != profile.enrollment.account
        || required(request, "group_id_hex", 128)? != profile.enrollment.group
    {
        return Err(ReceiverHold::Configuration);
    }
    Ok(kind.into())
}
pub(super) async fn dispatch<S: StorageProvider + 'static>(
    factory: &mut SemanticFactory<S>,
    profile: &ServingProfile,
    history: &mut store::Store,
    request: Value,
) -> Result<Value, ReceiverHold> {
    let kind = checked(&request, profile)?;
    if factory.held || factory.receiver.latched {
        return Err(ReceiverHold::Latched);
    }
    let authority = factory
        .receiver
        .engine
        .group_authority(&factory.receiver.group)
        .map_err(|_| ReceiverHold::ChangedState)?
        .facts;
    if !authority.is_member {
        return Err(ReceiverHold::ChangedState);
    }
    if kind == "group_info" {
        return Ok(
            json!({"type":"group_info","account_id_hex":profile.enrollment.account,"group_id_hex":profile.enrollment.group,"member_count":authority.member_count,"is_direct":false,"serving_generation":profile.serving_generation}),
        );
    }
    if kind == "subscribe_inbound" {
        return Ok(json!({"type":"ack","operation":"subscribe_inbound"}));
    }
    let (key, event_kind, text, tags) = if kind == "send_final" {
        let key = required(&request, "idempotency_key", 256)?.to_string();
        let text = required(&request, "text", 24000)?.to_string();
        let tags = match request.get("reply_to_message_id_hex") {
            None | Some(Value::Null) => vec![],
            Some(Value::String(s)) if hex64(s) => {
                vec![vec!["e".into(), s.clone(), "".into(), "reply".into()]]
            }
            _ => return Err(ReceiverHold::Malformed),
        };
        (
            format!("final:{key}"),
            MARMOT_APP_EVENT_KIND_CHAT,
            text,
            tags,
        )
    } else {
        let target = required(&request, "target_message_id_hex", 64)?;
        let emoji = required(&request, "emoji", 128)?;
        if !hex64(target) {
            return Err(ReceiverHold::Malformed);
        }
        let key = digest(
            &serde_json::to_vec(&(
                profile.serving_generation.as_str(),
                profile.enrollment.account.as_str(),
                profile.enrollment.group.as_str(),
                target,
                emoji,
            ))
            .map_err(|_| ReceiverHold::Malformed)?,
        );
        (
            format!("reaction:{key}"),
            MARMOT_APP_EVENT_KIND_REACTION,
            emoji.into(),
            vec![vec!["e".into(), target.into()]],
        )
    };
    let content = json!({"kind":event_kind,"text":text,"tags":tags});
    let fresh_intent = !history.outbound.contains_key(&key);
    if let Some(prior) = history.outbound.get(&key) {
        if prior.content != content {
            return Err(ReceiverHold::ChangedState);
        }
    } else {
        history.append(store::Record::Intent {
            key: key.clone(),
            content: content.clone(),
            epoch: authority.epoch.0,
        })?;
    }
    let prior = history
        .outbound
        .get(&key)
        .ok_or(ReceiverHold::Journal)?
        .clone();
    if prior.prepared.is_none() {
        // An existing intent without prepared bytes is uncertain, even if native
        // epoch is unchanged. Only this invocation may prepare a newly fsynced intent.
        // The boolean is derived locally below, never accepted over the wire.
        if !fresh_intent || prior.epoch != authority.epoch.0 {
            return Err(ReceiverHold::ChangedState);
        }
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ReceiverHold::Journal)?
            .as_secs();
        // Distinct durable operations must not produce the same app ID when
        // text and wall-clock seconds coincide. Bind the source-selected tag
        // to this generation and retained operation, never a fresh retry nonce.
        let mut tags = tags;
        tags.push(vec![
            "client-operation".into(),
            digest(
                &serde_json::to_vec(&(profile.serving_generation.as_str(), key.as_str()))
                    .map_err(|_| ReceiverHold::Malformed)?,
            ),
        ]);
        let event = MarmotAppEvent::new(
            profile.enrollment.account.clone(),
            created,
            event_kind,
            tags,
            text,
        );
        let payload = event.encode().map_err(|_| ReceiverHold::Malformed)?;
        factory.held = true;
        let result = factory
            .receiver
            .engine
            .send(SendIntent::AppMessage {
                group_id: factory.receiver.group.clone(),
                payload,
                expected_epoch: Some(authority.epoch),
            })
            .await
            .map_err(|_| ReceiverHold::Latched)?;
        let SendResult::ApplicationMessage {
            msg,
            app_event_id,
            group_id,
            ..
        } = result
        else {
            return Err(ReceiverHold::Latched);
        };
        if group_id != factory.receiver.group || app_event_id != event.id {
            return Err(ReceiverHold::Latched);
        }
        if history.outbound.values().any(|p| {
            p.prepared
                .as_ref()
                .is_some_and(|(id, _)| id == &app_event_id)
        }) {
            return Err(ReceiverHold::Latched);
        }
        history.append(store::Record::Prepared {
            key: key.clone(),
            message_id: app_event_id,
            wire: msg,
        })?;
        factory.held = false;
    }
    let prior = history
        .outbound
        .get(&key)
        .ok_or(ReceiverHold::Journal)?
        .clone();
    let (message_id, wire) = prior.prepared.ok_or(ReceiverHold::Journal)?;
    if !prior.published {
        if prior.epoch != authority.epoch.0 {
            return Err(ReceiverHold::ChangedState);
        }
        let expected = wire.id.clone();
        let report = tokio::time::timeout(
            Duration::from_secs(30),
            factory.transport.publish(TransportPublishRequest {
                account_id: factory.receiver.engine.self_id(),
                message: wire,
                target: TransportPublishTarget::Group {
                    group_id: factory.receiver.group.clone(),
                    transport_group_id: profile.transport_group.clone(),
                    endpoints: factory.endpoints.clone(),
                },
                required_acks: 1,
            }),
        )
        .await
        .map_err(|_| ReceiverHold::Engine)?
        .map_err(|_| ReceiverHold::Engine)?;
        if report.message_id != expected
            || report.required_acks != 1
            || !report.met_required_acks()
            || report
                .accepted
                .iter()
                .any(|r| !factory.endpoints.contains(&r.endpoint))
            || report
                .accepted
                .iter()
                .map(|r| &r.endpoint)
                .collect::<BTreeSet<_>>()
                .len()
                != report.accepted.len()
        {
            return Err(ReceiverHold::ChangedState);
        }
        history.append(store::Record::Published { key })?;
    }
    Ok(
        json!({"type":if kind=="send_final"{"final_sent"}else{"app_event_sent"},"account_id_hex":profile.enrollment.account,"group_id_hex":profile.enrollment.group,"message_ids_hex":[message_id],"serving_generation":profile.serving_generation}),
    )
}
