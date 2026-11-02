//! Read-only chat derivatives of the actual retained authenticated outcomes.
//! A RetainedCandidate is presentation data and cannot become semantic evidence.
use super::*;
use crate::protected_receiver::RetainedCandidate;
fn candidate_schema(body: &Value) -> bool {
    matches!(
        body["schema"].as_str(),
        Some("receiver-outcome.v1" | "receiver-delayed-outcome.v1")
    )
}
fn actor(account: &str, profile: &ServingProfile) -> Value {
    json!({"account_id_hex":account,"is_self":account==profile.enrollment.account})
}
fn target_id(app: &MarmotAppEvent) -> Option<&str> {
    app.tags
        .iter()
        .rev()
        .find(|t| t.first().is_some_and(|s| s == "e") && t.get(1).is_some_and(|s| hex64(s)))
        .and_then(|t| t.get(1))
        .map(String::as_str)
}
fn retained(
    candidate: &Value,
    profile: &ServingProfile,
) -> Result<RetainedCandidate, ReceiverHold> {
    let c: RetainedCandidate =
        serde_json::from_value(candidate.clone()).map_err(|_| ReceiverHold::ChangedState)?;
    if hex::encode(c.group.as_slice()) != profile.enrollment.group
        || c.application
            .validate_sender(&hex::encode(c.sender.as_slice()))
            .is_err()
    {
        return Err(ReceiverHold::ChangedState);
    }
    Ok(c)
}
fn context<S: StorageProvider + 'static>(
    factory: &SemanticFactory<S>,
    profile: &ServingProfile,
    history: &store::Store,
    id: &str,
) -> Result<Value, ReceiverHold> {
    let mut result = json!({"message_id_hex":id,"availability":"missing","text_truncated":false,"attachments":[],"attachments_truncated":false});
    if let Some(p) = history
        .outbound
        .values()
        .find(|p| p.prepared.as_ref().is_some_and(|(found, _)| found == id))
    {
        let text = p.content.get("text").and_then(Value::as_str).unwrap_or("");
        result = json!({"message_id_hex":id,"availability":"available","sender":actor(&profile.enrollment.account,profile),"text_excerpt":text.chars().take(2000).collect::<String>(),"text_truncated":text.chars().count()>2000,"attachments":[],"attachments_truncated":false});
    }
    let mut cursor = factory
        .ordered()?
        .source_cursor()
        .map_err(|_| ReceiverHold::Journal)?;
    while let Some(r) = cursor.next().map_err(|_| ReceiverHold::Journal)? {
        let body = &r.body["value"];
        if !candidate_schema(body) || body["candidate"].is_null() {
            continue;
        }
        let c = retained(&body["candidate"], profile)?;
        if c.application.id == id && c.application.kind == MARMOT_APP_EVENT_KIND_CHAT {
            let text = &c.application.content;
            result = json!({"message_id_hex":id,"availability":"available","sender":actor(&c.application.pubkey,profile),"recorded_at":c.application.created_at,"text_excerpt":text.chars().take(2000).collect::<String>(),"text_truncated":text.chars().count()>2000,"attachments":[],"attachments_truncated":false});
        }
    }
    // Resolve the original author first; later delayed records must not undo a
    // deletion/edit encountered earlier in source order. Two bounded-memory scans.
    let author = result["sender"]["account_id_hex"]
        .as_str()
        .map(str::to_owned);
    let mut cursor = factory
        .ordered()?
        .source_cursor()
        .map_err(|_| ReceiverHold::Journal)?;
    while let Some(r) = cursor.next().map_err(|_| ReceiverHold::Journal)? {
        let body = &r.body["value"];
        if !candidate_schema(body) || body["candidate"].is_null() {
            continue;
        }
        let c = retained(&body["candidate"], profile)?;
        if [MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT].contains(&c.application.kind)
            && target_id(&c.application) == Some(id)
            && author.as_deref() == Some(&c.application.pubkey)
        {
            result = json!({"message_id_hex":id,"availability":"deleted","text_truncated":false,"attachments":[],"attachments_truncated":false});
        }
    }
    Ok(result)
}
fn event<S: StorageProvider + 'static>(
    factory: &SemanticFactory<S>,
    profile: &ServingProfile,
    history: &store::Store,
    candidate: &Value,
    sequence: u64,
) -> Result<Option<Value>, ReceiverHold> {
    let c = retained(candidate, profile)?;
    let app = &c.application;
    let mut out = match app.kind {
        MARMOT_APP_EVENT_KIND_CHAT => {
            if context(factory, profile, history, &app.id)?["availability"] == "deleted" {
                return Ok(None);
            }
            let reply = match target_id(app) {
                Some(id) => context(factory, profile, history, id)?,
                None => Value::Null,
            };
            let mentions = app.tags.iter().any(|t| {
                t.first().is_some_and(|s| s == "p") && t.get(1) == Some(&profile.enrollment.account)
            }) || app
                .content
                .contains(&format!("nostr:{}", profile.enrollment.account));
            json!({"type":"inbound_message","message":{"message_id_hex":app.id,"sender":actor(&app.pubkey,profile),"text":app.content,"recorded_at":app.created_at,"media":[]},"mentions_self":mentions,"reply_to":reply,"application_tags":app.tags})
        }
        MARMOT_APP_EVENT_KIND_REACTION => {
            let Some(id) = target_id(app) else {
                return Ok(None);
            };
            let target = context(factory, profile, history, id)?;
            json!({"type":"reaction_added","event_id_hex":app.id,"target_message_id_hex":id,"actor":actor(&app.pubkey,profile),"emoji":app.content,"recorded_at":app.created_at,"target":target})
        }
        _ => return Ok(None),
    };
    out["account_id_hex"] = json!(profile.enrollment.account);
    out["group_id_hex"] = json!(profile.enrollment.group);
    out["serving_generation"] = json!(profile.serving_generation);
    out["source_epoch"] = json!(c.source_epoch);
    out["original_event_sha256"] = json!(digest(
        &app.encode().map_err(|_| ReceiverHold::ChangedState)?
    ));
    out["journal_cursor"] = json!(sequence);
    if serde_json::to_vec(&out)
        .map_err(|_| ReceiverHold::Malformed)?
        .len()
        > MAX_FRAME - 1024
    {
        return Err(ReceiverHold::Capacity);
    }
    Ok(Some(out))
}
pub(super) fn replay<S: StorageProvider + 'static>(
    factory: &SemanticFactory<S>,
    profile: &ServingProfile,
    history: &store::Store,
    after: u64,
) -> Result<(Vec<Value>, u64), ReceiverHold> {
    if factory.held || factory.receiver.latched {
        return Err(ReceiverHold::Latched);
    }
    let mut cursor = factory
        .ordered()?
        .source_cursor()
        .map_err(|_| ReceiverHold::Journal)?;
    let mut next = after;
    let mut events = Vec::new();
    let mut scanned = 0;
    while let Some(r) = cursor.next().map_err(|_| ReceiverHold::Journal)? {
        if r.sequence <= after {
            continue;
        }
        next = r.sequence;
        scanned += 1;
        let body = &r.body["value"];
        if candidate_schema(body)
            && !body["candidate"].is_null()
            && let Some(e) = event(factory, profile, history, &body["candidate"], r.sequence)?
        {
            events.push(e)
        }
        if scanned == 64 {
            break;
        }
    }
    Ok((events, next))
}
