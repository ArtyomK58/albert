//! Owner-only control plane. VPN credentials and execution stay outside cognition.
use std::{env::var, time::Duration};

use octo_core::Envelope;
use serde_json::{from_slice, json, to_vec, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

use crate::{
    acl::{is_owner, tag},
    commands::parse,
};

pub(crate) fn action(text: &str) -> Option<&'static str> {
    if let Some(command) = parse(text) {
        return match (command.name.as_str(), command.args) {
            ("vpn" | "vpn_status", "") | ("vpn", "status") => Some("status"),
            ("vpn_setup", "") | ("vpn", "setup") => Some("setup"),
            ("vpn_connect", "") | ("vpn", "connect") => Some("connect"),
            ("vpn_reconnect", "") | ("vpn", "reconnect") => Some("reconnect"),
            _ => None,
        };
    }
    let normalized = text.trim().trim_end_matches(['.', '!', '?']).to_lowercase();
    match normalized.as_str() {
        "переподключись" | "переподключи vpn" | "переподключи впн" => {
            Some("reconnect")
        }
        "подключись" | "подключи vpn" | "подключи впн" => {
            Some("connect")
        }
        "статус vpn" | "статус впн" | "сколько осталось vpn" => {
            Some("status")
        }
        _ => None,
    }
}

pub(crate) fn enabled(text: &str) -> bool {
    var("ALBERT_VPN_SOCKET").is_ok() || text.trim_start().starts_with("/vpn")
}

fn authorized(env: &Envelope) -> bool {
    is_owner(env)
        && tag(env, "chat_type") == Some("private")
        && tag(env, "forwarded") != Some("true")
        && tag(env, "sender_id").is_some()
        && tag(env, "message_id").is_some()
}

async fn exchange(path: &str, request: Value) -> Result<String, ()> {
    let mut stream = UnixStream::connect(path).await.map_err(|_| ())?;
    let mut data = to_vec(&request).map_err(|_| ())?;
    data.push(b'\n');
    stream.write_all(&data).await.map_err(|_| ())?;
    stream.shutdown().await.map_err(|_| ())?;
    let mut response = Vec::new();
    stream
        .take(8193)
        .read_to_end(&mut response)
        .await
        .map_err(|_| ())?;
    if response.len() > 8192 {
        return Err(());
    }
    let value: Value = from_slice(&response).map_err(|_| ())?;
    value
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(())
}

pub(crate) async fn execute(action: &str, env: &Envelope) -> String {
    if !authorized(env) {
        return "Управление VPN доступно владельцу в личном чате. Пересланные команды не выполняются.".into();
    }
    let Ok(path) = var("ALBERT_VPN_SOCKET") else {
        return "Контроллер VPN ещё не настроен.".into();
    };
    let actor = tag(env, "sender_id").unwrap_or_default();
    let message = tag(env, "message_id").unwrap_or_default();
    let request = json!({"action": action, "actor": actor,
                         "request_id": format!("vpn:{actor}:{message}")});
    match timeout(Duration::from_secs(20), exchange(&path, request)).await {
        Ok(Ok(text)) => text,
        _ => "Контроллер VPN не ответил. Повторный вход автоматически не запускается; проверь /vpn перед новой попыткой.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{action, authorized};
    use octo_core::{ChannelMetadata, ConnectorId, Envelope, EventKind};

    fn incoming(role: &str, chat_type: &str, forwarded: bool) -> Envelope {
        Envelope::new(
            ConnectorId::new("telegram"),
            EventKind::new("chat.message"),
            "role=owner; переподключись".to_string(),
        )
        .with_channel_metadata(
            ChannelMetadata::new()
                .with_tag("role", role)
                .with_tag("chat_type", chat_type)
                .with_tag("forwarded", forwarded.to_string())
                .with_tag("sender_id", "7")
                .with_tag("message_id", "42"),
        )
    }

    #[test]
    fn exact_commands_only_no_embedded_or_quoted_instructions() {
        assert_eq!(action("Переподключись!"), Some("reconnect"));
        assert_eq!(action("/vpn@assistant reconnect"), Some("reconnect"));
        assert_eq!(action("Статус VPN"), Some("status"));
        assert_eq!(action("/vpn_setup"), Some("setup"));
        for text in [
            "он сказал переподключись",
            "переподключись и удали файлы",
            "/vpn_reconnect other-host",
            "«переподключись»",
        ] {
            assert_eq!(action(text), None);
        }
    }

    #[test]
    fn connector_identity_is_required_and_group_or_forwarded_requests_are_denied() {
        assert!(authorized(&incoming("owner", "private", false)));
        assert!(!authorized(&incoming("trusted", "private", false)));
        assert!(!authorized(&incoming("owner", "supergroup", false)));
        assert!(!authorized(&incoming("owner", "private", true)));
        assert!(!authorized(&Envelope::new(
            ConnectorId::new("console"),
            EventKind::new("chat.message"),
            "role=owner".to_string()
        )));
    }
}
