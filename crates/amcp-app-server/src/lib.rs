use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{collections::VecDeque, path::Path, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::watch,
};

pub struct AppServerClient {
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    next_id: u64,
    initialized: bool,
    notifications: VecDeque<Value>,
}

impl AppServerClient {
    pub async fn spawn(
        executable: impl AsRef<Path>,
        codex_home: Option<&Path>,
        working_directory: Option<&Path>,
    ) -> Result<Self> {
        Self::spawn_internal(executable.as_ref(), codex_home, working_directory, None).await
    }

    pub async fn spawn_with_mcp(
        executable: impl AsRef<Path>,
        codex_home: Option<&Path>,
        working_directory: Option<&Path>,
        mcp_command: &Path,
        mcp_database: &Path,
    ) -> Result<Self> {
        Self::spawn_internal(
            executable.as_ref(),
            codex_home,
            working_directory,
            Some((mcp_command, mcp_database)),
        )
        .await
    }

    async fn spawn_internal(
        executable: &Path,
        codex_home: Option<&Path>,
        working_directory: Option<&Path>,
        mcp: Option<(&Path, &Path)>,
    ) -> Result<Self> {
        let mut command = Command::new(executable);
        command
            .arg("app-server")
            .arg("--listen")
            .arg("stdio://")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(codex_home) = codex_home {
            command.env("CODEX_HOME", codex_home);
        }
        if let Some(working_directory) = working_directory {
            command.current_dir(working_directory);
        }
        if let Some((mcp_command, mcp_database)) = mcp {
            command
                .arg("--config")
                .arg(format!(
                    "mcp_servers.amcp.command={}",
                    toml_string(mcp_command.to_string_lossy().as_ref())
                ))
                .arg("--config")
                .arg(format!(
                    "mcp_servers.amcp.args=[\"--db\",{}]",
                    toml_string(mcp_database.to_string_lossy().as_ref())
                ))
                .arg("--config")
                .arg("mcp_servers.amcp.enabled=true")
                .arg("--config")
                .arg("mcp_servers.amcp.required=false");
        }
        let mut child = command.spawn().context("start Codex app-server")?;
        let stdin = child
            .stdin
            .take()
            .context("Codex app-server stdin unavailable")?;
        let stdout = child
            .stdout
            .take()
            .context("Codex app-server stdout unavailable")?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout).lines(),
            next_id: 1,
            initialized: false,
            notifications: VecDeque::new(),
        })
    }

    pub async fn initialize(&mut self, client_name: &str, version: &str) -> Result<Value> {
        if self.initialized {
            bail!("Codex app-server is already initialized");
        }
        let result = self
            .request(
                "initialize",
                json!({
                    "clientInfo": {
                        "name": client_name,
                        "title": "AMCP Embedded Codex",
                        "version": version
                    },
                    "capabilities": { "experimentalApi": true }
                }),
            )
            .await?;
        self.notification("initialized", json!({})).await?;
        self.initialized = true;
        Ok(result)
    }

    pub async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({ "method": method, "id": id, "params": params }))
            .await?;
        while let Some(line) = self.stdout.next_line().await? {
            let message: Value = serde_json::from_str(&line)
                .with_context(|| format!("decode Codex app-server message: {line}"))?;
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                self.notifications.push_back(message);
                continue;
            }
            if let Some(error) = message.get("error") {
                bail!("Codex app-server {method} failed: {error}");
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
        bail!("Codex app-server closed stdout while waiting for {method}")
    }

    pub async fn notification(&mut self, method: &str, params: Value) -> Result<()> {
        self.send(json!({ "method": method, "params": params }))
            .await
    }

    pub async fn start_thread(
        &mut self,
        model: Option<&str>,
        working_directory: Option<&Path>,
    ) -> Result<Value> {
        let mut params = serde_json::Map::new();
        if let Some(model) = model {
            params.insert("model".into(), Value::String(model.into()));
        }
        if let Some(working_directory) = working_directory {
            params.insert(
                "cwd".into(),
                Value::String(working_directory.to_string_lossy().into_owned()),
            );
        }
        self.request("thread/start", Value::Object(params)).await
    }

    pub async fn list_threads(
        &mut self,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Value> {
        let mut params = serde_json::Map::new();
        if let Some(cursor) = cursor {
            params.insert("cursor".into(), Value::String(cursor.into()));
        }
        if let Some(limit) = limit {
            params.insert("limit".into(), Value::Number(limit.into()));
        }
        self.request("thread/list", Value::Object(params)).await
    }

    pub async fn read_thread(&mut self, thread_id: &str) -> Result<Value> {
        self.request("thread/read", json!({ "threadId": thread_id }))
            .await
    }

    pub async fn archive_thread(&mut self, thread_id: &str) -> Result<Value> {
        self.request("thread/archive", json!({ "threadId": thread_id }))
            .await
    }

    pub async fn unarchive_thread(&mut self, thread_id: &str) -> Result<Value> {
        self.request("thread/unarchive", json!({ "threadId": thread_id }))
            .await
    }

    pub async fn start_turn(&mut self, thread_id: &str, text: &str) -> Result<Value> {
        self.request(
            "turn/start",
            json!({
                "threadId": thread_id,
                "input": [{ "type": "text", "text": text }],
                "sandboxPolicy": { "type": "readOnly", "networkAccess": false },
                "approvalPolicy": "never",
                "approvalsReviewer": "user"
            }),
        )
        .await
    }

    pub async fn run_turn(&mut self, thread_id: &str, text: &str) -> Result<Value> {
        let (_cancel_sender, mut cancellation) = watch::channel(false);
        self.run_turn_cancellable(thread_id, text, &mut cancellation)
            .await
    }

    pub async fn run_turn_cancellable(
        &mut self,
        thread_id: &str,
        text: &str,
        cancellation: &mut watch::Receiver<bool>,
    ) -> Result<Value> {
        self.run_turn_cancellable_with_events(thread_id, text, cancellation, |_| {})
            .await
    }

    pub async fn run_turn_cancellable_with_events<F>(
        &mut self,
        thread_id: &str,
        text: &str,
        cancellation: &mut watch::Receiver<bool>,
        mut on_event: F,
    ) -> Result<Value>
    where
        F: FnMut(&Value),
    {
        let started = self.start_turn(thread_id, text).await?;
        let turn_id = started
            .get("turn")
            .and_then(|turn| turn.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("Codex app-server did not return a turn id")?;
        let mut answer = String::new();
        let mut events = Vec::new();
        let mut interrupt_requested = false;
        loop {
            if *cancellation.borrow() && !interrupt_requested {
                self.interrupt_turn(thread_id, &turn_id).await?;
                interrupt_requested = true;
            }
            let message = match self.next_message_or_cancellation(cancellation).await? {
                TurnStreamEvent::Message(message) => message,
                TurnStreamEvent::CancellationRequested => {
                    if !interrupt_requested {
                        self.interrupt_turn(thread_id, &turn_id).await?;
                        interrupt_requested = true;
                    }
                    continue;
                }
            };
            on_event(&message);
            let method = message
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let params = message.get("params").cloned().unwrap_or(Value::Null);
            if events.len() < 512 {
                events.push(summarize_notification(&message));
            }
            if method == "item/agentMessage/delta" {
                if let Some(delta) = params.get("delta").and_then(Value::as_str) {
                    answer.push_str(delta);
                }
            } else if method == "turn/completed" {
                let event_turn_id = params
                    .get("turn")
                    .and_then(|turn| turn.get("id"))
                    .and_then(Value::as_str);
                if event_turn_id.is_none() || event_turn_id == Some(turn_id.as_str()) {
                    if answer.is_empty() {
                        answer = extract_agent_text(&params);
                    }
                    return Ok(json!({
                        "turn": params.get("turn").cloned().unwrap_or(params),
                        "text": answer,
                        "events": events,
                    }));
                }
            }
        }
    }

    pub async fn interrupt_turn(&mut self, thread_id: &str, turn_id: &str) -> Result<()> {
        self.request(
            "turn/interrupt",
            json!({ "threadId": thread_id, "turnId": turn_id }),
        )
        .await
        .map(|_| ())
    }

    pub fn next_notification(&mut self) -> Option<Value> {
        self.notifications.pop_front()
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.child.kill().await.context("stop Codex app-server")?;
        let _ = self.child.wait().await;
        Ok(())
    }

    async fn send(&mut self, message: Value) -> Result<()> {
        let encoded = serde_json::to_string(&message)?;
        self.stdin.write_all(encoded.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn next_message_or_cancellation(
        &mut self,
        cancellation: &mut watch::Receiver<bool>,
    ) -> Result<TurnStreamEvent> {
        if let Some(message) = self.notifications.pop_front() {
            return Ok(TurnStreamEvent::Message(message));
        }
        tokio::select! {
            changed = cancellation.changed() => {
                if changed.is_ok() && *cancellation.borrow() {
                    Ok(TurnStreamEvent::CancellationRequested)
                } else {
                    let line = self.stdout.next_line().await?.context("Codex app-server closed stdout")?;
                    serde_json::from_str(&line)
                        .map(TurnStreamEvent::Message)
                        .with_context(|| format!("decode Codex app-server message: {line}"))
                }
            }
            line = self.stdout.next_line() => {
                let line = line?.context("Codex app-server closed stdout")?;
                serde_json::from_str(&line)
                    .map(TurnStreamEvent::Message)
                    .with_context(|| format!("decode Codex app-server message: {line}"))
            }
        }
    }
}

enum TurnStreamEvent {
    Message(Value),
    CancellationRequested,
}

fn summarize_notification(message: &Value) -> Value {
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let mut summary = serde_json::Map::new();
    summary.insert("method".into(), Value::String(method.clone()));
    for key in ["threadId", "turnId", "itemId", "status", "type"] {
        if let Some(value) = params.get(key)
            && (value.is_string() || value.is_number() || value.is_boolean())
        {
            summary.insert(key.into(), value.clone());
        }
    }
    if let Some(turn) = params.get("turn") {
        for key in ["id", "status"] {
            if let Some(value) = turn.get(key)
                && (value.is_string() || value.is_number() || value.is_boolean())
            {
                summary.insert(format!("turn_{key}"), value.clone());
            }
        }
    }
    summary.insert("delta".into(), Value::Bool(method.ends_with("/delta")));
    Value::Object(summary)
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("JSON string is valid TOML basic string")
}

fn extract_agent_text(value: &Value) -> String {
    if let Some(text) = value.get("text").and_then(Value::as_str) {
        return text.to_owned();
    }
    if let Some(item) = value.get("item") {
        if let Some(text) = item.get("text").and_then(Value::as_str) {
            return text.to_owned();
        }
        if let Some(content) = item.get("content").and_then(Value::as_array) {
            return content
                .iter()
                .filter_map(|part| part.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("");
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_turn_payload_matches_app_server_contract() {
        let params = json!({
            "threadId": "thr_123",
            "input": [{ "type": "text", "text": "hello" }],
            "sandboxPolicy": { "type": "readOnly", "networkAccess": false },
            "approvalPolicy": "never",
            "approvalsReviewer": "user"
        });
        assert_eq!(params["input"][0]["type"], "text");
        assert_eq!(params["threadId"], "thr_123");
        assert_eq!(params["sandboxPolicy"]["type"], "readOnly");
        assert_eq!(params["sandboxPolicy"]["networkAccess"], false);
        assert_eq!(params["approvalPolicy"], "never");
        assert_eq!(params["approvalsReviewer"], "user");
    }

    #[test]
    fn interrupt_payload_is_bound_to_thread_and_turn() {
        let params = json!({ "threadId": "thr_123", "turnId": "turn_456" });
        assert_eq!(params["threadId"], "thr_123");
        assert_eq!(params["turnId"], "turn_456");
    }

    #[test]
    fn thread_inventory_payloads_are_scoped_to_thread_ids() {
        let read = json!({ "threadId": "thr_123" });
        let list = json!({ "cursor": "next", "limit": 20 });
        assert_eq!(read["threadId"], "thr_123");
        assert_eq!(list["limit"], 20);
    }

    #[test]
    fn notification_summary_excludes_transcript_payloads() {
        let summary = summarize_notification(&json!({
            "method": "item/agentMessage/delta",
            "params": {
                "itemId": "item-1",
                "delta": "secret transcript text",
                "status": "in_progress"
            }
        }));
        assert_eq!(summary["method"], "item/agentMessage/delta");
        assert_eq!(summary["itemId"], "item-1");
        assert_eq!(summary["delta"], true);
        assert!(summary.get("params").is_none());
        assert!(summary.get("text").is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancellation_interrupts_the_active_turn_and_waits_for_completion() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("mock app-server directory");
        let server = directory.path().join("mock-app-server.sh");
        std::fs::write(
            &server,
            r#"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      echo '{"id":1,"result":{}}'
      ;;
    *'"method":"thread/start"'*)
      echo '{"id":2,"result":{"thread":{"id":"thread-1"}}}'
      ;;
    *'"method":"turn/start"'*)
      echo '{"id":3,"result":{"turn":{"id":"turn-1"}}}'
      echo '{"method":"item/agentMessage/delta","params":{"turnId":"turn-1","itemId":"item-1","delta":"partial reply"}}'
      ;;
    *'"method":"turn/interrupt"'*)
      echo '{"id":4,"result":{}}'
      echo '{"method":"turn/completed","params":{"turn":{"id":"turn-1","status":"interrupted"}}}'
      ;;
  esac
done
"#,
        )
        .expect("write mock app-server");
        let mut permissions = std::fs::metadata(&server)
            .expect("read mock app-server permissions")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&server, permissions).expect("make mock app-server executable");

        let mut client = AppServerClient::spawn(&server, None, None)
            .await
            .expect("start mock app-server");
        client
            .initialize("amcp-test", "0.1.0")
            .await
            .expect("initialize mock app-server");
        let thread = client
            .start_thread(None, None)
            .await
            .expect("start mock thread");
        assert_eq!(thread["thread"]["id"], "thread-1");
        let (cancel, mut cancellation) = watch::channel(false);
        cancel.send(true).expect("request cancellation");
        let observed_events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let event_sink = observed_events.clone();

        let result = client
            .run_turn_cancellable_with_events(
                "thread-1",
                "cancel this turn",
                &mut cancellation,
                move |event| {
                    event_sink
                        .lock()
                        .expect("event sink lock")
                        .push(event.clone());
                },
            )
            .await
            .expect("receive interrupted completion");
        assert_eq!(result["turn"]["id"], "turn-1");
        assert_eq!(result["turn"]["status"], "interrupted");
        {
            let events = observed_events.lock().expect("event sink lock");
            assert!(
                events
                    .iter()
                    .any(|event| event["method"] == "item/agentMessage/delta")
            );
            assert!(
                events
                    .iter()
                    .any(|event| event["method"] == "turn/completed")
            );
        }
        client.shutdown().await.expect("stop mock app-server");
    }
}
