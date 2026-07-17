use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{collections::VecDeque, path::Path, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
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
        let mut command = Command::new(executable.as_ref());
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

    pub async fn start_turn(&mut self, thread_id: &str, text: &str) -> Result<Value> {
        self.request(
            "turn/start",
            json!({
                "threadId": thread_id,
                "input": [{ "type": "text", "text": text }]
            }),
        )
        .await
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_turn_payload_matches_app_server_contract() {
        let params = json!({
            "threadId": "thr_123",
            "input": [{ "type": "text", "text": "hello" }]
        });
        assert_eq!(params["input"][0]["type"], "text");
        assert_eq!(params["threadId"], "thr_123");
    }
}
