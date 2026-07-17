#!/usr/bin/env python3
"""Minimal JSONL Codex app-server fixture for AMCP connector tests."""

import json
import sys


def main() -> None:
    archived = False

    for line in sys.stdin:
        message = json.loads(line)
        request_id = message.get("id")
        method = message.get("method")
        if request_id is None:
            continue
        if method == "initialize":
            result = {"serverInfo": {"name": "amcp-fixture"}}
        elif method == "thread/list":
            result = {
                "threads": [
                    {
                        "id": "thread-fixture",
                        "title": "Fixture session api_key=fixture-secret",
                        "cwd": "/tmp/amcp-fixture-project",
                        "model": "gpt-fixture",
                        "status": "idle",
                        "archived": archived,
                    }
                ]
            }
        elif method == "thread/read":
            result = {
                "thread": {
                    "id": "thread-fixture",
                    "title": "Fixture session api_key=fixture-secret",
                    "cwd": "/tmp/amcp-fixture-project",
                    "model": "gpt-fixture",
                    "status": "idle",
                    "archived": archived,
                },
                "items": [
                    {"type": "userMessage", "role": "user", "text": "secret transcript"},
                    {"type": "agentMessage", "role": "assistant", "delta": "secret delta"},
                ],
            }
        elif method == "thread/archive":
            archived = True
            result = {"threadId": "thread-fixture", "archived": True}
        elif method == "thread/unarchive":
            archived = False
            result = {"threadId": "thread-fixture", "archived": False}
        else:
            result = {}
        sys.stdout.write(json.dumps({"id": request_id, "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
