#!/usr/bin/env python3
import argparse
import json
import os
import socket

parser = argparse.ArgumentParser()
parser.add_argument("--mode", required=True)
parser.add_argument("--daemon-socket", required=True)
args = parser.parse_args()
if args.mode != "daemon":
    raise SystemExit(64)

try:
    os.unlink(args.daemon_socket)
except FileNotFoundError:
    pass
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(args.daemon_socket)
os.chmod(args.daemon_socket, 0o600)
server.listen(4)

hello = {
    "type": "daemon_hello",
    "appVersion": "0.7.0",
    "protocol": {
        "name": "prime-agent.daemon",
        "version": 7,
    },
    "schemaRevision": 13,
}

def send(writer, message):
    writer.write((json.dumps(message, separators=(",", ":")) + "\n").encode())
    writer.flush()

completed = False
reply = "marmot-e2e-ok: ping from connector " + ("chunk " * 40)
while not completed:
    connection, _ = server.accept()
    with connection:
        writer = connection.makefile("wb")
        reader = connection.makefile("rb")
        send(writer, hello)
        final_command_id = None
        for raw in reader:
            envelope = json.loads(raw)
            command = envelope["command"]
            command_type = command["type"]
            if command_type == "ack_result":
                if command.get("commandId") == final_command_id:
                    completed = True
                    break
                continue
            command_id = envelope["id"]
            if command_type == "create":
                name = command.get("name", "")
                if not name.startswith("marmot-"):
                    raise RuntimeError("missing stable Marmot session name")
                if "name" in command.get("config", {}):
                    raise RuntimeError("session name must be a top-level create field")
                data = {"activeSessionId": "fake-prime-session"}
            elif command_type == "attach":
                data = {"activeSessionId": "fake-prime-session"}
            elif command_type == "set_session_name":
                data = None
            elif command_type == "prompt_and_wait":
                send(writer, {
                    "type": "session_event",
                    "event": {
                        "type": "message_update",
                        "assistantMessageEvent": {
                            "type": "text_delta",
                            "delta": reply,
                        },
                    },
                })
                data = None
            elif command_type == "get_last_assistant_text":
                data = {"text": reply}
                final_command_id = command_id
            else:
                raise RuntimeError(f"unexpected daemon command: {command_type}")
            send(writer, {
                "type": "response",
                "id": command_id,
                "command": command_type,
                "success": True,
                "data": data,
            })

server.close()
try:
    os.unlink(args.daemon_socket)
except FileNotFoundError:
    pass
