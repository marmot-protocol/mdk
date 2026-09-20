"""Run with HERMES_APPROVAL_CONTRACT=1 and PYTHONPATH at hermes-agent.lock REF.

Uses the actual pinned approval queue, notification closure and slash handlers.
The transport is a fake; no fake handle_message makes approval decisions.
"""
import ast
import asyncio
import os
import sys
import types
import unittest
from unittest.mock import patch

from test_adapter import load_adapter_module, _DeliveryRoutingFakeClient


@unittest.skipUnless(os.getenv("HERMES_APPROVAL_CONTRACT") == "1", "requires pinned Hermes source")
class ApprovalHostContractTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from tools import approval
        import gateway.run as host
        from gateway.slash_commands import GatewaySlashCommandsMixin
        self.approval, self.host = approval, host
        self.slash = GatewaySlashCommandsMixin
        self.module = load_adapter_module()
        self.host_patch = patch.dict(sys.modules, {"gateway.run": host})
        self.host_patch.start()
        self.addCleanup(self.host_patch.stop)
        self.account, self.group, self.sender = "11" * 32, "22" * 16, "44" * 32
        self.env = patch.dict(os.environ, {"MARMOT_ALLOWED_USERS": self.sender})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.adapter = self.module.MarmotPlatformAdapter(
            sys.modules["gateway.config"].PlatformConfig(extra={
                "account_id_hex": self.account, "approval_reactions": True,
            }), client=_DeliveryRoutingFakeClient(),
        )
        self.session = "contract-test"
        self.counter = 0
        self.sent = []
        async def send(chat_id, content, **kwargs):
            self.counter += 1
            message_id = f"{self.counter:064x}"
            self.sent.append((message_id, content))
            return self.module.SendResult(success=True, message_id=message_id,
                raw_response={"type": "final_sent", "message_ids_hex": [message_id]})
        self.adapter._send_final_direct = send
        self.adapter.pause_typing_for_chat = lambda chat: None
        self.pending = []

    async def asyncTearDown(self):
        self.approval.unregister_gateway_notify(self.session)
        if self.pending:
            await asyncio.gather(*self.pending)
        await self.adapter.disconnect()

    async def request(self, command="echo contract", **extra):
        # Execute the real nested gateway closure with its transport/session
        # closure bindings. This catches notification signature/metadata drift.
        from pathlib import Path
        tree = ast.parse(Path(self.host.__file__).read_text())
        node = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "_approval_notify_sync")
        env = dict(vars(self.host))
        env.update(_status_adapter=self.adapter, _status_chat_id=self.group, event=types.SimpleNamespace(source=types.SimpleNamespace(chat_id=self.group)),
                   _approval_session_key=self.session, _status_thread_metadata=None,
                   _loop_for_step=asyncio.get_running_loop(),
                   _typed_approval_command_prefix=lambda: "/")
        exec(compile(ast.Module(body=[node], type_ignores=[]), self.host.__file__, "exec"), env)
        before = len(self.sent)
        task = asyncio.create_task(asyncio.to_thread(
            self.approval._await_gateway_decision, self.session,
            env["_approval_notify_sync"],
            {"command": command, "description": "contract test", **extra},
        ))
        self.pending.append(task)
        for _ in range(200):
            if len(self.sent) > before:
                return task, self.sent[-1][0]
            if task.done():
                self.fail(f"host notification failed: {task.result()}")
            await asyncio.sleep(.01)
        self.fail("host notification did not reach transport")

    async def react(self, target, emoji="👍", sender=None):
        return await self.adapter._handle_approval_reaction({
            "type": "reaction_added", "account_id_hex": self.account,
            "group_id_hex": self.group, "target_message_id_hex": target,
            "event_id_hex": "ee" * 32, "emoji": emoji,
            "actor": {"account_id_hex": sender or self.sender, "is_self": False},
        })

    async def typed(self, choice="approve"):
        source = types.SimpleNamespace(platform="marmot", chat_id=self.group)
        event = types.SimpleNamespace(source=source, get_command_args=lambda: "")
        runner = types.SimpleNamespace(_session_key_for_source=lambda source: self.session,
                                      _pending_approvals={}, adapters={"marmot": self.adapter})
        return await getattr(self.slash, f"_handle_{choice}_command")(runner, event)

    async def test_real_notification_and_reaction_decisions(self):
        for emoji, choice in [("👍", "once"), ("👎", "deny"), ("❤️", "always")]:
            task, target = await self.request()
            await self.react(target, emoji)
            self.assertEqual((await task)["choice"], choice)

    async def test_typed_decision_then_new_request_rejects_old_target(self):
        old, target = await self.request("echo A")
        await self.typed()
        self.assertEqual((await old)["choice"], "once")
        new, new_target = await self.request("echo B")
        await self.react(target)
        self.assertFalse(new.done())
        await self.react(new_target, "👎")
        self.assertEqual((await new)["choice"], "deny")

    async def test_resolver_race_without_typing_callback_rejects_old_entry(self):
        old, target = await self.request()
        self.approval.resolve_gateway_approval(self.session, "deny")
        await old
        new, new_target = await self.request()  # identical command, distinct entry
        await self.react(target)
        self.assertFalse(new.done())
        await self.react(new_target)
        self.assertEqual((await new)["choice"], "once")

    async def test_sender_rejection_leaves_prompt_usable(self):
        task, target = await self.request()
        await self.react(target, sender="55" * 32)
        self.assertFalse(task.done())
        await self.react(target)
        self.assertEqual((await task)["choice"], "once")

    async def test_no_permanent_override_for_restricted_request(self):
        task, target = await self.request(allow_permanent=False, smart_denied=True)
        await self.react(target, "❤️")
        self.assertFalse(task.done())
        await self.react(target, "👎")
        self.assertEqual((await task)["choice"], "deny")

    async def test_rejected_gateway_dispatch_does_not_retire_prompt(self):
        task, target = await self.request()
        # A rejection returns before the actual slash handler/resolver.
        from unittest.mock import AsyncMock
        self.adapter.handle_message = AsyncMock(return_value=None)
        event = types.SimpleNamespace(text="/approve", source=types.SimpleNamespace(chat_id=self.group))
        await self.adapter._handle_gateway_message(event)
        await self.react(target)
        self.assertEqual((await task)["choice"], "once")

    async def test_flag_off_is_typed_only(self):
        self.adapter.approval_reactions = False
        task, target = await self.request()
        await self.react(target)
        self.assertFalse(task.done())
        await self.typed("deny")
        self.assertEqual((await task)["choice"], "deny")

    async def test_flag_off_preserves_standard_send_and_metadata(self):
        from unittest.mock import AsyncMock
        self.adapter.approval_reactions = False
        metadata = {"thread_id": "approval-thread", "type": "preview"}
        result = self.module.SendResult(success=True, message_id="standard-send")
        self.adapter.send = AsyncMock(return_value=result)
        actual = await self.adapter.send_exec_approval(
            self.group, command="echo disabled", session_key=self.session,
            description="disabled request", metadata=metadata,
            allow_permanent=False, smart_denied=True,
        )
        expected = self.host._format_exec_approval_fallback(
            "echo disabled", "disabled request", "/",
            allow_permanent=False, smart_denied=True,
        )
        self.adapter.send.assert_awaited_once_with(self.group, expected, metadata=metadata)
        self.assertIs(actual, result)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.adapter._approval_prompt_messages, {})
        self.assertEqual(self.adapter._approval_prompt_bindings, {})

    async def test_parallel_notification_has_no_reaction_binding(self):
        first, target = await self.request("echo first")
        second, parallel_target = await self.request("echo second")
        await self.react(parallel_target)
        self.assertFalse(first.done())
        self.assertFalse(second.done())
        self.approval.resolve_gateway_approval(self.session, "deny", resolve_all=True)
        await asyncio.gather(first, second)

    async def test_expired_mapping_cannot_decide_pending_request(self):
        task, target = await self.request()
        key = (self.account, self.group, target)
        self.adapter._approval_prompt_deadlines[key] = 0
        await self.react(target)
        self.assertFalse(task.done())
        await self.typed("deny")
        self.assertEqual((await task)["choice"], "deny")

    async def test_unscoped_allow_all_does_not_authorize_consent(self):
        task, target = await self.request()
        with patch.dict(os.environ, {"MARMOT_ALLOWED_USERS": "*", "MARMOT_ALLOW_ALL_USERS": "true"}):
            await self.react(target)
        self.assertFalse(task.done())
        await self.react(target, "👎")
        self.assertEqual((await task)["choice"], "deny")
