"""Failure-path checks for the real adapter retry fixtures, not production policy."""

import asyncio
import unittest

from integrations.hermes.tests.marmot import test_adapter


class RetryFixtureLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_debounce_fixture_cancels_dispatch_before_storage_cleanup(self):
        case = test_adapter.ParityBehaviorTests(
            "test_retry_loop_cannot_bypass_live_debounce_or_duplicate_replay"
        )
        await case.asyncSetUp()
        adapter = case._adapter(client=object(), extra={"debounce_ms": 60_000})
        case._adapter = lambda client, extra=None: adapter
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def blocked_dispatch(event):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        async def failing_join():
            await started.wait()
            raise RuntimeError("synthetic fixture wait failure")

        adapter.handle_message = blocked_dispatch
        adapter._inbound_queue.join = failing_join
        try:
            with self.assertRaisesRegex(RuntimeError, "synthetic fixture wait failure"):
                await case.test_retry_loop_cannot_bypass_live_debounce_or_duplicate_replay()
            self.assertTrue(cancelled.is_set(), "fixture left queued dispatch alive")
            self.assertEqual(set(), adapter._inbound_queue._pending)
            self.assertFalse(adapter._inbound_spool.is_open)
        finally:
            await adapter.disconnect()

    async def test_release_fixture_cancels_dispatch_before_storage_cleanup(self):
        case = test_adapter.InboundDurabilityAdapterTests(
            "test_retry_loop_survives_unexpected_debounce_release_exception"
        )
        await case.asyncSetUp()
        adapter = case.make_adapter(extra={"group_activation": "always"})
        case.make_adapter = lambda **kwargs: adapter
        started = asyncio.Event()
        cancelled = asyncio.Event()

        async def blocked_dispatch(event):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        adapter.handle_message = blocked_dispatch
        task = asyncio.create_task(
            case.test_retry_loop_survives_unexpected_debounce_release_exception()
        )
        try:
            await asyncio.wait_for(started.wait(), timeout=60)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(cancelled.is_set(), "fixture closed storage with dispatch alive")
            self.assertEqual(set(), adapter._inbound_queue._pending)
            self.assertFalse(adapter._inbound_spool.is_open)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await adapter.disconnect()
