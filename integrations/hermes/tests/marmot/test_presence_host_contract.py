"""Pinned Hermes progress callback and executor context regression."""
import ast
import asyncio
import os
import threading
import types
import unittest
from pathlib import Path
from test_adapter import load_adapter_module, _DeliveryRoutingFakeClient
import sys


@unittest.skipUnless(os.getenv("HERMES_PRESENCE_CONTRACT") == "1", "requires pinned Hermes source")
class PresenceHostContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_late_host_tool_callback_keeps_originating_turn(self):
        import gateway.run as host
        module = load_adapter_module()
        adapter = module.MarmotPlatformAdapter(
            sys.modules["gateway.config"].PlatformConfig(extra={
                "account_id_hex": "11" * 32, "presence_reactions": True,
            }), client=_DeliveryRoutingFakeClient(),
        )
        self.addAsyncCleanup(adapter.disconnect)
        group = "22" * 16
        old = module.MessageEvent(text="old", message_id="33" * 32,
                                  source=types.SimpleNamespace(chat_id=group))
        new = module.MessageEvent(text="new", message_id="44" * 32, source=old.source)
        # No transport assertions here: existing socket tests cover reaction IO.
        adapter._presence._enqueue = lambda *args: None
        tree = ast.parse(Path(host.__file__).read_text())
        callback = next(n for n in ast.walk(tree)
                        if isinstance(n, ast.FunctionDef) and n.name == "progress_callback"
                        and any(isinstance(x, ast.Name) and x.id == "_live_status_adapter"
                                for x in ast.walk(n)))
        env = dict(vars(host))
        env.update(_live_status_adapter=adapter, _live_status_mode="short",
                   source=old.source, _run_still_current=lambda: True,
                   log_queue=None, progress_queue=None)
        exec(compile(ast.Module(body=[callback], type_ignores=[]), host.__file__, "exec"), env)
        progress = env["progress_callback"]
        started, release = threading.Event(), threading.Event()
        runner = types.SimpleNamespace(_get_executor=lambda: None)
        def late_tools():
            started.set()
            release.wait(5)
            progress("tool.started", "terminal")
            progress("tool.completed", "terminal")
        await adapter.on_processing_start(old)
        task = asyncio.create_task(host.GatewayRunner._run_in_executor_with_context(runner, late_tools))
        try:
            await asyncio.to_thread(started.wait, 5)
            await adapter.on_processing_start(new)
            release.set()
            await task
            await asyncio.sleep(0)
            state = adapter._presence.groups[group]
            self.assertIs(state.owner, new)
            self.assertEqual(state.mode, "accepted")
            self.assertEqual(state.active_tools, 0)
            # Current-turn host callbacks still drive the indicator.
            await host.GatewayRunner._run_in_executor_with_context(
                runner, progress, "tool.started", "terminal")
            await asyncio.sleep(0)
            self.assertEqual(state.mode, "tool")
            await host.GatewayRunner._run_in_executor_with_context(
                runner, progress, "tool.completed", "terminal")
            await asyncio.sleep(0)
            self.assertEqual(state.mode, "thinking")
        finally:
            release.set()
            await task
