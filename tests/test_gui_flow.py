"""Exercise controller behavior without requiring a graphical display."""
import ast
from pathlib import Path
import queue
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load_method(class_name, method_name, namespace):
    tree = ast.parse(Path(__file__).resolve().parents[1].joinpath("gui.py").read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == method_name)
    module = ast.Module(body=[method], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), "gui.py", "exec"), namespace)
    return namespace[method_name]


class GUIFlowTests(unittest.TestCase):
    def run_parse(self, folder):
        owner = threading.get_ident()
        threads = []
        callbacks = []
        def ui_call(*args, **kwargs):
            self.assertEqual(threading.get_ident(), owner)
        def create_thread(**kwargs):
            thread = threading.Thread(**kwargs)
            threads.append(thread)
            return thread
        progress = SimpleNamespace(**{name: ui_call for name in ("grid", "start", "stop", "grid_remove")})
        messages = Mock()
        namespace = {"queue": queue, "threading": SimpleNamespace(Thread=create_thread),
                     "messagebox": messages}
        method = load_method("StealerScopeGUI", "run_log_parser", namespace)
        button = SimpleNamespace(configure=ui_call)
        gui = SimpleNamespace(_parsing=False, parsed_data={"old": "case"},
                              settings_manager=SimpleNamespace(get=lambda *a, **kw: folder),
                              parse_button=button, import_logs_button=button, settings_button=button,
                              insert_log=ui_call, status_var=SimpleNamespace(set=ui_call), progress=progress,
                              refresh_dashboard=ui_call, select_view=ui_call,
                              after=lambda delay, callback: callbacks.append(callback))
        method(gui)
        self.assertIsNone(gui.parsed_data)
        method(gui)  # A second request must not start a second worker.
        self.assertEqual(len(threads), 1)
        threads[0].join(timeout=5)
        self.assertFalse(threads[0].is_alive())
        callbacks.pop(0)()
        self.assertFalse(gui._parsing)
        return gui, messages

    def test_worker_never_updates_ui_and_result_is_delivered(self):
        with tempfile.TemporaryDirectory() as folder:
            gui, messages = self.run_parse(folder)
        self.assertIn("credentials", gui.parsed_data)
        messages.showerror.assert_not_called()

    def test_failed_import_clears_previous_results(self):
        with tempfile.TemporaryDirectory() as folder:
            gui, messages = self.run_parse(str(Path(folder) / "missing"))
        self.assertIsNone(gui.parsed_data)
        messages.showerror.assert_called_once()

    def test_dashboard_filter_keeps_complete_matching_rows(self):
        method = load_method("StealerScopeGUI", "_filtered", {})
        rows = [("system.txt", "Host", "Device A"), ("system.txt", "OS", "Windows")]
        self.assertEqual(method(rows, "host"), [("system.txt", "Host", "Device A")])
        self.assertEqual(method(rows, "device a"), [("system.txt", "Host", "Device A")])

    def test_secret_mask_does_not_reveal_value(self):
        method = load_method("StealerScopeGUI", "_mask", {})
        masked = method("SensitiveValue")
        self.assertNotIn("SensitiveValue", masked)
        self.assertTrue(set(masked) == {"•"})
