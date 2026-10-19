# -*- coding: utf-8 -*-

"""Local tests for the non-persistent webOS 26 root diagnostic.

All TV interactions are simulated. No test connects to a real television.
"""

import ast
import binascii
import contextlib
import http.client
import io
import json
import os
import shutil
import sys
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import urlopen

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
for _path in (REPO_ROOT, TOOLS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import webos26_root_diagnostic as diag  # noqa: E402


def make_report(token, euid=0, egid=0, status="ok", pid=4242, proc=True,
                process=True):
    report = {
        "kind": "rootdiag-result",
        "token": token,
        "status": status,
        "pid": pid,
        "ppid": 1,
        "node": "v16.0.0",
        "platform": "linux",
        "argv": ["node", "/media/internal/downloads/rootdiag.js"],
        "proc_status_error": None if proc else "read failed",
    }
    if status == "error":
        report.update(
            {
                "stage": "snapshot",
                "error": "synthetic snapshot failure",
            }
        )
        return report
    if proc:
        report["uid"] = {
            "real": euid,
            "effective": euid,
            "saved": euid,
            "filesystem": euid,
            "line": "Uid:\t%d\t%d\t%d\t%d" % (euid, euid, euid, euid),
        }
        report["gid"] = {
            "real": egid,
            "effective": egid,
            "saved": egid,
            "filesystem": egid,
            "line": "Gid:\t%d\t%d\t%d\t%d" % (egid, egid, egid, egid),
        }
    else:
        report["uid"] = None
        report["gid"] = None
    report["getuid"] = euid if process else None
    report["geteuid"] = euid if process else None
    report["getgid"] = egid if process else None
    report["getegid"] = egid if process else None
    return report


def http_get(url, timeout=5):
    try:
        with urlopen(url, timeout=timeout) as response:
            return response.status, response.read()
    except HTTPError as exc:
        return exc.code, exc.read()


@contextlib.contextmanager
def workspace_temp_dir():
    """Temporary directory inside the workspace (the sandbox blocks host temp)."""
    name = ".diag-test-%s" % binascii.hexlify(os.urandom(6)).decode("ascii")
    path = os.path.join(REPO_ROOT, name)
    os.makedirs(path)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class PayloadIsolationTest(unittest.TestCase):
    def test_exact_payload_set_and_manifest(self):
        payload = diag.validate_payload()
        self.assertEqual(
            set(payload["files"]),
            set(diag.PAYLOAD_FILES) | {diag.PAGE_NAME},
        )
        self.assertEqual(payload["manifest"]["name"], diag.PAYLOAD_MANIFEST_NAME)
        self.assertEqual(payload["manifest"]["main"], diag.PAYLOAD_MAIN)
        self.assertEqual(payload["services"]["id"], diag.PAYLOAD_MANIFEST_NAME)

    def test_payload_directory_is_not_wwwroot(self):
        self.assertNotEqual(
            os.path.realpath(diag.PAYLOAD_DIR),
            os.path.realpath(os.path.join(REPO_ROOT, "wwwroot")),
        )
        for name in diag.PAYLOAD_FILES:
            self.assertNotIn("autoroot", name.lower())
            self.assertNotIn("hbchannel", name.lower())
            self.assertNotIn("main.js", name.lower())

    def test_no_installer_or_persistence_markers_in_payload(self):
        for name in list(diag.PAYLOAD_FILES) + [diag.PAGE_NAME]:
            text = diag.read_payload_file(diag.PAYLOAD_DIR, name).decode("utf-8").lower()
            for marker in diag.FORBIDDEN_PAYLOAD_MARKERS:
                self.assertNotIn(marker, text, "%s contains %r" % (name, marker))

    def test_payload_js_has_no_writer_or_subprocess_api(self):
        text = diag.read_payload_file(diag.PAYLOAD_DIR, diag.PAYLOAD_MAIN).decode("utf-8")
        lower = text.lower()
        for marker in diag.FORBIDDEN_PAYLOAD_APIS:
            self.assertNotIn(marker, lower)
        self.assertIn("/proc/self/status", text)

    def test_render_substitutes_token_and_report_url(self):
        payload = diag.validate_payload()
        token = diag.new_token()
        report_url = "http://192.0.2.10:8080" + diag.result_path(token)
        rendered = diag.render_payload_file(
            payload, diag.PAYLOAD_MAIN, token, report_url
        ).decode("utf-8")
        self.assertIn(token, rendered)
        self.assertIn(report_url, rendered)
        self.assertNotIn("__DIAG_", rendered)
        raw = diag.render_payload_file(
            payload, "package.json", token, report_url
        ).decode("utf-8")
        self.assertNotIn(token, raw)

    def test_rejects_manifest_with_non_diagnostic_main(self):
        with workspace_temp_dir() as tmp:
            self._copy_payload(tmp)
            self._write(
                tmp,
                "package.json",
                '{"name":"com.webos.service.jsserver","main":"main.js"}',
            )
            with self.assertRaisesRegex(diag.DiagnosticError, "main must be"):
                diag.validate_payload(tmp)

    def test_rejects_installer_marker(self):
        with workspace_temp_dir() as tmp:
            self._copy_payload(tmp)
            self._write(
                tmp,
                "services.json",
                '{"id":"com.webos.service.jsserver","autoroot":true}',
            )
            with self.assertRaisesRegex(diag.DiagnosticError, "forbidden marker"):
                diag.validate_payload(tmp)

    def test_rejects_writer_api(self):
        with workspace_temp_dir() as tmp:
            self._copy_payload(tmp)
            path = os.path.join(tmp, diag.PAYLOAD_MAIN)
            with open(path, "a", encoding="utf-8") as handle:
                handle.write("\n// fs.writeFileSync('/tmp/x', 'y')\n")
            with self.assertRaisesRegex(diag.DiagnosticError, "forbidden API"):
                diag.validate_payload(tmp)

    def test_rejects_extra_file(self):
        with workspace_temp_dir() as tmp:
            self._copy_payload(tmp)
            self._write(tmp, "extra.txt", "not part of the payload")
            with self.assertRaisesRegex(diag.DiagnosticError, "unexpected"):
                diag.validate_payload(tmp)

    def test_ignores_known_filesystem_metadata(self):
        with workspace_temp_dir() as tmp:
            self._copy_payload(tmp)
            self._write(tmp, ".DS_Store", "metadata")
            payload = diag.validate_payload(tmp)
            self.assertEqual(
                set(payload["files"]),
                set(diag.PAYLOAD_FILES) | {diag.PAGE_NAME},
            )

    def test_payload_path_rejects_traversal(self):
        with self.assertRaises(diag.DiagnosticError):
            diag._payload_path(diag.PAYLOAD_DIR, os.path.join("..", "wwwroot", "package.json"))

    def _copy_payload(self, target):
        for name in list(diag.PAYLOAD_FILES) + [diag.PAGE_NAME]:
            shutil.copyfile(
                os.path.join(diag.PAYLOAD_DIR, name), os.path.join(target, name)
            )

    def _write(self, directory, name, text):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
            handle.write(text)


class ToolIsolationTest(unittest.TestCase):
    def test_no_forbidden_imports_or_shell_calls(self):
        with open(diag.__file__, "r", encoding="utf-8") as handle:
            source = handle.read()
        tree = ast.parse(source)

        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".", 1)[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])

        self.assertNotIn("subprocess", imported)
        self.assertNotIn("webos_root_wizard", imported)
        self.assertNotIn("webos26_compatible_launch", imported)
        self.assertIn("slopbro", imported)

        for needle in ("os.system", "subprocess.", "Popen", "webos_root_wizard."):
            self.assertNotIn(needle, source)

    def test_only_expected_tv_path_constant(self):
        self.assertEqual(diag.TV_DOWNLOAD_DIR, "/media/internal/downloads")
        with open(diag.__file__, "r", encoding="utf-8") as handle:
            source = handle.read()
        for path in ("/var/luna", "/media/developer", "/lib/systemd", "/etc/"):
            self.assertNotIn(path, source)

    def test_tool_has_no_filesystem_write_or_process_calls(self):
        with open(diag.__file__, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read())

        def dotted_name(func):
            parts = []
            while isinstance(func, ast.Attribute):
                parts.append(func.attr)
                func = func.value
            if isinstance(func, ast.Name):
                parts.append(func.id)
            return ".".join(reversed(parts))

        forbidden = {
            "os.remove", "os.unlink", "os.mkdir", "os.makedirs", "os.rename",
            "os.chmod", "os.system", "shutil.copy", "shutil.copyfile",
            "shutil.rmtree", "subprocess.Popen", "subprocess.run",
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = dotted_name(node.func)
            self.assertNotIn(name, forbidden)
            if name == "open":
                for arg in node.args[1:2]:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        self.assertFalse(
                            any(ch in arg.value for ch in "wax+"),
                            "tool opens a file for writing: %r" % arg.value,
                        )

    def test_installer_flow_functions_are_not_called(self):
        deps = FakeDependencies("euid0")
        with mock.patch.object(diag.slopbro, "run", side_effect=AssertionError("installer")), \
                mock.patch.object(diag.slopbro, "run_test_payload", side_effect=AssertionError("payload test")), \
                mock.patch.object(diag.slopbro, "run_test_connection", side_effect=AssertionError("test server")), \
                mock.patch.object(diag.slopbro, "start_http_server", side_effect=AssertionError("foreign server")), \
                mock.patch.object(diag.slopbro, "save_client_key", side_effect=AssertionError("key write")):
            code, result = run_scenario("euid0", deps=deps)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], diag.STATUS_EUID0)
        self.assertTrue(deps.fake_client.closed)
        self.assertEqual(len(deps.launch_calls), 2)
        self.assertFalse(deps.key_saved)


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.token = diag.new_token()
        self.server = diag.DiagnosticServer(
            payload_dir=diag.PAYLOAD_DIR,
            token=self.token,
            expected_peer="127.0.0.1",
            bind_host="127.0.0.1",
            preferred_port=0,
            payload=diag.validate_payload(),
        )
        self.server.start()
        self.addCleanup(self.server.shutdown)

    def get(self, path):
        return http_get(self.server.base_url + path)

    def send_event(self, name, data, token=None):
        query = urlencode({"event": name, "data": json.dumps(data)})
        return self.get(
            diag.event_path(token or self.token) + "?" + query
        )

    def send_result(self, report, path_token=None):
        query = urlencode({"d": json.dumps(report)})
        return self.get(
            diag.result_path(path_token or self.token) + "?" + query
        )

    def test_server_binds_specific_address(self):
        self.assertEqual(self.server._httpd.server_address[0], "127.0.0.1")
        self.assertGreater(self.server.port, 0)

    def test_shutdown_is_safe_after_start_failure(self):
        server = diag.DiagnosticServer(
            payload_dir=diag.PAYLOAD_DIR,
            token=diag.new_token(),
            expected_peer="127.0.0.1",
            bind_host="127.0.0.1",
            preferred_port=0,
            payload=diag.validate_payload(),
        )
        with mock.patch.object(
            diag, "render_payload_file",
            side_effect=diag.DiagnosticError("synthetic render failure"),
        ):
            with self.assertRaises(diag.DiagnosticError):
                server.start()
        server.shutdown()
        self.assertIsNone(server._httpd)

    def test_page_and_payloads_require_the_token(self):
        status, _ = self.get(diag.page_path("0" * 32))
        self.assertEqual(status, 403)
        status, _ = self.get(diag.payload_path("0" * 32, diag.PAYLOAD_MAIN))
        self.assertEqual(status, 403)

        status, body = self.get(diag.page_path(self.token))
        self.assertEqual(status, 200)
        self.assertIn(b"rootdiag.js", body)
        self.assertNotIn(self.token.encode("ascii"), body)

        status, body = self.get(diag.payload_path(self.token, diag.PAYLOAD_MAIN))
        self.assertEqual(status, 200)
        self.assertIn(self.token.encode("ascii"), body)
        self.assertIn(self.server.report_url.encode("ascii"), body)
        self.assertNotIn(b"__DIAG_", body)

    def test_page_is_single_use_to_prevent_a_second_run(self):
        status, _ = self.get(diag.page_path(self.token))
        self.assertEqual(status, 200)
        status, _ = self.get(diag.page_path(self.token))
        self.assertEqual(status, 410)
        observation = self.server.observation()
        self.assertTrue(observation["page_served"])

    def test_forbidden_files_are_never_served(self):
        paths = [
            "/autoroot-webos26.sh",
            "/main.js",
            "/hbchannel.ipk",
            "/p/%s/autoroot-webos26.sh" % self.token,
            "/p/%s/main.js" % self.token,
            "/p/%s/elevate-service" % self.token,
            "/p/%s/%s" % (self.token, "../wwwroot/autoroot.sh"),
        ]
        for path in paths:
            status, _ = self.get(path)
            self.assertIn(status, (403, 404), path)

    def test_served_file_tracking_excludes_page(self):
        self.get(diag.page_path(self.token))
        self.assertEqual(self.server.served_payload_files(), [])
        self.get(diag.payload_path(self.token, "package.json"))
        self.assertEqual(self.server.served_payload_files(), ["package.json"])

    def test_result_requires_matching_path_and_body_token(self):
        report = make_report(self.token)
        status, _ = self.send_result(report, path_token="1" * 32)
        self.assertEqual(status, 403)
        self.assertIsNone(self.server.observation()["payload_result"])

        status, _ = self.send_result(make_report("2" * 32))
        self.assertEqual(status, 400)
        self.assertIsNone(self.server.observation()["payload_result"])

        status, _ = self.send_result(report)
        self.assertEqual(status, 204)
        self.assertEqual(
            self.server.observation()["payload_result"]["token"], self.token
        )

    def test_invalid_result_json_is_rejected(self):
        status, _ = self.get(diag.result_path(self.token) + "?d=not-json")
        self.assertEqual(status, 400)
        status, _ = self.get(diag.result_path(self.token) + "?d=%5B%5D")
        self.assertEqual(status, 400)
        self.assertIsNone(self.server.observation()["payload_result"])

    def test_duplicate_identical_result_is_ignored(self):
        report = make_report(self.token, euid=0, egid=0)
        self.send_result(report)
        self.send_result(report)
        observation = self.server.observation()
        self.assertFalse(observation["result_conflict"])
        self.assertEqual(observation["payload_result"]["geteuid"], 0)

    def test_duplicate_result_from_another_pid_is_not_a_conflict(self):
        self.send_result(make_report(self.token, euid=0, egid=0, pid=100))
        self.send_result(make_report(self.token, euid=0, egid=0, pid=200))
        observation = self.server.observation()
        self.assertFalse(observation["result_conflict"])
        self.assertEqual(observation["payload_result"]["geteuid"], 0)

    def test_conflicting_result_is_flagged(self):
        self.send_result(make_report(self.token, euid=0, egid=0))
        self.send_result(make_report(self.token, euid=1000, egid=1000))
        observation = self.server.observation()
        self.assertTrue(observation["result_conflict"])
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)

    def test_download_events_mark_complete(self):
        for name in diag.PAYLOAD_FILES:
            status, _ = self.send_event(
                "download", {"file": name, "ok": True, "httpStatus": 200}
            )
            self.assertEqual(status, 204)
        status, _ = self.send_event("downloads-complete", {})
        self.assertEqual(status, 204)
        observation = self.server.observation()
        self.assertTrue(observation["download_complete"])
        self.assertEqual(
            observation["downloads_ok"], sorted(diag.PAYLOAD_FILES)
        )

    def test_per_file_confirmations_alone_mark_complete(self):
        for name in diag.PAYLOAD_FILES:
            self.send_event(
                "download", {"file": name, "ok": True, "httpStatus": 200}
            )
        observation = self.server.observation()
        self.assertTrue(observation["download_complete"])
        self.assertIsNone(observation["download_failure"])

    def test_downloads_complete_without_all_files_is_a_failure(self):
        self.send_event("downloads-complete", {})
        observation = self.server.observation()
        self.assertFalse(observation["download_complete"])
        self.assertIn("not all", observation["download_failure"])
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_DOWNLOAD_FAILED)

    def test_downloads_complete_without_per_file_confirmations_is_a_failure(self):
        # Serving the bytes is not a Download Manager confirmation.
        for name in diag.PAYLOAD_FILES:
            status, _ = self.get(diag.payload_path(self.token, name))
            self.assertEqual(status, 200)
        self.send_event("downloads-complete", {})
        observation = self.server.observation()
        self.assertFalse(observation["download_complete"])
        self.assertIn("per-file", observation["download_failure"])
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_DOWNLOAD_FAILED)

    def test_page_error_is_classified_as_download_failure(self):
        self.send_event(
            "page-error",
            {"stage": "download-rejected", "detail": "path not in trusted locations"},
        )
        observation = self.server.observation()
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_DOWNLOAD_FAILED)
        self.assertIn("trusted locations", outcome.detail)

    def test_service_rejection_is_not_success(self):
        self.send_event(
            "run",
            {
                "message": json.dumps(
                    {"returnValue": False, "errorText": "Denied method call"}
                )
            },
        )
        observation = self.server.observation()
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_SERVICE_REJECTED)
        self.assertIn("Denied method call", outcome.detail)

    def test_return_value_true_alone_is_not_success(self):
        self.send_event("run-request", {
            "inputParams": "a b c %s -- /tmp/cgroup dummy %s" % (
                diag.FAKE_SERVICE_PATH,
                diag.TV_DOWNLOAD_DIR,
            )
        })
        self.send_event("run", {"message": json.dumps({"returnValue": True})})
        observation = self.server.observation()
        observation["download_complete"] = True
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)

    def test_unexpected_run_arguments_are_indeterminate(self):
        observation = {
            "download_complete": True,
            "run_requested": True,
            "run_request": {"inputParams": "a b c /different -- /tmp/cgroup dummy /tmp"},
            "run_result": {"returnValue": True},
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("unexpected jsserver argument", outcome.detail)

    def test_wrong_source_address_is_rejected(self):
        query = urlencode({"d": json.dumps(make_report(self.token))})
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.port, timeout=5,
            source_address=("127.0.0.2", 0),
        )
        try:
            try:
                connection.connect()
            except OSError as exc:
                self.skipTest("alternate loopback source address unavailable: %s" % exc)
            connection.request(
                "GET", diag.result_path(self.token) + "?" + query
            )
            response = connection.getresponse()
            body = response.read()
        finally:
            connection.close()
        self.assertEqual(response.status, 403, body)
        self.assertIsNone(self.server.observation()["payload_result"])


class ClassificationTest(unittest.TestCase):
    def setUp(self):
        self.token = diag.new_token()

    def classify(self, report):
        return diag.classify_payload_report(report, self.token)

    def test_effective_uid_zero_is_success(self):
        outcome = self.classify(make_report(self.token, euid=0, egid=0))
        self.assertEqual(outcome.status, diag.STATUS_EUID0)
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.evidence["effective_uid"], 0)
        self.assertEqual(outcome.evidence["uid_source"], "proc")

    def test_nonzero_effective_uid_is_unelevated(self):
        outcome = self.classify(make_report(self.token, euid=1000, egid=1000))
        self.assertEqual(outcome.status, diag.STATUS_UNELEVATED)
        self.assertEqual(outcome.exit_code, 10)

    def test_payload_success_with_download_failure_is_indeterminate(self):
        observation = {
            "payload_result": make_report(self.token, euid=0, egid=0),
            "download_failure": "download of 'package.json' failed",
            "download_complete": True,
            "run_requested": True,
            "run_result": {"returnValue": True},
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("inconsistent", outcome.detail)

    def test_payload_success_without_download_confirmation_is_indeterminate(self):
        observation = {
            "payload_result": make_report(self.token, euid=0, egid=0),
            "download_complete": False,
            "run_requested": True,
            "run_result": {"returnValue": True},
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("download phase was not confirmed", outcome.detail)

    def test_payload_success_without_run_request_is_indeterminate(self):
        observation = {
            "payload_result": make_report(self.token, euid=0, egid=0),
            "download_complete": True,
            "run_requested": False,
            "run_result": None,
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("neither a jsserver/run request", outcome.detail)

    def test_payload_success_with_lost_run_request_beacon_is_allowed(self):
        # A service response is independent evidence that the call was made;
        # losing the separate run-request beacon must not turn a real result
        # into a false negative.
        observation = {
            "payload_result": make_report(self.token, euid=0, egid=0),
            "download_complete": True,
            "run_requested": False,
            "run_result": {"returnValue": True},
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_EUID0)

    def test_payload_success_with_page_error_is_indeterminate(self):
        observation = {
            "payload_result": make_report(self.token, euid=0, egid=0),
            "page_error": {
                "stage": "download-rejected",
                "detail": "path not in trusted locations",
            },
            "download_complete": True,
            "run_requested": True,
            "run_result": {"returnValue": True},
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("page error", outcome.detail)

    def test_payload_success_with_service_rejection_is_indeterminate(self):
        observation = {
            "payload_result": make_report(self.token, euid=0, egid=0),
            "download_complete": True,
            "run_requested": True,
            "run_result": {
                "returnValue": False,
                "errorText": "Denied method call",
            },
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("service rejection", outcome.detail)

    def test_payload_success_with_unexpected_arguments_is_indeterminate(self):
        observation = {
            "payload_result": make_report(self.token, euid=0, egid=0),
            "download_complete": True,
            "run_requested": True,
            "run_request": {
                "inputParams": "a b c /different -- /tmp/cgroup dummy /tmp"
            },
            "run_result": {"returnValue": True},
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("unexpected jsserver argument", outcome.detail)

    def test_proc_only_source(self):
        outcome = self.classify(
            make_report(self.token, euid=0, egid=0, process=False)
        )
        self.assertEqual(outcome.status, diag.STATUS_EUID0)
        self.assertEqual(outcome.evidence["uid_source"], "proc")

    def test_process_only_source(self):
        outcome = self.classify(
            make_report(self.token, euid=0, egid=0, proc=False)
        )
        self.assertEqual(outcome.status, diag.STATUS_EUID0)
        self.assertEqual(outcome.evidence["uid_source"], "process")

    def test_conflicting_uid_sources_are_indeterminate(self):
        report = make_report(self.token, euid=0, egid=0)
        report["geteuid"] = 1000
        outcome = self.classify(report)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("conflicting effective uid", outcome.detail)

    def test_missing_effective_gid_is_indeterminate(self):
        report = make_report(self.token, euid=0, egid=0, proc=False, process=False)
        report["geteuid"] = 0
        outcome = self.classify(report)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("effective gid", outcome.detail)

    def test_boolean_uid_is_rejected(self):
        report = make_report(self.token, euid=0, egid=0, proc=False, process=False)
        report["geteuid"] = True
        report["getegid"] = 0
        outcome = self.classify(report)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)

    def test_error_report_is_payload_execution_failure(self):
        outcome = self.classify(make_report(self.token, status="error"))
        self.assertEqual(outcome.status, diag.STATUS_PAYLOAD_FAILED)
        self.assertEqual(outcome.exit_code, 22)
        self.assertIn("snapshot", outcome.detail)

    def test_wrong_token_or_kind_is_indeterminate(self):
        self.assertEqual(
            self.classify(make_report("3" * 32)).status,
            diag.STATUS_INDETERMINATE,
        )
        report = make_report(self.token)
        report["kind"] = "something-else"
        self.assertEqual(
            self.classify(report).status, diag.STATUS_INDETERMINATE
        )

    def test_outcome_priority(self):
        observation = {
            "payload_result": make_report(self.token, euid=0, egid=0),
            "result_conflict": True,
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)

    def test_download_timeout_without_files(self):
        outcome = diag.classify_outcome(
            {"timed_out_phase": "download", "served_files": []}, self.token
        )
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)

    def test_download_timeout_with_partial_files(self):
        outcome = diag.classify_outcome(
            {
                "timed_out_phase": "download",
                "served_files": ["package.json"],
            },
            self.token,
        )
        self.assertEqual(outcome.status, diag.STATUS_DOWNLOAD_FAILED)

    def test_accepted_service_without_report_is_indeterminate(self):
        observation = {
            "download_complete": True,
            "run_requested": True,
            "run_result": {"returnValue": True},
            "timed_out_phase": "result",
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("no payload report", outcome.detail)

    def test_run_requested_without_response_is_indeterminate(self):
        observation = {
            "download_complete": True,
            "run_requested": True,
            "run_result": None,
            "timed_out_phase": "service",
        }
        outcome = diag.classify_outcome(observation, self.token)
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)
        self.assertIn("no service response", outcome.detail)

    def test_page_bridge_error_is_indeterminate(self):
        outcome = diag.classify_outcome(
            {"page_error": {"stage": "bridge", "detail": "unavailable"}},
            self.token,
        )
        self.assertEqual(outcome.status, diag.STATUS_INDETERMINATE)


class FakeClient(object):
    def __init__(self):
        self.closed = False
        self.registered = None

    def register(self, client_key, manifest):
        self.registered = (client_key, manifest)
        return "synthetic-new-key"

    def close(self):
        self.closed = True


class FakeDependencies(diag.Dependencies):
    def __init__(self, scenario):
        super(FakeDependencies, self).__init__()
        self.scenario = scenario
        self.fake_client = FakeClient()
        self.launch_calls = []
        self.key_saved = False
        self.guess_local_ip = lambda tv_ip, override: "127.0.0.1"
        self.resolve_ipv4 = lambda host: "127.0.0.1"
        self.ws_connect = lambda *args, **kwargs: object()
        self.ssap_client = lambda ws: self.fake_client
        self.load_client_key = lambda tv_ip: ""
        self.launch_app = self._launch
        self.server_factory = diag.DiagnosticServer
        self.sleep = lambda seconds: None

    def _launch(self, client, app_id, params):
        self.launch_calls.append((app_id, dict(params)))
        if "URL" in params:
            self._simulate(params["URL"])
        return {}

    def _fetch(self, url):
        with urlopen(url, timeout=5) as response:
            if response.status != 200:
                raise AssertionError("unexpected status %s for %s" % (response.status, url))
            return response.read()

    def _event(self, base, token, name, data):
        query = urlencode({"event": name, "data": json.dumps(data)})
        with urlopen(
            base + diag.event_path(token) + "?" + query, timeout=5
        ) as response:
            if response.status != 204:
                raise AssertionError("event status %s" % response.status)

    def _result(self, base, token, report):
        query = urlencode({"d": json.dumps(report)})
        with urlopen(
            base + diag.result_path(token) + "?" + query, timeout=5
        ) as response:
            if response.status != 204:
                raise AssertionError("result status %s" % response.status)

    def _simulate(self, url):
        if self.scenario == "no_page":
            return

        parsed = urlsplit(url)
        base = "%s://%s" % (parsed.scheme, parsed.netloc)
        parts = [part for part in parsed.path.split("/") if part]
        token = parts[1]

        self._fetch(url)
        if self.scenario == "download_failure":
            self._fetch(base + diag.payload_path(token, "package.json"))
            self._event(
                base, token, "download",
                {"file": "package.json", "ok": True, "httpStatus": 200},
            )
            self._event(
                base, token, "page-error",
                {
                    "stage": "download-rejected",
                    "detail": "packet rejected: path not in trusted locations",
                },
            )
            return

        for name in diag.PAYLOAD_FILES:
            self._fetch(base + diag.payload_path(token, name))
        for name in diag.PAYLOAD_FILES:
            self._event(
                base, token, "download",
                {"file": name, "ok": True, "httpStatus": 200},
            )

        if self.scenario == "no_run":
            return

        self._event(base, token, "run-request", {
            "inputParams": "a b c %s -- /tmp/cgroup dummy %s" % (
                diag.FAKE_SERVICE_PATH,
                diag.TV_DOWNLOAD_DIR,
            )
        })

        if self.scenario == "service_rejected":
            self._event(
                base, token, "run",
                {"message": json.dumps(
                    {"returnValue": False, "errorText": "Denied method call"}
                )},
            )
            return
        if self.scenario == "run_timeout":
            self._event(base, token, "run-timeout", {})
            return

        self._event(
            base, token, "run",
            {"message": json.dumps({"returnValue": True})},
        )
        if self.scenario == "return_true_only":
            self._event(
                base, token, "run",
                {"message": json.dumps({"returnValue": True})},
            )
            return
        if self.scenario == "no_result":
            return
        if self.scenario == "payload_with_page_error":
            self._event(
                base, token, "page-error",
                {
                    "stage": "download-rejected",
                    "detail": "synthetic contradiction after a payload report",
                },
            )
            self._result(base, token, make_report(token, euid=0, egid=0))
            return
        if self.scenario == "payload_error":
            self._result(base, token, make_report(token, status="error"))
            return
        if self.scenario == "unelevated":
            self._result(
                base, token, make_report(token, euid=1000, egid=1000)
            )
            return
        if self.scenario == "conflict":
            self._result(base, token, make_report(token, euid=0, egid=0))
            self._result(base, token, make_report(token, euid=1000, egid=1000))
            return
        if self.scenario == "duplicate":
            report = make_report(token, euid=0, egid=0)
            self._result(base, token, report)
            self._result(base, token, report)
            return

        self._result(base, token, make_report(token, euid=0, egid=0))


def run_scenario(scenario, deps=None, download_timeout=0.4, result_timeout=0.4):
    deps = deps or FakeDependencies(scenario)
    argv = [
        "--local-ip", "127.0.0.1",
        "--port", "0",
        "--download-timeout", str(download_timeout),
        "--result-timeout", str(result_timeout),
        "192.0.2.5",
    ]
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = diag.main(argv, deps=deps)
    result = None
    for line in stdout.getvalue().splitlines():
        if line.startswith("RESULT: "):
            result = json.loads(line[len("RESULT: "):])
            break
    if result is None:
        raise AssertionError("no RESULT line; stdout=%r stderr=%r" % (
            stdout.getvalue(), stderr.getvalue()
        ))
    return code, result


class EndToEndTest(unittest.TestCase):
    def test_euid0_success(self):
        deps = FakeDependencies("euid0")
        code, result = run_scenario("euid0", deps=deps)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], diag.STATUS_EUID0)
        self.assertEqual(result["evidence"]["effective_uid"], 0)
        self.assertTrue(deps.fake_client.closed)
        self.assertEqual(len(deps.launch_calls), 2)
        self.assertTrue(deps.launch_calls[0][1] == {})
        self.assertIn("URL", deps.launch_calls[1][1])
        self.assertFalse(deps.key_saved)

    def test_only_three_diagnostic_files_are_served(self):
        _code, result = run_scenario("euid0", deps=FakeDependencies("euid0"))
        served = result["context"]["served_files"]
        self.assertEqual(
            served, sorted(diag.PAYLOAD_FILES)
        )
        for name in served:
            self.assertNotIn("autoroot", name)
            self.assertNotIn("hbchannel", name)
            self.assertNotIn("elevate", name)
            self.assertNotEqual(name, "main.js")

    def test_unelevated_result(self):
        code, result = run_scenario("unelevated", deps=FakeDependencies("unelevated"))
        self.assertEqual(code, 10)
        self.assertEqual(result["status"], diag.STATUS_UNELEVATED)

    def test_download_failure(self):
        code, result = run_scenario("download_failure")
        self.assertEqual(code, 20)
        self.assertEqual(result["status"], diag.STATUS_DOWNLOAD_FAILED)

    def test_service_rejection(self):
        code, result = run_scenario("service_rejected")
        self.assertEqual(code, 21)
        self.assertEqual(result["status"], diag.STATUS_SERVICE_REJECTED)

    def test_payload_execution_failure(self):
        code, result = run_scenario("payload_error")
        self.assertEqual(code, 22)
        self.assertEqual(result["status"], diag.STATUS_PAYLOAD_FAILED)

    def test_result_timeout_is_indeterminate_and_not_retried(self):
        deps = FakeDependencies("no_result")
        code, result = run_scenario("no_result", deps=deps)
        self.assertEqual(code, 23)
        self.assertEqual(result["status"], diag.STATUS_INDETERMINATE)
        self.assertEqual(len(deps.launch_calls), 2)

    def test_no_page_is_indeterminate_and_not_retried(self):
        deps = FakeDependencies("no_page")
        code, result = run_scenario("no_page", deps=deps, download_timeout=0.2)
        self.assertEqual(code, 23)
        self.assertEqual(result["status"], diag.STATUS_INDETERMINATE)
        self.assertEqual(len(deps.launch_calls), 2)

    def test_unspecified_local_address_is_refused(self):
        deps = FakeDependencies("euid0")
        deps.guess_local_ip = lambda tv_ip, override: "0.0.0.0"
        code, result = run_scenario("euid0", deps=deps)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], diag.STATUS_SETUP_FAILED)
        self.assertIn("refusing", result["detail"])
        self.assertEqual(len(deps.launch_calls), 0)

    def test_return_value_true_only_is_indeterminate(self):
        code, result = run_scenario("return_true_only")
        self.assertEqual(code, 23)
        self.assertEqual(result["status"], diag.STATUS_INDETERMINATE)

    def test_service_run_timeout_is_indeterminate(self):
        code, result = run_scenario("run_timeout")
        self.assertEqual(code, 23)
        self.assertEqual(result["status"], diag.STATUS_INDETERMINATE)

    def test_duplicate_result_is_ignored(self):
        code, result = run_scenario("duplicate")
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], diag.STATUS_EUID0)

    def test_conflicting_results_are_indeterminate(self):
        code, result = run_scenario("conflict")
        self.assertEqual(code, 23)
        self.assertEqual(result["status"], diag.STATUS_INDETERMINATE)

    def test_payload_success_with_contradictory_page_error_is_indeterminate(self):
        code, result = run_scenario("payload_with_page_error")
        self.assertEqual(code, 23)
        self.assertEqual(result["status"], diag.STATUS_INDETERMINATE)
        self.assertIn("inconsistent", result["detail"])

    def test_dry_run_does_not_start_server_or_contact_tv(self):
        with mock.patch.object(
            diag, "DiagnosticServer", side_effect=AssertionError("server")
        ), mock.patch.object(
            diag.slopbro.WebSocket, "connect", side_effect=AssertionError("TV")
        ), contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()):
            code = diag.main(["--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn('"status": "dry_run"', stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
