import json
import os
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

import slopbro
from webos_root_wizard import RootEngine, WizardError


class LaunchTelemetryTest(unittest.TestCase):
    def test_payload_url_enables_upstream_workaround_by_default(self):
        url = slopbro.build_self_hosted_url(
            "192.0.2.5", 8080, local_ip_override="192.0.2.10"
        )
        self.assertIn(
            "fake-service-path=" + slopbro.DEFAULT_FAKE_SERVICE_PATH, url
        )

    def setUp(self):
        self.tracker = slopbro.RequestedFilesTracker(["index-webos26.html"])
        root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wwwroot")
        self.server = slopbro.start_http_server(
            root, self.tracker, ["index-webos26.html"],
            allow_embedded_assets=False, allow_filesystem_fallback=True,
            bind_host="127.0.0.1", preferred_port=0,
        )
        self.base = "http://127.0.0.1:%d/" % self.server.server_port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_file_request_is_only_counted_after_get(self):
        with urlopen(Request(self.base + "index-webos26.html", method="HEAD")):
            pass
        self.assertFalse(self.tracker.wait_for_all(0))
        with urlopen(self.base + "index-webos26.html") as response:
            self.assertTrue(response.read())
        self.assertTrue(self.tracker.wait_for_all(1))

    def test_launch_rejection_is_reported_separately_from_files(self):
        response = {
            "returnValue": False,
            "error": "Rejected service launch - path not in trusted locations",
        }
        url = self.base + "primary-run-result?m=" + quote(json.dumps(response))
        with urlopen(url) as result:
            self.assertEqual(result.status, 204)
        self.assertEqual(self.tracker.wait_for_launch_response(1), response)
        self.assertFalse(self.tracker.wait_for_all(0))

    def test_token_path_is_required(self):
        root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wwwroot")
        token_tracker = slopbro.RequestedFilesTracker(["index-webos26.html"])
        token_server = slopbro.start_http_server(
            root, token_tracker, ["index-webos26.html"],
            allow_embedded_assets=False, allow_filesystem_fallback=True,
            bind_host="127.0.0.1", preferred_port=0, token="secret-token",
        )
        base = "http://127.0.0.1:%d/" % token_server.server_port
        try:
            with self.assertRaises(HTTPError) as root_error:
                urlopen(base + "index-webos26.html")
            self.assertEqual(root_error.exception.code, 404)

            with self.assertRaises(HTTPError) as wrong_token:
                urlopen(base + "p/wrong/index-webos26.html")
            self.assertEqual(wrong_token.exception.code, 404)

            with urlopen(base + "p/secret-token/index-webos26.html") as response:
                self.assertTrue(response.read())
            self.assertTrue(token_tracker.wait_for_all(1))
        finally:
            token_server.shutdown()
            token_server.server_close()


class SystemInfoTest(unittest.TestCase):
    class Client(object):
        def __init__(self, response):
            self.response = response

        def request(self, uri, payload, timeout):
            self.uri = uri
            self.payload = payload
            self.timeout = timeout
            return self.response

    def make_engine(self):
        engine = RootEngine.__new__(RootEngine)
        engine.log = Mock()
        return engine

    def test_reads_payload_system_info(self):
        engine = self.make_engine()
        info = engine.read_system_info(self.Client({
            "type": "response",
            "payload": {
                "modelName": "OLED65G49LS",
                "firmwareVersion": "43.21.73",
                "sdkVersion": "11.2.0-3703",
            },
        }))
        self.assertEqual(info["modelName"], "OLED65G49LS")
        self.assertEqual(info["firmwareVersion"], "43.21.73")
        self.assertEqual(info["sdkVersion"], "11.2.0-3703")

    def test_missing_system_info_does_not_raise(self):
        engine = self.make_engine()
        info = engine.read_system_info(self.Client({"type": "error", "error": "Denied"}))
        self.assertEqual(info, {})
        engine.validate_sdk_version(info)

    def test_rejects_non_webos26_sdk(self):
        engine = self.make_engine()
        with self.assertRaisesRegex(WizardError, "webOS 26"):
            engine.validate_sdk_version({"sdkVersion": "10.0.0"})

    def test_accepts_webos26_sdk(self):
        engine = self.make_engine()
        engine.validate_sdk_version({"sdkVersion": "11.2.0-3703"})


class WizardCompatibilityFlowTest(unittest.TestCase):
    def make_engine(self, compatible, homebrew, proceed=True, root_ok=True):
        engine = RootEngine.__new__(RootEngine)
        engine.tv_ip = "192.0.2.5"
        engine.local_ip_override = "192.0.2.10"
        engine.log = Mock()
        engine.status = Mock()
        engine.ask_user = Mock(side_effect=[proceed, root_ok])
        engine.check_prerequisites = Mock()
        engine.compatibility_attempt = Mock(return_value=compatible)
        engine.wait_for_homebrew = Mock(side_effect=homebrew)
        return engine

    def test_compatible_success_runs_exactly_once(self):
        engine = self.make_engine(
            (True, {"returnValue": True}), [True],
        )
        engine.run()
        engine.compatibility_attempt.assert_called_once_with(100)
        engine.wait_for_homebrew.assert_called_once_with()
        self.assertEqual(engine.ask_user.call_count, 2)

    def test_missing_files_does_not_retry(self):
        engine = self.make_engine((False, None), [False])
        with self.assertRaisesRegex(WizardError, "did not request all files"):
            engine.run()
        engine.compatibility_attempt.assert_called_once_with(100)
        engine.wait_for_homebrew.assert_called_once_with(10)

    def test_homebrew_appears_despite_missing_files(self):
        engine = self.make_engine((False, None), [True])
        engine.run()
        engine.compatibility_attempt.assert_called_once_with(100)
        engine.wait_for_homebrew.assert_called_once_with(10)

    def test_rejected_compatible_launch_is_an_error(self):
        engine = self.make_engine(
            (True, {"returnValue": False, "error": "compatible rejected"}),
            [False],
        )
        with self.assertRaisesRegex(WizardError, "compatible rejected"):
            engine.run()
        engine.compatibility_attempt.assert_called_once_with(100)
        engine.wait_for_homebrew.assert_called_once_with(10)

    def test_homebrew_appears_despite_rejected_launch(self):
        engine = self.make_engine(
            (True, {"returnValue": False, "error": "compatible rejected"}),
            [True],
        )
        engine.run()
        engine.compatibility_attempt.assert_called_once_with(100)
        engine.wait_for_homebrew.assert_called_once_with(10)

    def test_missing_homebrew_is_an_error(self):
        engine = self.make_engine((True, {"returnValue": True}), [False])
        with self.assertRaisesRegex(WizardError, "did not appear"):
            engine.run()
        engine.compatibility_attempt.assert_called_once_with(100)

    def test_root_ok_declined_is_an_error(self):
        engine = self.make_engine(
            (True, {"returnValue": True}), [True], root_ok=False,
        )
        with self.assertRaisesRegex(WizardError, "Root OK was not confirmed"):
            engine.run()
        self.assertEqual(engine.ask_user.call_args_list[-1][0][0], "Check Root OK")

    def test_user_cancels_before_attempt(self):
        engine = self.make_engine((True, {"returnValue": True}), [], proceed=False)
        with self.assertRaisesRegex(WizardError, "Stopped by the user"):
            engine.run()
        engine.compatibility_attempt.assert_not_called()


class WizardLanguageTest(unittest.TestCase):
    def test_wizard_source_has_no_cyrillic_strings(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "webos_root_wizard.py"
        )
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
        self.assertFalse(
            any("\u0400" <= character <= "\u04FF" for character in source),
            "the wizard is English-only; translate new UI strings instead of "
            "adding Cyrillic text",
        )


if __name__ == "__main__":
    unittest.main()
