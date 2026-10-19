#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal, non-persistent webOS 26 privilege diagnostic.

This tool reuses the existing SlopBro jsserver trigger and the webOS 26
compatibility loader's sequential download mechanism, but replaces the
installer payload with a read-only UID/GID check.

It deliberately does NOT:

* download or execute autoroot.sh / autoroot-webos26.sh,
* download or install Homebrew Channel,
* execute elevate-service,
* start SSH, Telnet or any other remote shell,
* modify LS2 permissions, manifests or Developer Mode state,
* create boot hooks or persistent services,
* reboot the TV or retry the exploit automatically.

Only three inert files are written to /media/internal/downloads by the TV's
download manager. The privileged JavaScript payload reads /proc/self/status
and reports the values back over HTTP. It writes no files.

Payload validation is a defense-in-depth heuristic, not a JavaScript sandbox;
the shipped payload is intentionally small and still requires manual review.

See the project documentation for the full description, the unavoidable
side effects and the interpretation limits.
"""

from __future__ import print_function

import argparse
import binascii
import json
import os
import re
import socket
import sys
import threading
import time
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import slopbro  # noqa: E402


TOOL_VERSION = "webos26_root_diagnostic/1"

PAYLOAD_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "diagnostic_payload"
)
PAGE_NAME = "rootdiag.html"
PAYLOAD_FILES = ("package.json", "services.json", "rootdiag.js")
PAYLOAD_FILE_SET = frozenset(PAYLOAD_FILES)
PAYLOAD_MANIFEST_NAME = "com.webos.service.jsserver"
PAYLOAD_MAIN = "rootdiag.js"
PAYLOAD_REPORT_KIND = "rootdiag-result"

# Filesystem metadata that may appear next to the payload without changing its
# meaning. Anything else in the directory is rejected by validate_payload.
IGNORED_PAYLOAD_METADATA = frozenset((".DS_Store", "Thumbs.db", "desktop.ini"))

TV_DOWNLOAD_DIR = "/media/internal/downloads"
FAKE_SERVICE_PATH = slopbro.DEFAULT_FAKE_SERVICE_PATH
VOICEWEB_APP = "com.webos.app.voiceweb"

TOKEN_BYTES = 16
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_EVENT_DATA = 4096
MAX_EVENT_NAME = 64
MAX_RESULT_DATA = 16384

STATUS_EUID0 = "executed_euid0"
STATUS_UNELEVATED = "executed_unelevated"
STATUS_DOWNLOAD_FAILED = "download_failed"
STATUS_SERVICE_REJECTED = "service_rejected"
STATUS_PAYLOAD_FAILED = "payload_execution_failed"
STATUS_INDETERMINATE = "indeterminate"
STATUS_SETUP_FAILED = "setup_failed"

EXIT_CODES = {
    STATUS_EUID0: 0,
    STATUS_UNELEVATED: 10,
    STATUS_DOWNLOAD_FAILED: 20,
    STATUS_SERVICE_REJECTED: 21,
    STATUS_PAYLOAD_FAILED: 22,
    STATUS_INDETERMINATE: 23,
    STATUS_SETUP_FAILED: 2,
}

# These markers are rejected in every served diagnostic payload. The list
# detects obvious accidental installer/shell/boot content; it is a heuristic,
# not a JavaScript sandbox and not a complete security proof.
FORBIDDEN_PAYLOAD_MARKERS = (
    "autoroot",
    "hbchannel",
    "homebrew",
    "elevate-service",
    "telnet",
    "sshd",
    "dropbear",
    "start-devmode",
    "devmode_enabled",
    "authorized_keys",
    "webosbrew",
    "systemctl",
    "init.d",
    "rc.local",
    "boot",
    "insmod",
)

FORBIDDEN_PAYLOAD_APIS = (
    "child_process",
    "execfile",
    "execsync",
    "spawn",
    "writefile",
    "appendfile",
    "createwritestream",
    "unlink",
    "rename",
    "mkdir",
    "chmod",
    "process.exit",
    "eval(",
    "new function",
)


class DiagnosticError(Exception):
    pass


def log(message):
    sys.stderr.write("[diag %s] %s\n" % (time.strftime("%H:%M:%S"), message))
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Payload validation and rendering
# ---------------------------------------------------------------------------


def _payload_path(payload_dir, name):
    base = os.path.realpath(payload_dir)
    path = os.path.realpath(os.path.join(base, name))
    if os.path.dirname(path) != base:
        raise DiagnosticError(
            "payload file %r resolves outside the diagnostic payload directory" % name
        )
    if not os.path.isfile(path):
        raise DiagnosticError("missing diagnostic payload file: %s" % name)
    return path


def read_payload_file(payload_dir, name):
    with open(_payload_path(payload_dir, name), "rb") as handle:
        return handle.read()


def _decode_payload(data, name):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DiagnosticError("payload file %s is not valid UTF-8: %s" % (name, exc))


def validate_payload(payload_dir=PAYLOAD_DIR):
    """Validate the exact diagnostic payload set and return metadata.

    The exact file set, the manifest main entry and the server-side route
    whitelist prevent accidentally reusing the repository's installer files.
    The marker/API scan below is a defense-in-depth heuristic, not a
    JavaScript sandbox and not a formal proof that a payload cannot do harm:
    obfuscated or dynamically constructed code could evade string checks. The
    shipped payload is intentionally tiny and still requires manual review.

    Raises DiagnosticError.
    """
    if not os.path.isdir(payload_dir):
        raise DiagnosticError("diagnostic payload directory not found: %s" % payload_dir)

    expected_names = set(PAYLOAD_FILES) | {PAGE_NAME}
    actual_names = set(os.listdir(payload_dir)) - IGNORED_PAYLOAD_METADATA
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        details = []
        if missing:
            details.append("missing: %s" % ", ".join(missing))
        if extra:
            details.append("unexpected: %s" % ", ".join(extra))
        raise DiagnosticError(
            "diagnostic payload directory must contain exactly %s (%s)"
            % (", ".join(sorted(expected_names)), "; ".join(details))
        )

    raw = {}
    text = {}
    for name in sorted(expected_names):
        raw[name] = read_payload_file(payload_dir, name)
        text[name] = _decode_payload(raw[name], name)

    for name in sorted(expected_names):
        lower = text[name].lower()
        for marker in FORBIDDEN_PAYLOAD_MARKERS:
            if marker in lower:
                raise DiagnosticError(
                    "payload file %s contains forbidden marker %r" % (name, marker)
                )

    js_lower = text[PAYLOAD_MAIN].lower()
    for marker in FORBIDDEN_PAYLOAD_APIS:
        if marker in js_lower:
            raise DiagnosticError(
                "payload file %s contains forbidden API %r" % (PAYLOAD_MAIN, marker)
            )

    for placeholder in ("__DIAG_TOKEN__", "__DIAG_REPORT_URL__"):
        if placeholder not in text[PAYLOAD_MAIN]:
            raise DiagnosticError(
                "payload file %s is missing placeholder %s"
                % (PAYLOAD_MAIN, placeholder)
            )

    try:
        manifest = json.loads(text["package.json"])
    except ValueError as exc:
        raise DiagnosticError("package.json is not valid JSON: %s" % exc)
    if not isinstance(manifest, dict):
        raise DiagnosticError("package.json must contain a JSON object")
    if set(manifest.keys()) != {"name", "main"}:
        raise DiagnosticError(
            "package.json must contain exactly the name and main fields"
        )
    if manifest.get("name") != PAYLOAD_MANIFEST_NAME:
        raise DiagnosticError(
            "package.json name must be %s (found %r)"
            % (PAYLOAD_MANIFEST_NAME, manifest.get("name"))
        )
    if manifest.get("main") != PAYLOAD_MAIN:
        raise DiagnosticError(
            "package.json main must be %s (found %r)"
            % (PAYLOAD_MAIN, manifest.get("main"))
        )

    try:
        services = json.loads(text["services.json"])
    except ValueError as exc:
        raise DiagnosticError("services.json is not valid JSON: %s" % exc)
    if not isinstance(services, dict) or set(services.keys()) != {"id", "services"}:
        raise DiagnosticError(
            "services.json must contain exactly the id and services fields"
        )
    if services.get("id") != PAYLOAD_MANIFEST_NAME:
        raise DiagnosticError(
            "services.json must describe %s" % PAYLOAD_MANIFEST_NAME
        )
    service_entries = services.get("services")
    if service_entries != [{"name": PAYLOAD_MANIFEST_NAME}]:
        raise DiagnosticError(
            "services.json must list exactly %s" % PAYLOAD_MANIFEST_NAME
        )

    page_lower = text[PAGE_NAME].lower()
    required_page_content = (
        PAYLOAD_MAIN,
        "jsserver/run",
        TV_DOWNLOAD_DIR,
        FAKE_SERVICE_PATH,
    )
    for required in required_page_content:
        if required.lower() not in page_lower:
            raise DiagnosticError(
                "diagnostic page is missing required content %r" % required
            )

    files = {}
    for name in sorted(expected_names):
        files[name] = {
            "size": len(raw[name]),
            "sha256": sha256(raw[name]).hexdigest(),
        }

    return {
        "payload_dir": os.path.realpath(payload_dir),
        "files": files,
        "manifest": manifest,
        "services": services,
    }


def render_payload_file(payload, name, token, report_url):
    """Return the bytes served for a payload file, substituting the run token."""
    data = read_payload_file(payload["payload_dir"], name)
    if name != PAYLOAD_MAIN:
        return data
    text = _decode_payload(data, name)
    text = text.replace("__DIAG_TOKEN__", token)
    text = text.replace("__DIAG_REPORT_URL__", report_url)
    if "__DIAG_" in text:
        raise DiagnosticError("unsubstituted diagnostic placeholder remains")
    return text.encode("utf-8")


# ---------------------------------------------------------------------------
# URL layout (token is part of the path, not a query parameter)
# ---------------------------------------------------------------------------


def page_path(token):
    return "/p/%s/%s" % (token, PAGE_NAME)


def payload_path(token, name):
    return "/p/%s/%s" % (token, name)


def event_path(token):
    return "/e/%s/event" % token


def result_path(token):
    return "/r/%s/result" % token


def new_token():
    return binascii.hexlify(os.urandom(TOKEN_BYTES)).decode("ascii")


# ---------------------------------------------------------------------------
# Outcome model
# ---------------------------------------------------------------------------


class Outcome(object):
    def __init__(self, status, detail, evidence=None):
        self.status = status
        self.detail = detail
        self.evidence = evidence or {}

    @property
    def exit_code(self):
        return EXIT_CODES.get(self.status, 1)

    def to_dict(self):
        return {
            "status": self.status,
            "detail": self.detail,
            "exit_code": self.exit_code,
            "evidence": self.evidence,
        }


def _as_int(value):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value


def _bounded(value, limit=200):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    try:
        text = str(value)
    except Exception:
        return None
    if len(text) > limit:
        text = text[:limit]
    return text


def _sanitize_id_block(block):
    if not isinstance(block, dict):
        return None
    return {
        "real": _as_int(block.get("real")),
        "effective": _as_int(block.get("effective")),
        "saved": _as_int(block.get("saved")),
        "filesystem": _as_int(block.get("filesystem")),
    }


def _sanitize_report(report):
    if not isinstance(report, dict):
        return {"_type": type(report).__name__}
    argv = report.get("argv")
    if isinstance(argv, list):
        argv = [_bounded(item, 120) for item in argv[:8]]
    else:
        argv = []
    return {
        "kind": _bounded(report.get("kind"), 40),
        "status": _bounded(report.get("status"), 20),
        "returnValue": (
            report.get("returnValue")
            if isinstance(report.get("returnValue"), bool)
            else None
        ),
        "pid": _as_int(report.get("pid")),
        "ppid": _as_int(report.get("ppid")),
        "node": _bounded(report.get("node"), 40),
        "platform": _bounded(report.get("platform"), 40),
        "uid": _sanitize_id_block(report.get("uid")),
        "gid": _sanitize_id_block(report.get("gid")),
        "getuid": _as_int(report.get("getuid")),
        "geteuid": _as_int(report.get("geteuid")),
        "getgid": _as_int(report.get("getgid")),
        "getegid": _as_int(report.get("getegid")),
        "proc_status_error": _bounded(report.get("proc_status_error"), 200),
        "stage": _bounded(report.get("stage"), 40),
        "error": _bounded(report.get("error"), 300),
        "errorText": _bounded(report.get("errorText"), 300),
        "message": _bounded(report.get("message"), 300),
        "argv": argv,
    }


def classify_payload_report(report, token):
    """Classify a token-matched payload report. Never assumes success without uid 0."""
    if not isinstance(report, dict):
        return Outcome(STATUS_INDETERMINATE, "payload report is not a JSON object")
    if report.get("kind") != PAYLOAD_REPORT_KIND:
        return Outcome(
            STATUS_INDETERMINATE,
            "unexpected payload report kind: %r" % report.get("kind"),
        )
    if report.get("token") != token:
        return Outcome(STATUS_INDETERMINATE, "payload report token mismatch")

    evidence = _sanitize_report(report)
    status = report.get("status")
    if status == "error":
        stage = _bounded(report.get("stage"), 40) or "unknown"
        error = _bounded(report.get("error"), 300) or "unknown error"
        return Outcome(
            STATUS_PAYLOAD_FAILED,
            "payload reported an execution error at %s: %s" % (stage, error),
            evidence=evidence,
        )
    if status != "ok":
        return Outcome(
            STATUS_INDETERMINATE,
            "invalid payload status: %r" % status,
            evidence=evidence,
        )

    uid_block = report.get("uid") if isinstance(report.get("uid"), dict) else {}
    gid_block = report.get("gid") if isinstance(report.get("gid"), dict) else {}

    proc_euid = _as_int(uid_block.get("effective"))
    proc_egid = _as_int(gid_block.get("effective"))
    get_euid = _as_int(report.get("geteuid"))
    get_egid = _as_int(report.get("getegid"))
    proc_ruid = _as_int(uid_block.get("real"))
    get_uid = _as_int(report.get("getuid"))

    if proc_euid is not None and get_euid is not None and proc_euid != get_euid:
        return Outcome(
            STATUS_INDETERMINATE,
            "conflicting effective uid values (/proc=%d, process=%d)"
            % (proc_euid, get_euid),
            evidence=evidence,
        )
    if proc_egid is not None and get_egid is not None and proc_egid != get_egid:
        return Outcome(
            STATUS_INDETERMINATE,
            "conflicting effective gid values (/proc=%d, process=%d)"
            % (proc_egid, get_egid),
            evidence=evidence,
        )

    effective_uid = proc_euid if proc_euid is not None else get_euid
    effective_gid = proc_egid if proc_egid is not None else get_egid
    real_uid = proc_ruid if proc_ruid is not None else get_uid

    if effective_uid is None:
        return Outcome(
            STATUS_INDETERMINATE,
            "payload report contains no usable effective uid",
            evidence=evidence,
        )
    if effective_gid is None:
        return Outcome(
            STATUS_INDETERMINATE,
            "payload report contains no usable effective gid",
            evidence=evidence,
        )

    evidence["effective_uid"] = effective_uid
    evidence["effective_gid"] = effective_gid
    evidence["real_uid"] = real_uid
    evidence["uid_source"] = "proc" if proc_euid is not None else "process"
    evidence["gid_source"] = "proc" if proc_egid is not None else "process"

    if effective_uid == 0:
        detail = "effective uid 0 confirmed by the privileged payload (egid %d" % effective_gid
        if real_uid is not None:
            detail += ", real uid %d" % real_uid
        detail += ")"
        return Outcome(STATUS_EUID0, detail, evidence=evidence)

    return Outcome(
        STATUS_UNELEVATED,
        "payload executed, but effective uid is %d (egid %d), not 0"
        % (effective_uid, effective_gid),
        evidence=evidence,
    )


def _service_error_text(run_result):
    for key in ("errorText", "error", "message"):
        value = run_result.get(key)
        if value:
            return _bounded(value, 300)
    return json.dumps(run_result, sort_keys=True)[:300]


def expected_input_params():
    """The exact jsserver argument string used by the compatibility chain."""
    return "a b c %s -- /tmp/cgroup dummy %s" % (
        FAKE_SERVICE_PATH,
        TV_DOWNLOAD_DIR,
    )


def _payload_success_contradiction(observation):
    """Describe recorded evidence that contradicts a successful run.

    A direct payload report is strong evidence, but a recorded download
    failure, page-level error, explicit service rejection or a mismatching
    jsserver argument string contradicts the chain that must have produced
    it. Missing confirmation events are not treated as contradictions here:
    a lost beacon does not disprove a direct payload report. Explicit
    failures and mismatches do.
    """
    page_error = observation.get("page_error")
    if page_error:
        if isinstance(page_error, dict):
            stage = _bounded(page_error.get("stage"), 40) or "page-error"
            detail = _bounded(page_error.get("detail"), 400) or ""
        else:
            stage = _bounded(page_error, 40) or "page-error"
            detail = ""
        message = "page error (%s)" % stage
        if detail:
            message += ": " + detail
        return message

    download_failure = observation.get("download_failure")
    if download_failure:
        return "download failure: %s" % _bounded(download_failure, 300)

    run_result = observation.get("run_result")
    if isinstance(run_result, dict) and run_result.get("returnValue") is False:
        return "service rejection: %s" % _service_error_text(run_result)

    run_request = observation.get("run_request")
    if isinstance(run_request, dict):
        observed_input = run_request.get("inputParams")
        if observed_input is not None and observed_input != expected_input_params():
            return "unexpected jsserver argument string: %r" % observed_input

    return None


def classify_outcome(observation, token):
    """Turn the observed phase data into one of the documented outcomes."""
    if observation.get("setup_error"):
        return Outcome(STATUS_SETUP_FAILED, str(observation["setup_error"]))

    payload_result = observation.get("payload_result")
    if payload_result is not None:
        if observation.get("result_conflict"):
            return Outcome(
                STATUS_INDETERMINATE,
                "conflicting payload reports were received",
                evidence={"payload_result": _sanitize_report(payload_result)},
            )
        payload_outcome = classify_payload_report(payload_result, token)
        if payload_outcome.status in (STATUS_EUID0, STATUS_UNELEVATED):
            if not observation.get("download_complete"):
                return Outcome(
                    STATUS_INDETERMINATE,
                    "the payload reported %s, but the download phase was not "
                    "confirmed by the page" % payload_outcome.status,
                    evidence={"payload_result": _sanitize_report(payload_result)},
                )
            if (
                not observation.get("run_requested")
                and observation.get("run_result") is None
            ):
                return Outcome(
                    STATUS_INDETERMINATE,
                    "the payload reported %s, but neither a jsserver/run "
                    "request nor a service response was recorded"
                    % payload_outcome.status,
                    evidence={"payload_result": _sanitize_report(payload_result)},
                )
            contradiction = _payload_success_contradiction(observation)
            if contradiction:
                return Outcome(
                    STATUS_INDETERMINATE,
                    "the payload reported %s, but the recorded chain is "
                    "inconsistent: %s"
                    % (payload_outcome.status, contradiction),
                    evidence={
                        "payload_result": _sanitize_report(payload_result),
                        "contradiction": contradiction,
                    },
                )
        return payload_outcome

    if observation.get("result_conflict"):
        return Outcome(STATUS_INDETERMINATE, "conflicting payload reports were received")

    page_error = observation.get("page_error")
    if page_error:
        stage = _bounded(page_error.get("stage"), 40) or "page-error"
        detail = _bounded(page_error.get("detail"), 400) or ""
        message = "diagnostic page error (%s)" % stage
        if detail:
            message += ": " + detail
        evidence = {"page_error": {"stage": stage, "detail": detail}}
        if stage.startswith("download"):
            return Outcome(STATUS_DOWNLOAD_FAILED, message, evidence=evidence)
        return Outcome(STATUS_INDETERMINATE, message, evidence=evidence)

    download_failure = observation.get("download_failure")
    if download_failure:
        return Outcome(STATUS_DOWNLOAD_FAILED, str(download_failure))

    run_request = observation.get("run_request")
    if isinstance(run_request, dict):
        observed_input = run_request.get("inputParams")
        if observed_input is not None and observed_input != expected_input_params():
            return Outcome(
                STATUS_INDETERMINATE,
                "the page reported an unexpected jsserver argument string: %r"
                % observed_input,
                evidence={"run_request": {"inputParams": observed_input}},
            )

    run_result = observation.get("run_result")
    if isinstance(run_result, dict):
        return_value = run_result.get("returnValue")
        if return_value is False:
            return Outcome(
                STATUS_SERVICE_REJECTED,
                "the TV rejected the jsserver request: %s"
                % _service_error_text(run_result),
                evidence={"run_response": _sanitize_report(run_result)},
            )
        if return_value is not True:
            return Outcome(
                STATUS_INDETERMINATE,
                "the service response did not contain a boolean returnValue",
                evidence={"run_response": _sanitize_report(run_result)},
            )

    if observation.get("run_timeout"):
        return Outcome(
            STATUS_INDETERMINATE,
            "no service response was received within the page timeout",
        )

    if observation.get("download_complete"):
        if run_result is None:
            if observation.get("run_requested"):
                if observation.get("timed_out_phase") == "service":
                    return Outcome(
                        STATUS_INDETERMINATE,
                        "the run request was sent, but no service response arrived "
                        "before the timeout",
                    )
                return Outcome(
                    STATUS_INDETERMINATE,
                    "the run request was sent, but no service response was observed",
                )
            return Outcome(
                STATUS_INDETERMINATE,
                "all downloads completed, but no jsserver/run request was observed",
            )
        if isinstance(run_result, dict) and run_result.get("returnValue") is True:
            if observation.get("timed_out_phase") == "result":
                return Outcome(
                    STATUS_INDETERMINATE,
                    "the service accepted the request, but no payload report arrived "
                    "before the result timeout",
                )
            return Outcome(
                STATUS_INDETERMINATE,
                "the service accepted the request, but no payload report arrived",
            )

    if observation.get("timed_out_phase") == "download":
        served = observation.get("served_files") or []
        if served:
            return Outcome(
                STATUS_DOWNLOAD_FAILED,
                "the download phase timed out; the TV fetched only: %s"
                % ", ".join(served),
                evidence={"served_files": list(served)},
            )
        return Outcome(
            STATUS_INDETERMINATE,
            "the diagnostic page was not loaded or requested no payload files",
        )

    return Outcome(STATUS_INDETERMINATE, "the diagnostic reached an incomplete state")


# ---------------------------------------------------------------------------
# Local HTTP server
# ---------------------------------------------------------------------------


class DiagnosticServer(object):
    """Small token-gated HTTP server for the diagnostic page, payload and result.

    Only the four whitelisted files are served. No request path is used to
    open a file, there is no directory listing and no wwwroot fallback. The
    content checks in validate_payload are a heuristic (see its docstring),
    not a JavaScript sandbox; the route whitelist keeps the server from ever
    serving an arbitrary repository file.
    """

    class _HTTPServer(HTTPServer):
        # The page emits several small beacons in quick succession.
        request_queue_size = 16

    def __init__(
        self,
        payload_dir=PAYLOAD_DIR,
        token=None,
        expected_peer=None,
        bind_host="127.0.0.1",
        preferred_port=8080,
        payload=None,
    ):
        if payload is None:
            payload = validate_payload(payload_dir)
        self.payload = payload
        self.payload_dir = payload["payload_dir"]
        self.token = token or new_token()
        if not TOKEN_RE.match(self.token):
            raise DiagnosticError("invalid diagnostic token")
        self.expected_peer = expected_peer
        self.bind_host = bind_host
        self.preferred_port = preferred_port

        self._page_bytes = read_payload_file(self.payload_dir, PAGE_NAME)
        self._raw = {
            name: read_payload_file(self.payload_dir, name) for name in PAYLOAD_FILES
        }
        self._rendered = {}

        self._httpd = None
        self._thread = None
        self.port = None
        self.base_url = None
        self.report_url = None

        self._lock = threading.Lock()
        self._download_event = threading.Event()
        self._run_event = threading.Event()
        self._result_event = threading.Event()

        self._page_loaded = False
        self._page_served = False
        self._served = set()
        self._downloads_ok = set()
        self._download_complete = False
        self._download_failure = None
        self._page_error = None
        self._run_requested = False
        self._run_request = None
        self._run_response = None
        self._run_timeout = False
        self._result = None
        self._result_fingerprint = None
        self._result_conflict = False
        self._event_names = []

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        handler = self._make_handler()
        for port in (self.preferred_port, 0):
            try:
                self._httpd = self._HTTPServer((self.bind_host, port), handler)
                break
            except socket.error:
                self._httpd = None
        if self._httpd is None:
            raise DiagnosticError(
                "could not bind the diagnostic HTTP server to %s" % self.bind_host
            )
        self.port = self._httpd.server_port
        if self.port <= 0:
            self._httpd.server_close()
            self._httpd = None
            raise DiagnosticError("diagnostic HTTP server has no port")
        self.base_url = "http://%s:%d" % (self.bind_host, self.port)
        self.report_url = self.base_url + result_path(self.token)
        self._rendered[PAYLOAD_MAIN] = render_payload_file(
            self.payload, PAYLOAD_MAIN, self.token, self.report_url
        )
        self._thread = threading.Thread(target=self._httpd.serve_forever)
        self._thread.daemon = True
        self._thread.start()

    def shutdown(self):
        httpd = self._httpd
        thread = self._thread
        self._httpd = None
        self._thread = None
        if httpd is not None:
            # shutdown() waits for serve_forever() to return; only call it if the
            # serving thread was actually started. This also keeps a failure
            # between bind() and thread start from hanging the process.
            if thread is not None:
                try:
                    httpd.shutdown()
                except Exception:
                    pass
            try:
                httpd.server_close()
            except Exception:
                pass

    def _make_handler(self):
        server = self

        class DiagnosticRequestHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):
                server._handle_request(self, head_only=False)

            def do_HEAD(self):
                server._handle_request(self, head_only=True)

            def log_request(self, code="-", size="-"):
                path = urlsplit(self.path).path.replace(server.token, "<token>")
                log("http %s %s -> %s" % (self.command, path, code))

            def log_message(self, fmt, *args):
                # Suppress the default request line; it would contain the token.
                pass

        return DiagnosticRequestHandler

    # -- request handling --------------------------------------------------

    def _handle_request(self, handler, head_only):
        if not self._peer_allowed(handler.client_address[0]):
            self._send_error(handler, 403, "client address not allowed")
            return

        path = urlsplit(handler.path).path
        parts = [unquote(part) for part in path.split("/") if part]
        if len(parts) != 3:
            self._send_error(handler, 404, "not found")
            return

        kind, path_token, name = parts
        if path_token != self.token:
            self._send_error(handler, 403, "invalid diagnostic token")
            return

        if kind == "p" and name == PAGE_NAME:
            with self._lock:
                already_served = self._page_served
            if already_served:
                # A reload would start a second download/run sequence with the
                # same token. Refuse it: the diagnostic performs one attempt.
                self._send_error(handler, 410, "diagnostic page already served")
                return
            if self._send_bytes(
                handler, self._page_bytes, "text/html; charset=utf-8", head_only
            ) and not head_only:
                with self._lock:
                    self._page_served = True
                    self._page_loaded = True
            return

        if kind == "p" and name in PAYLOAD_FILE_SET:
            data = self._rendered.get(name) or self._raw.get(name)
            if data is None:
                self._send_error(handler, 404, "not found")
                return
            ctype = (
                "application/json; charset=utf-8"
                if name.endswith(".json")
                else "application/javascript; charset=utf-8"
            )
            if self._send_bytes(handler, data, ctype, head_only) and not head_only:
                self._mark_served(name)
            return

        if kind == "e" and name == "event":
            if head_only:
                self._send_error(handler, 405, "method not allowed")
                return
            self._handle_event(handler)
            return

        if kind == "r" and name == "result":
            if head_only:
                self._send_error(handler, 405, "method not allowed")
                return
            self._handle_result(handler)
            return

        self._send_error(handler, 404, "not found")

    def _handle_event(self, handler):
        query = parse_qs(urlsplit(handler.path).query, keep_blank_values=True)
        name = (query.get("event") or [""])[0]
        raw = (query.get("data") or [""])[0]
        if not name or len(name) > MAX_EVENT_NAME:
            self._send_error(handler, 400, "invalid event name")
            return
        if len(raw) > MAX_EVENT_DATA:
            self._send_error(handler, 400, "event data too large")
            return
        try:
            data = json.loads(raw) if raw else {}
        except (ValueError, TypeError):
            self._send_error(handler, 400, "event data is not valid JSON")
            return
        if not isinstance(data, dict):
            self._send_error(handler, 400, "event data must be an object")
            return
        self._record_event(name, data)
        self._send_no_content(handler)

    def _handle_result(self, handler):
        query = parse_qs(urlsplit(handler.path).query, keep_blank_values=True)
        raw = (query.get("d") or [""])[0]
        if not raw or len(raw) > MAX_RESULT_DATA:
            self._send_error(handler, 400, "invalid or oversized result")
            return
        try:
            report = json.loads(raw)
        except (ValueError, TypeError):
            self._send_error(handler, 400, "result is not valid JSON")
            return
        if not isinstance(report, dict):
            self._send_error(handler, 400, "result must be an object")
            return
        if report.get("token") != self.token:
            self._send_error(handler, 400, "result token mismatch")
            return
        self._record_result(report)
        self._send_no_content(handler)

    def _send_bytes(self, handler, data, ctype, head_only):
        try:
            handler.send_response(200)
            handler.send_header("Content-Type", ctype)
            handler.send_header("Content-Length", str(len(data)))
            handler.send_header("Cache-Control", "no-store")
            handler.end_headers()
            if not head_only:
                handler.wfile.write(data)
                handler.wfile.flush()
            return True
        except OSError:
            return False

    def _send_no_content(self, handler):
        try:
            handler.send_response(204)
            handler.send_header("Content-Length", "0")
            handler.end_headers()
        except OSError:
            pass

    def _send_error(self, handler, code, message):
        try:
            handler.send_error(code, message)
        except OSError:
            pass

    def _peer_allowed(self, address):
        if self.expected_peer is None:
            return True
        return address == self.expected_peer

    # -- state -------------------------------------------------------------

    def _mark_served(self, name):
        with self._lock:
            self._served.add(name)

    def _record_event(self, name, data):
        with self._lock:
            if len(self._event_names) < 64:
                self._event_names.append(name)

            if name == "download":
                file_name = data.get("file")
                if data.get("ok") is True and file_name in PAYLOAD_FILE_SET:
                    self._downloads_ok.add(file_name)
                    # All three per-file confirmations are sufficient; the
                    # separate downloads-complete beacon is only a redundant
                    # confirmation and may be lost independently.
                    if self._downloads_ok == PAYLOAD_FILE_SET:
                        self._download_complete = True
                        self._download_event.set()
                elif data.get("ok") is not True:
                    if self._download_failure is None:
                        self._download_failure = "download of %r failed: %s" % (
                            file_name,
                            _bounded(data.get("detail") or data, 300),
                        )
                    self._download_event.set()
                return

            if name == "downloads-complete":
                # Delivery by the HTTP server alone is not a download
                # confirmation. Require the page's per-file Download Manager
                # completion reports so this flag cannot be set from served
                # bytes only.
                if self._downloads_ok == PAYLOAD_FILE_SET:
                    self._download_complete = True
                elif self._download_failure is None:
                    self._download_failure = (
                        "the page reported completed downloads, but not all "
                        "per-file download confirmations were received"
                    )
                self._download_event.set()
                return

            if name == "page-error":
                if self._page_error is None:
                    self._page_error = {
                        "stage": _bounded(data.get("stage"), 40) or "page-error",
                        "detail": _bounded(data.get("detail"), 400) or "",
                    }
                self._download_event.set()
                return

            if name == "run-request":
                self._run_requested = True
                self._run_request = {
                    "inputParams": _bounded(data.get("inputParams"), 500)
                }
                return

            if name == "run":
                message = data.get("message")
                parsed = None
                if isinstance(message, str):
                    try:
                        parsed = json.loads(message)
                    except (ValueError, TypeError):
                        parsed = None
                elif isinstance(message, dict):
                    parsed = message
                if not isinstance(parsed, dict):
                    parsed = {"_unparsable": _bounded(message, 500)}
                self._run_response = parsed
                self._run_event.set()
                return

            if name == "run-timeout":
                self._run_timeout = True
                self._run_event.set()
                return

    def _record_result(self, report):
        uid_block = report.get("uid") if isinstance(report.get("uid"), dict) else {}
        gid_block = report.get("gid") if isinstance(report.get("gid"), dict) else {}
        fingerprint = (
            report.get("kind"),
            report.get("token"),
            report.get("status"),
            _as_int(report.get("geteuid")),
            _as_int(report.get("getegid")),
            _as_int(uid_block.get("real")),
            _as_int(uid_block.get("effective")),
            _as_int(gid_block.get("real")),
            _as_int(gid_block.get("effective")),
        )
        with self._lock:
            if self._result is None:
                self._result = report
                self._result_fingerprint = fingerprint
                self._result_event.set()
            elif fingerprint != self._result_fingerprint:
                self._result_conflict = True

    def observation(self):
        with self._lock:
            return {
                "page_loaded": self._page_loaded,
                "page_served": self._page_served,
                "served_files": sorted(self._served),
                "downloads_ok": sorted(self._downloads_ok),
                "download_complete": self._download_complete,
                "download_failure": self._download_failure,
                "page_error": dict(self._page_error) if self._page_error else None,
                "run_requested": self._run_requested,
                "run_request": dict(self._run_request) if self._run_request else None,
                "run_result": dict(self._run_response) if self._run_response else None,
                "run_timeout": self._run_timeout,
                "payload_result": dict(self._result) if self._result else None,
                "result_conflict": self._result_conflict,
                "event_names": list(self._event_names),
            }

    def served_payload_files(self):
        with self._lock:
            return sorted(self._served & PAYLOAD_FILE_SET)

    def wait_for_download_phase(self, timeout):
        return self._download_event.wait(timeout)

    def wait_for_run_phase(self, timeout):
        return self._run_event.wait(timeout)

    def wait_for_result(self, timeout):
        return self._result_event.wait(timeout)


# ---------------------------------------------------------------------------
# Flow
# ---------------------------------------------------------------------------


class Dependencies(object):
    """Injectable webOS/network functions; tests replace these."""

    def __init__(self):
        self.guess_local_ip = slopbro.guess_local_ip
        self.resolve_ipv4 = resolve_ipv4
        self.ws_connect = slopbro.WebSocket.connect
        self.ssap_client = slopbro.SSAPClient
        self.load_client_key = slopbro.load_client_key
        self.launch_app = slopbro.launch_app
        self.server_factory = DiagnosticServer
        self.sleep = time.sleep


def _is_ipv4(value):
    try:
        socket.inet_aton(value)
    except (socket.error, TypeError):
        return False
    return value.count(".") == 3


def resolve_ipv4(host):
    try:
        return socket.gethostbyname(host)
    except (socket.error, TypeError) as exc:
        raise DiagnosticError("could not resolve TV address %r: %s" % (host, exc))


def _payload_failure(message, payload=None):
    log("error: " + message)
    return emit_outcome(
        Outcome(STATUS_SETUP_FAILED, message),
        payload=payload,
    )


def emit_outcome(outcome, payload=None, server=None, token=None, tv_ip=None,
                 local_ip=None):
    context = {
        "diagnostic": TOOL_VERSION,
        "tv_ip": tv_ip,
        "local_ip": local_ip,
        "payload": payload["files"] if payload else None,
        "token_fingerprint": (
            sha256(token.encode("ascii")).hexdigest()[:16] if token else None
        ),
    }
    if server is not None:
        observation = server.observation()
        context.update(
            {
                "served_files": observation["served_files"],
                "page_loaded": observation["page_loaded"],
                "download_complete": observation["download_complete"],
                "download_failure": observation["download_failure"],
                "page_error": observation["page_error"],
                "run_requested": observation["run_requested"],
                "service_response": (
                    _sanitize_report(observation["run_result"])
                    if observation["run_result"]
                    else None
                ),
                "event_names": observation["event_names"][-16:],
            }
        )

    summary = outcome.to_dict()
    summary["context"] = context

    log("status: %s" % outcome.status)
    log("detail: %s" % outcome.detail)
    if outcome.evidence:
        log("evidence: %s" % json.dumps(outcome.evidence, sort_keys=True))
    print("RESULT: " + json.dumps(summary, sort_keys=True))
    sys.stdout.flush()
    return outcome.exit_code


def _setup_failure(message, payload=None, server=None, token=None, tv_ip=None,
                   local_ip=None):
    log("setup failed: " + message)
    return emit_outcome(
        Outcome(STATUS_SETUP_FAILED, message),
        payload=payload,
        server=server,
        token=token,
        tv_ip=tv_ip,
        local_ip=local_ip,
    )


def run(args, deps=None):
    deps = deps or Dependencies()
    try:
        payload = validate_payload()
    except DiagnosticError as exc:
        return _payload_failure("payload validation failed: %s" % exc)

    local_ip = None
    server = None
    client = None
    token = new_token()

    try:
        try:
            local_ip = deps.guess_local_ip(args.tv_ip, args.local_ip)
            if not _is_ipv4(local_ip):
                raise DiagnosticError(
                    "could not determine an IPv4 LAN address for the computer; "
                    "use --local-ip"
                )
            if local_ip in ("0.0.0.0", "255.255.255.255"):
                raise DiagnosticError(
                    "refusing to bind the diagnostic server to %s; use --local-ip"
                    % local_ip
                )
            if local_ip.startswith("127.") and not args.local_ip:
                raise DiagnosticError(
                    "the automatically selected computer address is loopback (%s); "
                    "use --local-ip with the computer's LAN address" % local_ip
                )
            if local_ip.startswith("127."):
                log(
                    "warning: using an explicitly selected loopback address; "
                    "the TV will not reach it unless this is a local test"
                )
            tv_ipv4 = deps.resolve_ipv4(args.tv_ip)
        except Exception as exc:
            return _setup_failure(
                "address setup failed: %s" % exc,
                payload=payload,
                token=token,
                tv_ip=args.tv_ip,
            )

        try:
            server = deps.server_factory(
                payload_dir=payload["payload_dir"],
                token=token,
                expected_peer=tv_ipv4,
                bind_host=local_ip,
                preferred_port=args.port,
                payload=payload,
            )
            server.start()
        except Exception as exc:
            return _setup_failure(
                "could not start the diagnostic HTTP server: %s" % exc,
                payload=payload,
                server=server,
                token=token,
                tv_ip=args.tv_ip,
                local_ip=local_ip,
            )

        page_url = server.base_url + page_path(token)
        log("target TV: %s (%s), computer address: %s" % (args.tv_ip, tv_ipv4, local_ip))
        log("HTTP server bound to %s:%d (LAN-specific bind, token-gated)"
            % (local_ip, server.port))
        log("payload files: %s" % ", ".join(PAYLOAD_FILES))
        log("no installer, no shell, no service-permission change, no reboot, no retry")
        log(
            "warning: files from an earlier attempt may exist in %s; the diagnostic "
            "cannot inspect or back them up" % TV_DOWNLOAD_DIR
        )

        log("[action] Open Voice Assistant on the TV and keep its panel visible.")
        log("[action] Accept the TV pairing prompt if one appears.")

        try:
            ws = deps.ws_connect(
                args.tv_ip,
                slopbro.PORT_TLS,
                secure=True,
                source_address=(local_ip, 0),
            )
        except Exception as exc:
            return _setup_failure(
                "SSAP connection failed: %s" % exc,
                payload=payload,
                server=server,
                token=token,
                tv_ip=args.tv_ip,
                local_ip=local_ip,
            )

        client = deps.ssap_client(ws)
        try:
            stored_key = deps.load_client_key(args.tv_ip)
            if stored_key:
                log("using the existing SSAP client key (read-only)")
            else:
                log("no stored SSAP client key; pairing will be requested")
            new_key = client.register(stored_key, slopbro.DEFAULT_MANIFEST)
        except Exception as exc:
            return _setup_failure(
                "SSAP registration/pairing failed: %s" % exc,
                payload=payload,
                server=server,
                token=token,
                tv_ip=args.tv_ip,
                local_ip=local_ip,
            )

        if new_key and new_key != stored_key:
            log("pairing accepted; the new client key is NOT saved (non-persistent mode)")

        try:
            deps.launch_app(client, VOICEWEB_APP, {})
        except Exception as exc:
            log("warning: Voice Assistant activation failed (%s); trying the URL launch" % exc)
        deps.sleep(1.0)
        try:
            deps.launch_app(client, VOICEWEB_APP, {"URL": page_url})
            log("Voice Assistant launched with the diagnostic page")
        except Exception as exc:
            return _setup_failure(
                "Voice Assistant URL launch failed: %s" % exc,
                payload=payload,
                server=server,
                token=token,
                tv_ip=args.tv_ip,
                local_ip=local_ip,
            )

        try:
            client.close()
        except Exception:
            pass
        client = None

        log("waiting up to %gs for the three payload downloads"
            % args.download_timeout)
        if not server.wait_for_download_phase(args.download_timeout):
            observation = server.observation()
            observation["timed_out_phase"] = "download"
        else:
            observation = server.observation()
            if (
                observation["download_complete"]
                and not observation["download_failure"]
                and not observation["page_error"]
            ):
                log("all three payload downloads were confirmed")
                if not server.wait_for_run_phase(args.result_timeout):
                    observation = server.observation()
                    observation["timed_out_phase"] = "service"
                else:
                    observation = server.observation()
                run_result = observation.get("run_result")
                rejected = (
                    isinstance(run_result, dict)
                    and run_result.get("returnValue") is False
                )
                run_evidence = (
                    observation.get("run_requested") or run_result is not None
                )
                if run_evidence and not rejected:
                    log("waiting up to %gs for the privileged payload report"
                        % args.result_timeout)
                    got = server.wait_for_result(args.result_timeout)
                    if got:
                        # Allow near-simultaneous duplicate reports to arrive so
                        # a conflicting report cannot be missed by exiting
                        # immediately.
                        deps.sleep(1.0)
                    observation = server.observation()
                    if not got:
                        observation["timed_out_phase"] = "result"
            else:
                log("download phase ended before a usable payload was confirmed")

        outcome = classify_outcome(observation, token)
        return emit_outcome(
            outcome,
            payload=payload,
            server=server,
            token=token,
            tv_ip=args.tv_ip,
            local_ip=local_ip,
        )

    except KeyboardInterrupt:
        return emit_outcome(
            Outcome(STATUS_INDETERMINATE, "interrupted by the user; no retry was started"),
            payload=payload,
            server=server,
            token=token,
            tv_ip=args.tv_ip,
            local_ip=local_ip,
        )
    except Exception as exc:
        return _setup_failure(
            "unexpected error: %s" % exc,
            payload=payload,
            server=server,
            token=token,
            tv_ip=args.tv_ip,
            local_ip=local_ip,
        )
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        if server is not None:
            server.shutdown()


def run_dry(args):
    try:
        payload = validate_payload()
    except DiagnosticError as exc:
        log("payload validation failed: %s" % exc)
        return emit_outcome(Outcome(STATUS_SETUP_FAILED, "payload validation failed: %s" % exc))

    log("payload validation: ok")
    for name in [PAGE_NAME] + list(PAYLOAD_FILES):
        info = payload["files"][name]
        log("  %-14s %6d bytes  sha256=%s"
            % (name, info["size"], info["sha256"]))
    log("dry run only: no HTTP listener was started and the TV was not contacted")
    summary = {
        "status": "dry_run",
        "detail": "diagnostic payload validated; no listener, no TV contact",
        "exit_code": 0,
        "payload": payload["files"],
        "context": {"diagnostic": TOOL_VERSION},
    }
    print("RESULT: " + json.dumps(summary, sort_keys=True))
    sys.stdout.flush()
    return 0


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Minimal, non-persistent webOS 26 privilege diagnostic. It reuses "
            "the SlopBro jsserver trigger but installs nothing and changes no "
            "system configuration."
        )
    )
    parser.add_argument(
        "tv_ip",
        nargs="?",
        help="TV IPv4 address or hostname (optional only with --dry-run)",
    )
    parser.add_argument(
        "--local-ip",
        help="computer LAN IPv4 address; use only if automatic detection is wrong",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="preferred local HTTP port, 0 selects an ephemeral port (default: 8080)",
    )
    parser.add_argument(
        "--download-timeout",
        type=float,
        default=45.0,
        help="seconds to wait for the three download confirmations (default: 45)",
    )
    parser.add_argument(
        "--result-timeout",
        type=float,
        default=20.0,
        help="seconds to wait for the service response/privileged report (default: 20)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the local diagnostic payload only; start no listener and do not contact the TV",
    )
    args = parser.parse_args(argv)

    if not args.dry_run and not args.tv_ip:
        parser.error("tv_ip is required unless --dry-run is used")
    if args.port < 0 or args.port > 65535:
        parser.error("--port must be between 0 and 65535")
    if args.download_timeout <= 0:
        parser.error("--download-timeout must be greater than 0")
    if args.result_timeout <= 0:
        parser.error("--result-timeout must be greater than 0")
    if args.local_ip and not _is_ipv4(args.local_ip):
        parser.error("--local-ip must be an IPv4 address")
    return args


def main(argv=None, deps=None):
    args = parse_args(argv)
    if args.dry_run:
        return run_dry(args)
    return run(args, deps=deps)


if __name__ == "__main__":
    sys.exit(main())
