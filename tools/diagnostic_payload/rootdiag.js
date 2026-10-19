/* webOS 26 non-persistent privilege diagnostic payload.
 *
 * Loaded by the jsserver package as its main module. It reads the kernel's
 * view of this process from /proc/self/status, cross-checks
 * process.geteuid()/getegid() where available, and reports the values to the
 * computer over HTTP. It does not write files, start processes, load
 * third-party modules, or change configuration.
 */
var fs = require("fs");
var http = require("http");

var TOKEN = "__DIAG_TOKEN__";
var REPORT_URL = "__DIAG_REPORT_URL__";

var attempts = 0;

function asNonNegativeInt(value) {
    if (typeof value !== "number" || !isFinite(value) || value < 0) {
        return null;
    }
    if (Math.floor(value) !== value) {
        return null;
    }
    return value;
}

function processCall(name) {
    try {
        if (typeof process[name] === "function") {
            return asNonNegativeInt(process[name]());
        }
    } catch (error) {
        // Fall through to the /proc value, or report the field as missing.
    }
    return null;
}

function parseIdLine(text, key) {
    if (typeof text !== "string" || !text) {
        return null;
    }
    var pattern = new RegExp("^" + key + ":\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)", "m");
    var match = pattern.exec(text);
    if (!match) {
        return null;
    }
    return {
        real: parseInt(match[1], 10),
        effective: parseInt(match[2], 10),
        saved: parseInt(match[3], 10),
        filesystem: parseInt(match[4], 10),
        line: match[0]
    };
}

function boundedString(value, limit) {
    if (value === null || typeof value === "undefined") {
        return null;
    }
    var text;
    try {
        text = String(value);
    } catch (error) {
        return null;
    }
    if (text.length > limit) {
        text = text.substring(0, limit);
    }
    return text;
}

function snapshot() {
    var statusText = "";
    var statusError = null;
    try {
        statusText = fs.readFileSync("/proc/self/status", "utf8");
    } catch (error) {
        statusError = boundedString(error && error.message ? error.message : error, 200);
    }

    var uid = parseIdLine(statusText, "Uid");
    var gid = parseIdLine(statusText, "Gid");
    var getuid = processCall("getuid");
    var geteuid = processCall("geteuid");
    var getgid = processCall("getgid");
    var getegid = processCall("getegid");

    var argv = [];
    try {
        argv = process.argv.slice(0, 8).map(function (item) {
            return boundedString(item, 120);
        });
    } catch (error) {
        argv = [];
    }

    return {
        kind: "rootdiag-result",
        token: TOKEN,
        status: "ok",
        pid: asNonNegativeInt(process.pid),
        ppid: asNonNegativeInt(process.ppid),
        node: boundedString(process.version, 40),
        platform: boundedString(process.platform, 40),
        uid: uid,
        gid: gid,
        getuid: getuid,
        geteuid: geteuid,
        getgid: getgid,
        getegid: getegid,
        real_uid: uid ? uid.real : getuid,
        effective_uid: uid ? uid.effective : geteuid,
        saved_uid: uid ? uid.saved : null,
        filesystem_uid: uid ? uid.filesystem : null,
        real_gid: gid ? gid.real : getgid,
        effective_gid: gid ? gid.effective : getegid,
        saved_gid: gid ? gid.saved : null,
        filesystem_gid: gid ? gid.filesystem : null,
        proc_status_error: statusError,
        argv: argv
    };
}

function sendReport(report) {
    // At most two sends: once when the module is loaded and once if the
    // service later calls the exported run() hook. Duplicates are ignored by
    // the computer; this is not an exploit retry.
    if (attempts >= 2) {
        return;
    }
    attempts += 1;

    var body;
    try {
        body = encodeURIComponent(JSON.stringify(report));
    } catch (error) {
        return;
    }

    var url = REPORT_URL + (REPORT_URL.indexOf("?") >= 0 ? "&" : "?") + "d=" + body;
    try {
        var request = http.get(url, function (response) {
            response.resume();
        });
        request.setTimeout(5000, function () {
            try { request.destroy(); } catch (error) {}
        });
        request.on("error", function () {
            // A lost report is classified as indeterminate by the computer;
            // nothing is written to the device as a fallback.
        });
    } catch (error) {
        // Nothing else to do without turning the diagnostic into a writer.
    }
}

var report;
try {
    report = snapshot();
} catch (error) {
    report = {
        kind: "rootdiag-result",
        token: TOKEN,
        status: "error",
        stage: "snapshot",
        error: boundedString(error && error.message ? error.message : error, 300)
    };
}
sendReport(report);

module.exports = {
    run: function () {
        sendReport(report);
    }
};
