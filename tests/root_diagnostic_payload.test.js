// Local tests for the webOS 26 root diagnostic page and payload.
// No TV, no network: both scripts run in a Node VM with fake bridges and fs/http.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const payloadDir = path.join(__dirname, '..', 'tools', 'diagnostic_payload');
const token = '0123456789abcdef0123456789abcdef';
const pcBase = 'http://192.0.2.10:8080';

function read(name) {
  return fs.readFileSync(path.join(payloadDir, name), 'utf8');
}

function makeClock() {
  let nextId = 1;
  const timers = [];
  return {
    setTimeout(fn, ms) {
      const timer = { id: nextId++, fn, ms, cancelled: false };
      timers.push(timer);
      return timer.id;
    },
    clearTimeout(id) {
      const timer = timers.find(item => item.id === id);
      if (timer) timer.cancelled = true;
    },
    run(ms) {
      const timer = timers.find(item => !item.cancelled && item.ms === ms);
      if (!timer) return false;
      timer.cancelled = true;
      timer.fn();
      return true;
    },
    pending() {
      return timers.filter(item => !item.cancelled).map(item => item.ms);
    },
  };
}

function pageContext(options = {}) {
  const clock = makeClock();
  const calls = [];
  const bridges = [];
  const beacons = [];
  const elements = {
    status: { textContent: '' },
    detail: { textContent: '' },
  };

  function Bridge() {
    this.onservicecallback = null;
    this.cancel = () => {};
    this.call = (uri, payload) => {
      calls.push({ uri, payload });
      if (uri.endsWith('/cancelAllDownloads') && this.onservicecallback &&
          !options.noCancelCallback) {
        this.onservicecallback(options.cancelResponse || '{"returnValue":true}');
      }
      // Download and run callbacks are driven explicitly by each test.
    };
    bridges.push(this);
  }

  const context = {
    location: {
      protocol: 'http:',
      host: '192.0.2.10:8080',
      pathname: options.pathname || `/p/${token}/rootdiag.html`,
    },
    document: {
      getElementById: name => elements[name] || { textContent: '' },
    },
    Image: function Image() {
      Object.defineProperty(this, 'src', {
        set: value => beacons.push(value),
      });
    },
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
    Date,
    JSON,
  };
  if (!options.noBridge) {
    context.webOSServiceBridge = Bridge;
  }

  const html = read('rootdiag.html');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  vm.runInNewContext(script, context, { filename: 'rootdiag.html' });

  return {
    clock,
    calls,
    bridges,
    beacons,
    elements,
    lastBridge: () => bridges[bridges.length - 1],
    downloads: () => calls.filter(call => call.uri.endsWith('/download')),
    runCalls: () => calls.filter(call => call.uri.endsWith('jsserver/run')),
    events: () => beacons.map(parseBeacon),
  };
}

function parseBeacon(src) {
  const url = new URL(src);
  const parts = url.pathname.split('/').filter(Boolean);
  return {
    kind: parts[0],
    token: parts[1],
    name: parts[2],
    event: url.searchParams.get('event'),
    data: JSON.parse(url.searchParams.get('data') || '{}'),
  };
}

function completeDownload(page, index) {
  const calls = page.downloads();
  assert.ok(calls[index], `download ${index} was not requested`);
  page.lastBridge().onservicecallback(JSON.stringify({
    completed: true,
    aborted: false,
    interrupted: false,
    httpStatus: 200,
  }));
}

function completeAllDownloads(page) {
  for (let index = 0; index < 3; index++) {
    completeDownload(page, index);
    assert.equal(page.clock.run(700), true, `no continuation after download ${index}`);
  }
  assert.equal(page.clock.run(700), true, 'run was not scheduled after downloads');
}

function testHappyPath() {
  const page = pageContext();
  assert.equal(page.clock.run(800), true, 'download start was not scheduled');
  completeAllDownloads(page);

  const downloads = page.downloads().map(call => JSON.parse(call.payload));
  assert.equal(downloads.length, 3);
  assert.deepEqual(
    downloads.map(item => item.targetFilename),
    ['package.json', 'services.json', 'rootdiag.js'],
  );
  for (const item of downloads) {
    assert.equal(item.targetDir, '/media/internal/downloads');
    assert.equal(item.subscribe, true);
    assert.ok(item.target.startsWith(`${pcBase}/p/${token}/`));
    assert.ok(!item.target.includes('autoroot'));
    assert.ok(!item.target.includes('hbchannel'));
    assert.ok(!item.target.includes('main.js'));
    assert.ok(!item.target.includes('elevate'));
  }

  const runs = page.runCalls();
  assert.equal(runs.length, 1);
  assert.equal(
    JSON.parse(runs[0].payload).inputParams,
    'a b c /usr/palm/services/com.palm.service.devmode -- /tmp/cgroup dummy ' +
      '/media/internal/downloads',
  );

  page.lastBridge().onservicecallback('{"returnValue":true}');

  const eventNames = page.events().map(event => event.event);
  assert.ok(eventNames.includes('cancel'));
  assert.equal(eventNames.filter(name => name === 'download').length, 3);
  assert.ok(!eventNames.includes('downloads-complete'));
  assert.ok(eventNames.includes('run-request'));
  assert.ok(eventNames.includes('run'));

  const runEvent = page.events().find(event => event.event === 'run');
  assert.equal(JSON.parse(runEvent.data.message).returnValue, true);

  assert.equal(page.runCalls().length, 1, 'run must not be repeated');
}

function testDownloadRejectionStopsBeforeRun() {
  const page = pageContext();
  page.clock.run(800);
  page.lastBridge().onservicecallback(JSON.stringify({
    returnValue: false,
    errorText: 'path not in trusted locations',
  }));

  assert.equal(page.runCalls().length, 0);
  const error = page.events().find(event => event.event === 'page-error');
  assert.ok(error);
  assert.equal(error.data.stage, 'download-rejected');
  assert.ok(error.data.detail.includes('trusted locations'));
}

function testHttpStatusFailureStopsBeforeRun() {
  const page = pageContext();
  page.clock.run(800);
  page.lastBridge().onservicecallback(JSON.stringify({
    completed: true,
    aborted: false,
    interrupted: false,
    httpStatus: 404,
  }));

  assert.equal(page.runCalls().length, 0);
  const error = page.events().find(event => event.event === 'page-error');
  assert.ok(error);
  assert.equal(error.data.stage, 'download');
}

function testDownloadTimeoutStopsBeforeRun() {
  const page = pageContext();
  page.clock.run(800);
  assert.equal(page.clock.run(12000), true, 'download watchdog was not scheduled');
  assert.equal(page.runCalls().length, 0);
  const error = page.events().find(event => event.event === 'page-error');
  assert.ok(error);
  assert.equal(error.data.stage, 'download-timeout');
}

function testCancelTimeoutStopsBeforeDownloads() {
  const page = pageContext({ noCancelCallback: true });
  assert.equal(page.downloads().length, 0);
  assert.equal(page.clock.run(2500), true, 'cancel watchdog was not scheduled');
  assert.equal(page.downloads().length, 0);
  const error = page.events().find(event => event.event === 'page-error');
  assert.ok(error);
  assert.equal(error.data.stage, 'cancel-timeout');
}

function testCancelRejectionStopsBeforeDownloads() {
  const page = pageContext({
    cancelResponse: '{"returnValue":false,"errorText":"denied"}',
  });
  assert.equal(page.downloads().length, 0);
  const error = page.events().find(event => event.event === 'page-error');
  assert.ok(error);
  assert.equal(error.data.stage, 'cancel-rejected');
}

function testCancelUnparsableResponseStopsBeforeDownloads() {
  const page = pageContext({ cancelResponse: 'not-json' });
  assert.equal(page.downloads().length, 0);
  const error = page.events().find(event => event.event === 'page-error');
  assert.ok(error);
  assert.equal(error.data.stage, 'cancel-response');
}

function testServiceRejectionIsReported() {
  const page = pageContext();
  page.clock.run(800);
  completeAllDownloads(page);
  page.lastBridge().onservicecallback(JSON.stringify({
    returnValue: false,
    errorText: 'Denied method call',
  }));

  const runEvent = page.events().find(event => event.event === 'run');
  assert.ok(runEvent);
  assert.equal(JSON.parse(runEvent.data.message).returnValue, false);
  assert.equal(page.runCalls().length, 1);
}

function testRunTimeoutIsReported() {
  const page = pageContext();
  page.clock.run(800);
  completeAllDownloads(page);
  assert.equal(page.clock.run(10000), true, 'run watchdog was not scheduled');
  const timeout = page.events().find(event => event.event === 'run-timeout');
  assert.ok(timeout);
}

function testMissingBridgeIsReportedWithoutDownloads() {
  const page = pageContext({ noBridge: true });
  assert.equal(page.downloads().length, 0);
  assert.equal(page.runCalls().length, 0);
  const error = page.events().find(event => event.event === 'page-error');
  assert.ok(error);
  assert.equal(error.data.stage, 'bridge');
}

function testInvalidTokenIsRejectedWithoutBridgeCalls() {
  const page = pageContext({ pathname: '/p/not-a-token/rootdiag.html' });
  assert.equal(page.downloads().length, 0);
  assert.equal(page.runCalls().length, 0);
  const error = page.events().find(event => event.event === 'page-error');
  assert.ok(error);
  assert.equal(error.data.stage, 'token');
}

function loadPayload(options = {}) {
  const template = read('rootdiag.js');
  const script = template
    .replace('__DIAG_TOKEN__', token)
    .replace('__DIAG_REPORT_URL__', `${pcBase}/r/${token}/result`);

  const httpCalls = [];
  const fsCalls = [];
  const writeCalls = [];
  const fakeFs = {
    readFileSync(file, encoding) {
      fsCalls.push({ file, encoding });
      if (options.readError) throw new Error('synthetic read error');
      return [
        'Name:\tnode',
        'Uid:\t' + options.euid + '\t' + options.euid + '\t' + options.euid + '\t' + options.euid,
        'Gid:\t' + options.egid + '\t' + options.egid + '\t' + options.egid + '\t' + options.egid,
        '',
      ].join('\n');
    },
    writeFileSync() { writeCalls.push('writeFileSync'); },
    appendFileSync() { writeCalls.push('appendFileSync'); },
    unlinkSync() { writeCalls.push('unlinkSync'); },
  };
  const fakeHttp = {
    get(url, callback) {
      httpCalls.push(url);
      if (callback) callback({ resume() {} });
      return {
        setTimeout() {},
        on() {},
        destroy() {},
      };
    },
  };
  const fakeProcess = {
    pid: 4242,
    ppid: 1,
    version: 'v16.0.0',
    platform: 'linux',
    argv: ['node', '/media/internal/downloads/rootdiag.js'],
    getuid: () => options.euid,
    geteuid: () => options.euid,
    getgid: () => options.egid,
    getegid: () => options.egid,
  };
  const module = { exports: {} };
  const context = {
    require(name) {
      if (name === 'fs') return fakeFs;
      if (name === 'http') return fakeHttp;
      throw new Error('unexpected require: ' + name);
    },
    process: fakeProcess,
    module,
    exports: module.exports,
    JSON,
    Math,
    RegExp,
    String,
    isFinite,
    parseInt,
    encodeURIComponent,
  };
  vm.runInNewContext(script, context, { filename: 'rootdiag.js' });

  return { module, httpCalls, fsCalls, writeCalls };
}

function reportFromUrl(url) {
  const parsed = new URL(url);
  const raw = parsed.searchParams.get('d');
  assert.ok(raw, 'report URL has no d parameter');
  return JSON.parse(raw);
}

function testPayloadReportsEuidZero() {
  const result = loadPayload({ euid: 0, egid: 0 });
  assert.equal(result.httpCalls.length, 1);
  assert.ok(result.httpCalls[0].startsWith(`${pcBase}/r/${token}/result?`));
  assert.deepEqual(result.fsCalls.map(item => item.file), ['/proc/self/status']);
  assert.deepEqual(result.writeCalls, []);

  const report = reportFromUrl(result.httpCalls[0]);
  assert.equal(report.kind, 'rootdiag-result');
  assert.equal(report.token, token);
  assert.equal(report.status, 'ok');
  assert.equal(report.uid.effective, 0);
  assert.equal(report.gid.effective, 0);
  assert.equal(report.geteuid, 0);
  assert.equal(report.getegid, 0);
  assert.equal(report.real_uid, 0);
  assert.equal(report.effective_uid, 0);
  assert.equal(report.pid, 4242);
  assert.deepEqual(report.argv, ['node', '/media/internal/downloads/rootdiag.js']);

  assert.equal(typeof result.module.exports.run, 'function');
  result.module.exports.run();
  assert.equal(result.httpCalls.length, 2);
  result.module.exports.run();
  assert.equal(result.httpCalls.length, 2, 'report must be attempted at most twice');
}

function testPayloadReportsUnelevated() {
  const result = loadPayload({ euid: 1000, egid: 1000 });
  const report = reportFromUrl(result.httpCalls[0]);
  assert.equal(report.uid.effective, 1000);
  assert.equal(report.gid.effective, 1000);
  assert.equal(report.geteuid, 1000);
  assert.equal(report.getegid, 1000);
}

function testPayloadFallsBackToProcessCallsWhenProcFails() {
  const result = loadPayload({ euid: 1000, egid: 1000, readError: true });
  const report = reportFromUrl(result.httpCalls[0]);
  assert.equal(report.uid, null);
  assert.equal(report.gid, null);
  assert.equal(report.geteuid, 1000);
  assert.equal(report.getegid, 1000);
  assert.equal(report.effective_uid, 1000);
  assert.ok(report.proc_status_error.includes('synthetic read error'));
}

testHappyPath();
testDownloadRejectionStopsBeforeRun();
testHttpStatusFailureStopsBeforeRun();
testDownloadTimeoutStopsBeforeRun();
testCancelTimeoutStopsBeforeDownloads();
testCancelRejectionStopsBeforeDownloads();
testCancelUnparsableResponseStopsBeforeDownloads();
testServiceRejectionIsReported();
testRunTimeoutIsReported();
testMissingBridgeIsReportedWithoutDownloads();
testInvalidTokenIsRejectedWithoutBridgeCalls();
testPayloadReportsEuidZero();
testPayloadReportsUnelevated();
testPayloadFallsBackToProcessCallsWhenProcFails();

console.log('diagnostic page and payload tests passed');
