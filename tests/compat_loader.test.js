const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const loaderPath = path.join(
  __dirname, '..', 'wwwroot', 'run-webos26-compatible.html'
);

function runLoader(options) {
  const html = fs.readFileSync(loaderPath, 'utf8');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const timers = [];
  const calls = [];
  const beacons = [];
  const status = { textContent: '' };
  let nextTimerId = 1;

  function fakeSetTimeout(fn) {
    const timer = { id: nextTimerId++, fn, cancelled: false };
    timers.push(timer);
    return timer.id;
  }

  function fakeClearTimeout(id) {
    const timer = timers.find(item => item.id === id);
    if (timer) timer.cancelled = true;
  }

  function runNextTimer() {
    for (let i = 0; i < timers.length; i++) {
      const timer = timers[i];
      if (!timer.cancelled) {
        timer.cancelled = true;
        timers.splice(i, 1);
        timer.fn();
        return true;
      }
    }
    return false;
  }

  function runTimers(limit) {
    for (let i = 0; i < (limit || 50); i++) {
      if (!runNextTimer()) return;
    }
  }

  function PalmServiceBridge() {
    this.call = (uri, payload) => {
      const call = { uri, payload: JSON.parse(payload) };
      calls.push(call);
      if (uri.endsWith('/cancelAllDownloads')) {
        if (options.cancelReply !== null) {
          this.onservicecallback(options.cancelReply ||
            '{"returnValue":true}');
        }
      } else if (uri.endsWith('/download')) {
        if (options.downloadReply !== null) {
          this.onservicecallback(
            typeof options.downloadReply === 'function'
              ? options.downloadReply(call)
              : (options.downloadReply ||
                '{"completed":true,"aborted":false,"interrupted":false,"httpStatus":200}')
          );
        }
      } else if (uri.endsWith('/run')) {
        if (options.runReply !== null) {
          this.onservicecallback(options.runReply ||
            '{"returnValue":true}');
        }
      }
    };
    this.cancel = () => {};
  }

  const context = {
    location: {
      href: 'http://192.0.2.10:8080/run-webos26-compatible.html',
      protocol: 'http:',
      host: '192.0.2.10:8080',
    },
    document: { getElementById: () => status },
    PalmServiceBridge,
    Image: function Image() {
      Object.defineProperty(this, 'src', { set: url => beacons.push(url) });
    },
    Date,
    setTimeout: fakeSetTimeout,
    clearTimeout: fakeClearTimeout,
  };

  vm.runInNewContext(script, context, { filename: loaderPath });
  runTimers(options.timerLimit);

  return {
    calls,
    beacons,
    status,
    downloads: calls.filter(call => call.uri.endsWith('/download')),
    runCalls: calls.filter(call => call.uri.endsWith('jsserver/run')),
  };
}

function assertFailedWithoutRun(result, pattern) {
  assert.equal(result.runCalls.length, 0, 'jsserver/run must not be called');
  assert.match(result.status.textContent, /Failed:/);
  if (pattern) {
    assert.ok(
      result.beacons.some(url => url.includes(pattern)),
      'expected failure beacon matching ' + pattern
    );
  }
}

// webOS 26 has been observed to omit httpStatus on successful completions.
// The diagnostic run accepted that shape; only a numeric non-2xx status fails.
const missingStatus = runLoader({
  downloadReply: '{"completed":true,"aborted":false,"interrupted":false}',
});
assert.equal(missingStatus.downloads.length, 4);
assert.equal(missingStatus.runCalls.length, 1);

// A non-completed response is always a failure, with or without httpStatus.
assertFailedWithoutRun(runLoader({
  downloadReply: '{"completed":false,"aborted":false,"interrupted":false}',
}), 'ERROR%20download');

// An HTTP error must stop the sequence before jsserver/run.
assertFailedWithoutRun(runLoader({
  downloadReply:
    '{"completed":true,"aborted":false,"interrupted":false,"httpStatus":404}',
}), 'ERROR%20download');

// A rejected download request must stop the sequence.
assertFailedWithoutRun(runLoader({
  downloadReply: '{"returnValue":false,"error":"download rejected"}',
}), 'ERROR%20download-rejected');

// Downloads must not start without an explicit cancel acknowledgement.
assertFailedWithoutRun(runLoader({
  cancelReply: '{"returnValue":false,"error":"cancel rejected"}',
}), 'ERROR%20cancel-rejected');

// A cancel that never answers must fail closed, not start downloads.
assertFailedWithoutRun(runLoader({
  cancelReply: null,
}), 'ERROR%20cancel-timeout');

// A download that never answers must fail closed and not continue.
assertFailedWithoutRun(runLoader({
  downloadReply: null,
}), 'ERROR%20download-timeout');

// Happy path: four files, one jsserver/run, and the trusted-path workaround.
const happy = runLoader({});
assert.equal(happy.downloads.length, 4);
assert.equal(happy.runCalls.length, 1);
assert.match(
  happy.runCalls[0].payload.inputParams,
  /a b c \/usr\/palm\/services\/com\.palm\.service\.devmode -- \/tmp\/cgroup dummy \/media\/internal\/downloads/
);
assert.ok(happy.beacons.some(url => url.includes('compat-run-result')));

// A run response that is not a boolean must not be forwarded as a success.
const invalidRun = runLoader({
  runReply: '{"returnValue":"yes"}',
});
assert.equal(invalidRun.runCalls.length, 1);
assert.ok(
  invalidRun.beacons.some(url => url.includes('ERROR%20invalid-service-response'))
);

console.log('compatible loader hardening tests passed');
