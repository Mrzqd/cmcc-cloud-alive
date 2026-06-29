#!/usr/bin/env node
'use strict';

const { spawn } = require('child_process');
const { cloudStatus, heartbeat, isHeartbeatAccepted } = require('../lib/family-api');

const OFFICIAL_PROCESS_PATTERN = 'bootCypc|uSmartView|chuanyun-vdi-client|yidongyun-keepalive|server/web-server';

function usage() {
  console.error('Usage: node scripts/verify-http-heartbeat.js <userServiceId> [--duration-ms 120000] [--interval-ms 30000] [--cag-host 111.31.3.182] [--cag-port 8899] [--tcpdump 1]');
  process.exit(2);
}

function parseArgs(argv) {
  const out = {
    _: [],
    durationMs: 120000,
    intervalMs: 30000,
    cagHost: '111.31.3.182',
    cagPort: '8899',
    tcpdump: '1',
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      out[key] = argv[++i];
    } else {
      out._.push(arg);
    }
  }
  out.durationMs = Math.max(5000, Number(out.durationMs || 0));
  out.intervalMs = Math.max(5000, Number(out.intervalMs || 0));
  return out;
}

function formatShanghai(date = new Date()) {
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(date);
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function runCapture(command, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (err) => {
      resolve({ ok: false, code: null, signal: null, stdout, stderr, error: err.message });
    });
    child.on('exit', (code, signal) => {
      resolve({ ok: code === 0, code, signal, stdout, stderr });
    });
    if (opts.timeoutMs) {
      setTimeout(() => {
        try { child.kill('SIGTERM'); } catch {}
      }, opts.timeoutMs);
    }
  });
}

async function pgrepOfficialProcesses() {
  const result = await runCapture('pgrep', ['-af', OFFICIAL_PROCESS_PATTERN]);
  return result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.includes('verify-http-heartbeat'));
}

async function ssCagConnections(cagHost, cagPort) {
  const result = await runCapture('ss', ['-tunp']);
  return result.stdout
    .split('\n')
    .filter((line) => line.includes(cagHost) && line.includes(`:${cagPort}`))
    .map((line) => line.trim());
}

function startTcpdump(cagHost, cagPort) {
  const filter = `host ${cagHost} and port ${cagPort}`;
  const child = spawn('tcpdump', ['-i', 'any', '-nn', '-l', '-tt', filter], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const lines = [];
  let stderr = '';
  let startError = null;
  child.stdout.on('data', (chunk) => {
    String(chunk).split('\n').forEach((line) => {
      if (line.trim()) lines.push(line.trim());
    });
  });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.on('error', (err) => { startError = err.message; });
  return {
    child,
    lines,
    get stderr() { return stderr; },
    get startError() { return startError; },
    stop() {
      return new Promise((resolve) => {
        child.once('exit', (code, signal) => resolve({ code, signal }));
        try { child.kill('SIGTERM'); } catch { resolve({ code: null, signal: null }); }
        setTimeout(() => {
          if (!child.killed) {
            try { child.kill('SIGKILL'); } catch {}
          }
        }, 2000);
      });
    },
  };
}

function summarizeError(err) {
  return {
    name: err?.name || 'Error',
    message: err?.message || String(err),
    kind: err?.kind,
    code: err?.code,
    businessCode: err?.businessCode,
    response: err?.response ? {
      code: err.response.code,
      msg: err.response.msg,
      businessCode: err.response.businessCode || '',
    } : undefined,
  };
}

function isPoweredState(status) {
  const text = String(status?.vmStatusShow || '');
  if (!status) return false;
  if (/关机|休眠|离线|回收|未开机/.test(text)) return false;
  return true;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const userServiceId = args._[0];
  if (!userServiceId) usage();

  const report = {
    startedAt: new Date().toISOString(),
    startedAtShanghai: formatShanghai(),
    userServiceId: String(userServiceId),
    durationMs: args.durationMs,
    intervalMs: args.intervalMs,
    cagHost: String(args.cagHost),
    cagPort: String(args.cagPort),
    officialProcessesBefore: [],
    officialProcessesAfter: [],
    cagConnectionsBefore: [],
    cagConnectionsAfter: [],
    tcpdump: {
      requested: String(args.tcpdump) !== '0',
      started: false,
      packetLines: [],
      stderr: '',
      error: '',
    },
    cloudStatusBefore: null,
    cloudStatusAfter: null,
    heartbeats: [],
    acceptedCount: 0,
    errorCount: 0,
    stoppedByOtherLogin: false,
  };

  report.officialProcessesBefore = await pgrepOfficialProcesses();
  report.cagConnectionsBefore = await ssCagConnections(report.cagHost, report.cagPort);
  try {
    report.cloudStatusBefore = await cloudStatus(userServiceId);
  } catch (err) {
    report.cloudStatusBeforeError = summarizeError(err);
  }

  let tcpdump = null;
  if (report.tcpdump.requested) {
    tcpdump = startTcpdump(report.cagHost, report.cagPort);
    report.tcpdump.started = true;
    await wait(1000);
    if (tcpdump.startError) {
      report.tcpdump.started = false;
      report.tcpdump.error = tcpdump.startError;
    }
  }

  const deadline = Date.now() + args.durationMs;
  let index = 0;
  while (Date.now() < deadline) {
    index++;
    const startedAt = new Date();
    try {
      const response = await heartbeat(userServiceId);
      const accepted = Boolean(isHeartbeatAccepted(response));
      if (accepted) report.acceptedCount++;
      report.heartbeats.push({
        index,
        at: startedAt.toISOString(),
        atShanghai: formatShanghai(startedAt),
        accepted,
        code: response.code,
        msg: response.msg || '',
        businessCode: response.businessCode || '',
      });
      try {
        report.heartbeats[report.heartbeats.length - 1].cloudStatus = await cloudStatus(userServiceId);
      } catch (err) {
        report.heartbeats[report.heartbeats.length - 1].cloudStatusError = summarizeError(err);
      }
    } catch (err) {
      report.errorCount++;
      const summary = summarizeError(err);
      report.heartbeats.push({
        index,
        at: startedAt.toISOString(),
        atShanghai: formatShanghai(startedAt),
        error: summary,
      });
      if (Number(summary.code) === 4043 || Number(summary.businessCode) === 4043) {
        report.stoppedByOtherLogin = true;
        break;
      }
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await wait(Math.min(args.intervalMs, remaining));
  }

  if (tcpdump) {
    await tcpdump.stop();
    report.tcpdump.packetLines = tcpdump.lines;
    report.tcpdump.stderr = tcpdump.stderr.trim();
    report.tcpdump.error = report.tcpdump.error || tcpdump.startError || '';
  }

  report.officialProcessesAfter = await pgrepOfficialProcesses();
  report.cagConnectionsAfter = await ssCagConnections(report.cagHost, report.cagPort);
  try {
    report.cloudStatusAfter = await cloudStatus(userServiceId);
  } catch (err) {
    report.cloudStatusAfterError = summarizeError(err);
  }
  report.finishedAt = new Date().toISOString();
  report.finishedAtShanghai = formatShanghai();
  report.noOfficialClientStarted = report.officialProcessesBefore.length === 0 && report.officialProcessesAfter.length === 0;
  report.noCagConnectionObserved = report.cagConnectionsBefore.length === 0 &&
    report.cagConnectionsAfter.length === 0 &&
    report.tcpdump.packetLines.length === 0;
  report.httpPathOk = report.acceptedCount > 0 &&
    !report.stoppedByOtherLogin &&
    report.noOfficialClientStarted &&
    report.noCagConnectionObserved;
  const statusSnapshots = [
    report.cloudStatusBefore,
    ...report.heartbeats.map((item) => item.cloudStatus).filter(Boolean),
    report.cloudStatusAfter,
  ].filter(Boolean);
  report.poweredStatusSnapshots = statusSnapshots.filter(isPoweredState).length;
  report.sleepPreventionProof = report.httpPathOk &&
    statusSnapshots.length > 0 &&
    report.poweredStatusSnapshots === statusSnapshots.length &&
    report.durationMs >= 30 * 60 * 1000;
  report.ok = report.httpPathOk;

  console.log(JSON.stringify(report, null, 2));
  process.exit(report.ok ? 0 : 1);
}

main().catch((err) => {
  console.error(err.stack || err.message || String(err));
  process.exit(1);
});
