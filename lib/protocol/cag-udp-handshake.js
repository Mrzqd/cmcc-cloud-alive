'use strict';

const dgram = require('dgram');
const crypto = require('crypto');
const {
  createConnectInfoDatagram,
  createLocalKeyDatagram,
} = require('./cag-handshake-plan');
const {
  parseZteCagDatagram,
  encodeZteCagUdpControlDatagram,
} = require('./zte-cag');

function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function hex32(value) {
  return `0x${(Number(value) >>> 0).toString(16).padStart(8, '0')}`;
}

function redactHandshakeEvent(event) {
  if (!event) return event;
  const out = { ...event };
  delete out.rawHex;
  return out;
}

function summarizeControlMessage(buffer, remote = {}) {
  const parsed = parseZteCagDatagram(buffer);
  const control = parsed.udpControl;
  const base = {
    remoteAddress: remote.address || '',
    remotePort: remote.port || 0,
    length: buffer.length,
    sha256: sha256Hex(buffer),
    hasUdpControl: Boolean(control),
  };
  if (!control) return base;
  base.type = control.header.type;
  base.typeName = control.header.typeName;
  base.sequence = control.header.sequence;
  base.routeIdHex = control.header.routeId.toString('hex');
  base.tunnelIdHex = hex32(control.header.tunnelId);
  base.controlWord = control.header.controlWord;
  base.payloadLength = control.payload.length;
  if (control.ztecServerKeyInfo) {
    base.serverKeyHex = hex32(control.ztecServerKeyInfo.key);
    base.serverKeyFlagsHex = hex32(control.ztecServerKeyInfo.flags);
    base.sdkAesFlagsHex = hex32(control.ztecServerKeyInfo.sdkAesFlags);
  }
  if (control.connectReply) {
    base.connectReply = {
      ok: control.connectReply.ok,
      code: control.connectReply.code,
      payloadHex: control.connectReply.raw.toString('hex'),
    };
  }
  return base;
}

function sendUdp(socket, datagram, port, host) {
  return new Promise((resolve, reject) => {
    socket.send(datagram, port, host, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function waitForControl(socket, predicate, timeoutMs) {
  return new Promise((resolve, reject) => {
    const seen = [];
    const timer = setTimeout(() => {
      cleanup();
      const types = seen.map((event) => event.typeName || event.type || 'unknown').join(', ');
      const err = new Error(`timed out waiting for CAG control response after ${timeoutMs}ms${types ? `; seen: ${types}` : ''}`);
      err.seen = seen;
      reject(err);
    }, timeoutMs);

    function cleanup() {
      clearTimeout(timer);
      socket.off('message', onMessage);
      socket.off('error', onError);
    }

    function onError(err) {
      cleanup();
      reject(err);
    }

    function onMessage(message, remote) {
      let event;
      try {
        event = summarizeControlMessage(message, remote);
      } catch (err) {
        event = {
          remoteAddress: remote.address,
          remotePort: remote.port,
          length: message.length,
          sha256: sha256Hex(message),
          parseError: err.message,
        };
      }
      seen.push(event);
      if (predicate(event)) {
        cleanup();
        resolve({ event, seen });
      }
    }

    socket.on('message', onMessage);
    socket.once('error', onError);
  });
}

async function runCagUdpHandshake(auth = {}, opts = {}) {
  const host = opts.host || auth.cagIp;
  const port = Number(opts.port || auth.cagPort || 0);
  if (!host) throw new Error('CAG host is required');
  if (!Number.isInteger(port) || port <= 0) throw new Error('CAG port is required');

  const timeoutMs = Number(opts.timeoutMs || 5000);
  const sendConnectInfo = opts.sendConnectInfo === true || String(opts.sendConnectInfo || '0') === '1';
  const sendReady = opts.sendReady === true || String(opts.sendReady || '0') === '1';
  const socket = dgram.createSocket('udp4');
  const localKey = createLocalKeyDatagram({
    randomKey: opts.randomKey,
    clientKey: opts.clientKey,
    baseFlags: opts.baseFlags,
    transportFlag: opts.transportFlag,
    addressFamilyFlag: opts.addressFamilyFlag,
    sequence: opts.localKeySequence === undefined ? 3 : opts.localKeySequence,
    traceId: opts.traceId,
    spanId: opts.spanId,
  });

  const report = {
    route: {
      source: 'cag',
      host,
      port,
    },
    safe: {
      sdkStarted: false,
      desktopConnectSent: false,
      spiceAuthSent: false,
      sendsConnectInfo: sendConnectInfo,
      sendsReady: sendReady,
    },
    localKey: {
      randomKeyHex: hex32(localKey.randomKey),
      clientKeyLength: localKey.clientKey.length,
      routeIdHex: localKey.routeId.toString('hex'),
      datagram: {
        length: localKey.datagram.length,
        sha256: sha256Hex(localKey.datagram),
      },
      sequence: localKey.parsed.udpControl.header.sequence,
      traceId: localKey.parsed.ztecOpentelemetryKeyInfo?.traceId || '',
      spanId: localKey.parsed.ztecOpentelemetryKeyInfo?.spanId || '',
    },
    serverKey: null,
    connectInfo: null,
    connectReply: null,
    peerReady: null,
    readyConfirm: null,
    observed: [],
  };

  try {
    await new Promise((resolve) => socket.bind(0, resolve));
    const address = socket.address();
    report.localUdp = {
      address: address.address,
      port: address.port,
    };

    const serverKeyWait = waitForControl(socket, (event) => (
      event.type === 0x07 &&
      event.routeIdHex === report.localKey.routeIdHex &&
      event.serverKeyHex
    ), timeoutMs);
    await sendUdp(socket, localKey.datagram, port, host);
    const serverKeyResult = await serverKeyWait;
    report.observed.push(...serverKeyResult.seen.map(redactHandshakeEvent));
    report.serverKey = redactHandshakeEvent(serverKeyResult.event);

    if (!sendConnectInfo) return report;

    const serverKey = Number.parseInt(report.serverKey.serverKeyHex.replace(/^0x/i, ''), 16) >>> 0;
    const tunnelId = Number.parseInt(report.serverKey.tunnelIdHex.replace(/^0x/i, ''), 16) >>> 0;
    const connectInfo = createConnectInfoDatagram(auth, {
      randomKey: localKey.randomKey,
      serverKey,
      tunnelId,
      sequence: opts.connectInfoSequence === undefined ? 40 : opts.connectInfoSequence,
      controlWord: opts.connectInfoControlWord === undefined ? 0 : opts.connectInfoControlWord,
      aesFlags: opts.aesFlags === undefined ? 1 : opts.aesFlags,
    });
    report.connectInfo = {
      datagram: {
        length: connectInfo.datagram.length,
        sha256: sha256Hex(connectInfo.datagram),
      },
      sequence: connectInfo.parsedConnectInfo ? Number(opts.connectInfoSequence === undefined ? 40 : opts.connectInfoSequence) : undefined,
      payloadLength: connectInfo.payload.length,
      usernamePresent: Boolean(connectInfo.parsedConnectInfo.username),
      passwordPresent: Boolean(auth.vmPassword),
    };

    const connectReplyWait = waitForControl(socket, (event) => (
      event.type === 0x09 &&
      event.routeIdHex === report.localKey.routeIdHex &&
      event.connectReply
    ), timeoutMs);
    await sendUdp(socket, connectInfo.datagram, port, host);
    const connectReplyResult = await connectReplyWait;
    report.observed.push(...connectReplyResult.seen.map(redactHandshakeEvent));
    report.connectReply = redactHandshakeEvent(connectReplyResult.event);

    if (!sendReady) return report;

    const routeId = localKey.routeId;
    const readyControlWord = opts.readyControlWord === undefined ? 0x1405 : Number(opts.readyControlWord);
    const clientReadySequence = opts.clientReadySequence === undefined ? 0x53230046 : Number(opts.clientReadySequence);
    const peerConfirmSequence = opts.peerConfirmSequence === undefined ? 0x20430013 : Number(opts.peerConfirmSequence);
    const clientReady = encodeZteCagUdpControlDatagram({
      type: 0x01,
      sequence: clientReadySequence,
      routeId,
      tunnelId,
      controlWord: readyControlWord,
    });
    const peerReadyWait = waitForControl(socket, (event) => (
      event.type === 0x02 &&
      event.routeIdHex === report.localKey.routeIdHex &&
      event.tunnelIdHex === report.serverKey.tunnelIdHex
    ), timeoutMs);
    await sendUdp(socket, clientReady, port, host);
    let peerReadyResult;
    try {
      peerReadyResult = await peerReadyWait;
    } catch (err) {
      if (Array.isArray(err.seen)) {
        report.observed.push(...err.seen.map(redactHandshakeEvent));
      }
      err.report = report;
      throw err;
    }
    report.observed.push(...peerReadyResult.seen.map(redactHandshakeEvent));
    report.peerReady = redactHandshakeEvent(peerReadyResult.event);

    const peerConfirm = encodeZteCagUdpControlDatagram({
      type: 0x02,
      sequence: peerConfirmSequence,
      routeId,
      tunnelId,
      controlWord: readyControlWord,
    });
    await sendUdp(socket, peerConfirm, port, host);
    report.readyConfirm = {
      type: 0x02,
      typeName: 'peer_ready',
      sequence: peerConfirmSequence,
      tunnelIdHex: report.serverKey.tunnelIdHex,
      datagram: {
        length: peerConfirm.length,
        sha256: sha256Hex(peerConfirm),
      },
    };
    return report;
  } catch (err) {
    if (!err.report) err.report = report;
    throw err;
  } finally {
    socket.close();
  }
}

module.exports = {
  runCagUdpHandshake,
  summarizeControlMessage,
};
