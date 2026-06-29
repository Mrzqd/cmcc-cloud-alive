'use strict';

const assert = require('assert');
const dgram = require('dgram');
const {
  encodeZteCagPacket,
  encodeZteCagUdpControlDatagram,
  parseZteCagDatagram,
  runCagUdpHandshake,
} = require('../lib/protocol');

function bindUdp(socket) {
  return new Promise((resolve) => socket.bind(0, '127.0.0.1', resolve));
}

function sendUdp(socket, datagram, port, address) {
  return new Promise((resolve, reject) => {
    socket.send(datagram, port, address, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function serverKeyDatagram(routeId, tunnelId, serverKey) {
  const body = Buffer.alloc(0x24);
  body.writeUInt32LE(0x65, 0);
  body.writeUInt32LE(serverKey >>> 0, 4);
  body.writeUInt32LE(0x03, 0x1c);
  return encodeZteCagUdpControlDatagram({
    type: 0x07,
    sequence: 0,
    routeId,
    tunnelId,
    controlWord: 0x3200,
    payload: encodeZteCagPacket(body),
  });
}

function connectReplyDatagram(routeId, tunnelId) {
  const payload = Buffer.alloc(0x24);
  payload.writeUInt32LE(200, 0);
  return encodeZteCagUdpControlDatagram({
    type: 0x09,
    sequence: 0,
    routeId,
    tunnelId,
    controlWord: 0x2400,
    payload,
  });
}

async function main() {
  const server = dgram.createSocket('udp4');
  const receivedTypes = [];
  const tunnelId = 0x34db0787;
  const serverKey = 0x4f21c3da;

  server.on('message', async (message, remote) => {
    const parsed = parseZteCagDatagram(message);
    const control = parsed.udpControl;
    if (!control) return;
    receivedTypes.push(control.header.type);
    if (control.header.type === 0x06) {
      await sendUdp(
        server,
        serverKeyDatagram(control.header.routeId, tunnelId, serverKey),
        remote.port,
        remote.address,
      );
    } else if (control.header.type === 0x08) {
      await sendUdp(
        server,
        connectReplyDatagram(control.header.routeId, tunnelId),
        remote.port,
        remote.address,
      );
    } else if (control.header.type === 0x01) {
      await sendUdp(
        server,
        encodeZteCagUdpControlDatagram({
          type: 0x02,
          sequence: 0x20430046,
          routeId: control.header.routeId,
          tunnelId,
          controlWord: 0x1405,
        }),
        remote.port,
        remote.address,
      );
    }
  });

  await bindUdp(server);
  const serverAddress = server.address();
  try {
    const report = await runCagUdpHandshake({
      cagIp: '127.0.0.1',
      cagPort: serverAddress.port,
      vmcIp: '10.10.2.243',
      vmcPort: 8443,
      vmId: '163c68a9-5e1e-4cba-b9bb-68ad599a8abf',
      vmUserName: 'user-for-test',
      vmPassword: 'password-for-test',
    }, {
      randomKey: '0x05297b44',
      clientKey: '1cf70100b39cdc40894d7064b782e88b',
      traceId: 'bb0ff3ff89ba0d0f0ca7d033a5f8b522',
      spanId: '100390b5139e6c89',
      sendConnectInfo: true,
      sendReady: true,
      timeoutMs: 1000,
    });

    await wait(20);
    assert.deepStrictEqual(receivedTypes, [0x06, 0x08, 0x01, 0x02]);
    assert.strictEqual(report.serverKey.typeName, 'server_key');
    assert.strictEqual(report.serverKey.serverKeyHex, '0x4f21c3da');
    assert.strictEqual(report.connectReply.connectReply.ok, true);
    assert.strictEqual(report.peerReady.typeName, 'peer_ready');
    assert.strictEqual(report.readyConfirm.sequence, 0x20430013);
    assert.strictEqual(report.safe.sdkStarted, false);
    assert.strictEqual(report.safe.sendsConnectInfo, true);
    assert.strictEqual(report.safe.sendsReady, true);
  } finally {
    server.close();
  }
}

main().then(() => {
  console.log('cag-udp-handshake tests passed');
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
