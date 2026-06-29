'use strict';

const crypto = require('crypto');

const ZTEC_MAGIC = Buffer.from('ZTEC', 'ascii');
const ZTE_CAG_PACKET_HEAD_SIZE = 6;
const ZTE_CAG_UDP_CONTROL_HEAD_SIZE = 21;
const ZTE_CAG_KEY_BODY_SIZE = 0x2c;
const ZTE_CAG_OPENTELEMETRY_KEY_BODY_SIZE = 0xac;
const ZTE_CAG_TUNNEL_HEAD_SIZE = 24;
const ZTE_CAG_CONNECT_REPLY_SIZE = 0x24;

const ZteCagTunnelType = Object.freeze({
  DATA: 0x81,
  CONTROL: 0x82,
  BATCH_OR_RETRANSMIT: 0x85,
  ACK: 0x86,
  SERVER_CONTROL: 0x87,
  CLIENT_CONTROL: 0x89,
});

const ZteCagAuthType = Object.freeze({
  RADIUS: 1,
  UAC: 2,
});

const TLS_CONTENT_TYPES = new Set([0x14, 0x15, 0x16, 0x17]);
const TLS_MAJOR_VERSION = 0x03;

function findMagicOffset(input, magic = ZTEC_MAGIC) {
  return Buffer.from(input || []).indexOf(Buffer.from(magic));
}

function looksLikeTlsRecordAt(buffer, offset = 0) {
  if (buffer.length < offset + 5) return false;
  return TLS_CONTENT_TYPES.has(buffer.readUInt8(offset)) &&
    buffer.readUInt8(offset + 1) === TLS_MAJOR_VERSION;
}

function findTlsRecordOffset(input) {
  const buffer = Buffer.from(input || []);
  for (let i = 0; i <= buffer.length - 5; i++) {
    if (looksLikeTlsRecordAt(buffer, i)) return i;
  }
  return -1;
}

function requireUInt32(value, name) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error(`${name} must be a uint32`);
  }
  return n >>> 0;
}

function requireUInt16(value, name) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
    throw new Error(`${name} must be a uint16`);
  }
  return n;
}

function normalizeClientKey(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length === 16) return buffer;
  if (buffer.length === 4) {
    return Buffer.concat([buffer, Buffer.alloc(12)]);
  }
  throw new Error('clientKey must be 16 bytes');
}

function encodeZteCagPacketHead(bodyLength) {
  const head = Buffer.alloc(ZTE_CAG_PACKET_HEAD_SIZE);
  ZTEC_MAGIC.copy(head, 0);
  head.writeUInt16LE(requireUInt16(bodyLength, 'bodyLength'), 4);
  return head;
}

function decodeZteCagPacketHead(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length < ZTE_CAG_PACKET_HEAD_SIZE) {
    throw new Error(`ZTE CAG packet head requires ${ZTE_CAG_PACKET_HEAD_SIZE} bytes`);
  }
  const magic = buffer.subarray(0, 4);
  return {
    magic,
    magicText: magic.toString('ascii'),
    ok: magic.equals(ZTEC_MAGIC),
    bodyLength: buffer.readUInt16LE(4),
    raw: buffer.subarray(0, ZTE_CAG_PACKET_HEAD_SIZE),
  };
}

function encodeZteCagPacket(body) {
  const payload = Buffer.from(body || []);
  return Buffer.concat([encodeZteCagPacketHead(payload.length), payload]);
}

function decodeZteCagPacket(input) {
  const buffer = Buffer.from(input || []);
  const head = decodeZteCagPacketHead(buffer);
  const total = ZTE_CAG_PACKET_HEAD_SIZE + head.bodyLength;
  if (buffer.length < total) {
    throw new Error(`ZTE CAG packet body requires ${head.bodyLength} bytes`);
  }
  return {
    head,
    body: buffer.subarray(ZTE_CAG_PACKET_HEAD_SIZE, total),
    rest: buffer.subarray(total),
  };
}

function zteCagPasswordBlockLength(passwordLength) {
  const n = Number(passwordLength || 0);
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
    throw new Error('passwordLength must be a uint16-sized integer');
  }
  if (n === 0) return 0;
  let length = n + 1;
  if ((length & 0x0f) !== 0) {
    length = (((length + 0x0f) >> 4) + 1) << 4;
  }
  return length;
}

function zteCagConnectInfoLength(opts = {}) {
  const authType = Number(opts.authType || ZteCagAuthType.UAC);
  if (authType === ZteCagAuthType.RADIUS) return 0xdc;
  return 0x7e + zteCagPasswordBlockLength(opts.passwordLength || 0);
}

function encodeZteCagLocalKeyBody(opts = {}) {
  const authType = requireUInt16(opts.authType || ZteCagAuthType.UAC, 'authType');
  const randomKey = requireUInt32(opts.randomKey || 0, 'randomKey');
  const body = Buffer.alloc(ZTE_CAG_KEY_BODY_SIZE);
  body.writeUInt32LE((authType + 0x64) >>> 0, 0);
  body.writeUInt32LE(randomKey, 4);
  body.writeUInt32LE(zteCagConnectInfoLength(opts), 8);
  normalizeClientKey(opts.clientKey).copy(body, 0x0c, 0, 16);

  let flags = Number(opts.baseFlags === undefined ? 0x03 : opts.baseFlags) & 0xffff;
  flags |= (Number(opts.transportFlag || 0) & 0xff) << 16;
  flags |= (Number(opts.addressFamilyFlag || 0) & 0xff) << 24;
  body.writeUInt32LE(flags >>> 0, 0x1c);
  return body;
}

function encodeZteCagLocalKeyPacket(opts = {}) {
  return encodeZteCagPacket(encodeZteCagLocalKeyBody(opts));
}

function decodeZteCagKeyBody(input) {
  const body = Buffer.from(input || []);
  if (body.length < ZTE_CAG_KEY_BODY_SIZE) {
    throw new Error(`ZTE CAG key body requires ${ZTE_CAG_KEY_BODY_SIZE} bytes`);
  }
  const flags = body.readUInt32LE(0x1c);
  return {
    firstWord: body.readUInt32LE(0),
    key: body.readUInt32LE(4),
    connectInfoLength: body.readUInt32LE(8),
    clientKey: body.subarray(0x0c, 0x1c),
    flags,
    aesType: (flags & 0x01) ? 2 : 1,
    useCbc: Boolean(flags & 0x02),
    sdkAesFlags: ((flags & 0x01) ? 2 : 1) | ((flags << 7) & 0x100),
    transportFlag: (flags >>> 16) & 0xff,
    addressFamilyFlag: (flags >>> 24) & 0xff,
    raw: body.subarray(0, ZTE_CAG_KEY_BODY_SIZE),
  };
}

function writeFixedAscii(target, offset, size, value) {
  const text = Buffer.from(String(value || ''), 'ascii');
  text.copy(target, offset, 0, Math.min(text.length, size - 1));
}

function readFixedAscii(input) {
  const buffer = Buffer.from(input || []);
  const end = buffer.indexOf(0);
  return buffer.subarray(0, end === -1 ? buffer.length : end).toString('ascii');
}

function fixedAsciiBuffer(value, size, name = 'value') {
  if (!Number.isInteger(size) || size <= 0) throw new Error('size must be a positive integer');
  const out = Buffer.alloc(size);
  const text = Buffer.from(String(value || ''), 'ascii');
  if (text.length >= size) throw new Error(`${name} is too long for ${size}-byte field`);
  text.copy(out, 0);
  return out;
}

function encodeZteCagIpAddress(address) {
  const out = Buffer.alloc(16);
  const text = String(address || '').trim();
  const parts = text.split('.');
  if (parts.length !== 4) throw new Error('only IPv4 CAG destination addresses are currently supported');
  parts.forEach((part, i) => {
    if (!/^\d+$/.test(part)) throw new Error(`invalid IPv4 address: ${text}`);
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) throw new Error(`invalid IPv4 address: ${text}`);
    out.writeUInt8(n, i);
  });
  return out;
}

function decodeZteCagIpAddress(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length < 4) throw new Error('IPv4 address requires at least 4 bytes');
  return [...buffer.subarray(0, 4)].join('.');
}

function xorZteCagPassword(input, key = 0x63) {
  const out = Buffer.from(input || []);
  const k = Number(key) & 0xff;
  if (k === 0) return out;
  for (let i = 0; i < out.length; i++) {
    if (out[i] !== k) out[i] ^= k;
  }
  return out;
}

function encodeZteCagCredentialBlock(value, size = 0x40) {
  return fixedAsciiBuffer(value, size, 'credential');
}

function decodeZteCagCredentialBlock(input) {
  return readFixedAscii(Buffer.from(input || []));
}

function encodeZteCagRadiusConnectInfoBody(opts = {}) {
  const port = requireUInt16(opts.vmcPort || opts.port || 0, 'vmcPort');
  const vmId = String(opts.vmId || opts.vmID || '');
  if (!vmId) throw new Error('vmId is required');

  const aesOpts = {
    clientKey: opts.clientKey ?? opts.randomKey,
    serverKey: opts.serverKey,
    aesFlags: opts.aesFlags ?? opts.sdkAesFlags ?? 1,
  };
  const body = Buffer.alloc(0xdc);
  body.writeUInt16LE(port, 0);
  encodeZteCagIpAddress(opts.vmcIp || opts.ip || opts.host).copy(body, 0x04);
  fixedAsciiBuffer(vmId, 0x28, 'vmId').copy(body, 0x14);
  body.writeUInt16LE(body.readUInt16LE(0xbc) | (Number(opts.addressFamilyFlag || 0) & 0xff), 0xbc);

  const username = opts.vmUserName || opts.username || '';
  zteCagAesCrypt(encodeZteCagCredentialBlock(username, 0x40), aesOpts).copy(body, 0x3c);

  const password = opts.vmPassword || opts.password || '';
  if (password) {
    const passwordBytes = Buffer.from(String(password), 'ascii');
    if (passwordBytes.length >= 0x40) throw new Error('password is too long for 64-byte CAG field');
    const xored = xorZteCagPassword(passwordBytes, 0x63);
    const block = Buffer.alloc(0x40);
    xored.copy(block, 0);
    zteCagAesCrypt(block, aesOpts).copy(body, 0x7c);
  }

  return body;
}

function decodeZteCagRadiusConnectInfoBody(input, opts = {}) {
  const body = Buffer.from(input || []);
  if (body.length < 0xdc) throw new Error('ZTE CAG RADIUS connect-info body requires 0xdc bytes');
  const out = {
    port: body.readUInt16LE(0),
    ip: decodeZteCagIpAddress(body.subarray(0x04, 0x14)),
    vmId: readFixedAscii(body.subarray(0x14, 0x3c)),
    addressFamilyFlag: body.readUInt16LE(0xbc) & 0xff,
    encryptedUsername: body.subarray(0x3c, 0x7c),
    encryptedPassword: body.subarray(0x7c, 0xbc),
    raw: body.subarray(0, 0xdc),
  };

  if (opts.clientKey !== undefined || opts.randomKey !== undefined) {
    const aesOpts = {
      clientKey: opts.clientKey ?? opts.randomKey,
      serverKey: opts.serverKey,
      aesFlags: opts.aesFlags ?? opts.sdkAesFlags ?? 1,
    };
    out.username = decodeZteCagCredentialBlock(zteCagAesCrypt(out.encryptedUsername, { ...aesOpts, decrypt: true }));
    const passwordBlock = zteCagAesCrypt(out.encryptedPassword, { ...aesOpts, decrypt: true });
    out.passwordXor = passwordBlock;
    out.password = decodeZteCagCredentialBlock(xorZteCagPassword(passwordBlock, 0x63));
  }

  return out;
}

function encodeZteCagOpentelemetryLocalKeyBody(opts = {}) {
  const body = Buffer.alloc(ZTE_CAG_OPENTELEMETRY_KEY_BODY_SIZE);
  encodeZteCagLocalKeyBody({
    ...opts,
    baseFlags: opts.baseFlags === undefined ? 0x07 : opts.baseFlags,
  }).copy(body, 0, 0, ZTE_CAG_KEY_BODY_SIZE);
  writeFixedAscii(body, 0x2c, 0x40, opts.traceId);
  writeFixedAscii(body, 0x6c, 0x40, opts.spanId);
  return body;
}

function encodeZteCagOpentelemetryLocalKeyPacket(opts = {}) {
  return encodeZteCagPacket(encodeZteCagOpentelemetryLocalKeyBody(opts));
}

function decodeZteCagOpentelemetryLocalKeyBody(input) {
  const body = Buffer.from(input || []);
  if (body.length < ZTE_CAG_OPENTELEMETRY_KEY_BODY_SIZE) {
    throw new Error(`ZTE CAG opentelemetry key body requires ${ZTE_CAG_OPENTELEMETRY_KEY_BODY_SIZE} bytes`);
  }
  return {
    ...decodeZteCagKeyBody(body),
    traceId: readFixedAscii(body.subarray(0x2c, 0x6c)),
    spanId: readFixedAscii(body.subarray(0x6c, 0xac)),
  };
}

function decodeZteCagServerKeyBody(input) {
  const body = Buffer.from(input || []);
  if (body.length < 0x20) {
    throw new Error('ZTE CAG server key body requires at least 0x20 bytes');
  }
  const flags = body.readUInt32LE(0x1c);
  return {
    firstWord: body.readUInt32LE(0),
    key: body.readUInt32LE(4),
    flags,
    aesType: (flags & 0x01) ? 2 : 1,
    useCbc: Boolean(flags & 0x02),
    sdkAesFlags: ((flags & 0x01) ? 2 : 1) | ((flags << 7) & 0x100),
    raw: body,
  };
}

function decodeZteCagServerKeyPacket(input) {
  const packet = decodeZteCagPacket(input);
  if (!packet.head.ok) throw new Error(`invalid ZTE CAG magic: ${packet.head.magicText}`);
  if (packet.head.bodyLength !== ZTE_CAG_KEY_BODY_SIZE && packet.head.bodyLength !== 0x24) {
    throw new Error(`unexpected ZTE CAG server key body length: ${packet.head.bodyLength}`);
  }
  return {
    ...packet,
    keyInfo: decodeZteCagServerKeyBody(packet.body),
  };
}

function hexByte(value, upper = false) {
  const out = (Number(value) & 0xff).toString(16).padStart(2, '0');
  return upper ? out.toUpperCase() : out;
}

function uint32BytesLE(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32LE(requireUInt32(value, 'uint32'), 0);
  return [...buffer];
}

function deriveZteCagAesMaterial(opts = {}) {
  const clientKey = requireUInt32(opts.clientKey, 'clientKey');
  const serverKey = requireUInt32(opts.serverKey, 'serverKey');
  const aesFlags = requireUInt32(opts.aesFlags || opts.sdkAesFlags || 1, 'aesFlags');
  const local = (clientKey & 0xabacacab) >>> 0;
  const remote = (serverKey | 0x98979798) >>> 0;
  const lb = uint32BytesLE(local);
  const rb = uint32BytesLE(remote);

  const ivString = [
    '02x',
    hexByte(lb[2], true),
    hexByte(lb[0], true),
    hexByte(lb[1], false),
    hexByte(lb[3], true),
    hexByte(rb[1], false),
    hexByte(rb[2], false),
    hexByte(rb[3], true),
  ].join('');
  const keyString = [
    clientKey.toString(16).padStart(8, '0'),
    serverKey.toString(16).padStart(8, '0'),
    hexByte(rb[0], false),
    hexByte(rb[3], false),
    hexByte(rb[2], false),
    hexByte(rb[1], false),
    hexByte(lb[3], false),
    hexByte(lb[1], false),
    hexByte(lb[0], false),
    hexByte(lb[2], false),
  ].join('');

  const aesType = aesFlags & 0xff;
  const bits = aesType * 128;
  if (bits !== 128 && bits !== 256) {
    throw new Error(`unsupported ZTE CAG AES key size flag: ${aesType}`);
  }
  return {
    clientKey,
    serverKey,
    local,
    remote,
    aesFlags,
    aesType,
    bits,
    useCbc: Boolean(aesFlags & 0x100),
    keyString,
    key: Buffer.from(keyString, 'ascii').subarray(0, bits / 8),
    ivString,
    iv: Buffer.from(ivString, 'ascii').subarray(0, 16),
  };
}

function zteCagAesCrypt(input, opts = {}) {
  const material = opts.key ? opts : deriveZteCagAesMaterial(opts);
  const data = Buffer.from(input || []);
  if ((data.length % 16) !== 0) throw new Error('ZTE CAG AES input length must be a multiple of 16');
  const bits = material.bits || (Buffer.from(material.key).length * 8);
  const mode = material.useCbc ? 'cbc' : 'ecb';
  const algorithm = `aes-${bits}-${mode}`;
  const cipher = opts.decrypt
    ? crypto.createDecipheriv(algorithm, material.key, mode === 'cbc' ? material.iv : null)
    : crypto.createCipheriv(algorithm, material.key, mode === 'cbc' ? material.iv : null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function parseZteCagConnectReply(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length < ZTE_CAG_CONNECT_REPLY_SIZE) {
    throw new Error(`ZTE CAG connect reply requires ${ZTE_CAG_CONNECT_REPLY_SIZE} bytes`);
  }
  const code = buffer.readUInt32LE(0);
  return {
    ok: code === 200,
    code,
    raw: buffer.subarray(0, ZTE_CAG_CONNECT_REPLY_SIZE),
  };
}

function parseZteCagUdpControlHeader(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length < ZTE_CAG_UDP_CONTROL_HEAD_SIZE) {
    throw new Error(`ZTE CAG UDP control header requires ${ZTE_CAG_UDP_CONTROL_HEAD_SIZE} bytes`);
  }
  const type = buffer.readUInt8(0);
  return {
    raw: buffer.subarray(0, ZTE_CAG_UDP_CONTROL_HEAD_SIZE),
    type,
    typeName: zteCagUdpControlTypeName(type),
    flags24: buffer.subarray(1, 4),
    sequence: buffer.readUInt32BE(4),
    routeId: buffer.subarray(8, 15),
    tunnelId: buffer.readUInt32BE(15),
    controlWord: buffer.readUInt16BE(19),
  };
}

function normalizeFixedBuffer(input, size, name) {
  const buffer = Buffer.from(input || []);
  if (buffer.length !== size) throw new Error(`${name} must be ${size} bytes`);
  return buffer;
}

function encodeZteCagUdpControlHeader(opts = {}) {
  const out = Buffer.alloc(ZTE_CAG_UDP_CONTROL_HEAD_SIZE);
  out.writeUInt8(Number(opts.type || 0) & 0xff, 0);
  normalizeFixedBuffer(opts.flags24 || Buffer.from('000080', 'hex'), 3, 'flags24').copy(out, 1);
  out.writeUInt32BE(requireUInt32(opts.sequence || 0, 'sequence'), 4);
  normalizeFixedBuffer(opts.routeId || Buffer.alloc(7), 7, 'routeId').copy(out, 8);
  out.writeUInt32BE(requireUInt32(opts.tunnelId || 0, 'tunnelId'), 15);
  out.writeUInt16BE(requireUInt16(opts.controlWord || 0, 'controlWord'), 19);
  return out;
}

function encodeZteCagUdpControlDatagram(opts = {}) {
  return Buffer.concat([
    encodeZteCagUdpControlHeader(opts),
    Buffer.from(opts.payload || []),
  ]);
}

function parseZteCagUdpControlDatagram(input) {
  const buffer = Buffer.from(input || []);
  const header = parseZteCagUdpControlHeader(buffer);
  const payload = buffer.subarray(ZTE_CAG_UDP_CONTROL_HEAD_SIZE);
  const out = {
    header,
    payload,
  };

  if (payload.length >= ZTE_CAG_PACKET_HEAD_SIZE && payload.subarray(0, 4).equals(ZTEC_MAGIC)) {
    const packet = decodeZteCagPacket(payload);
    out.ztecPacket = {
      head: packet.head,
      body: packet.body,
    };
    if (packet.head.bodyLength === ZTE_CAG_KEY_BODY_SIZE) {
      out.ztecKeyInfo = decodeZteCagKeyBody(packet.body);
    } else if (packet.head.bodyLength === ZTE_CAG_OPENTELEMETRY_KEY_BODY_SIZE) {
      out.ztecOpentelemetryKeyInfo = decodeZteCagOpentelemetryLocalKeyBody(packet.body);
    } else if (header.type === 0x07 && packet.head.bodyLength === 0x24) {
      out.ztecServerKeyInfo = decodeZteCagServerKeyBody(packet.body);
      out.dynamicTunnelWord0 = header.tunnelId;
    }
  } else if (header.type === 0x09 && payload.length >= ZTE_CAG_CONNECT_REPLY_SIZE) {
    out.connectReply = parseZteCagConnectReply(payload);
  }

  return out;
}

function encodeZteCagTunnelHeader(opts = {}) {
  const out = Buffer.alloc(ZTE_CAG_TUNNEL_HEAD_SIZE);
  out.writeUInt32BE(requireUInt32(opts.word0 === undefined ? 0xe1db878d : opts.word0, 'word0'), 0);
  out.writeUInt32BE(requireUInt32(opts.word1 || 0, 'word1'), 4);
  out.writeUInt32BE(requireUInt32(opts.word2 || 0, 'word2'), 8);
  out.writeUInt32BE(requireUInt32(opts.word3 || 0, 'word3'), 12);
  out.writeUInt32BE(requireUInt32(opts.word4 || 0, 'word4'), 16);
  out.writeUInt32BE(requireUInt32(opts.word5 || 0, 'word5'), 20);
  return out;
}

function parseZteCagTunnelHeader(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length < ZTE_CAG_TUNNEL_HEAD_SIZE) {
    throw new Error(`ZTE CAG tunnel header requires ${ZTE_CAG_TUNNEL_HEAD_SIZE} bytes`);
  }
  const word1 = buffer.readUInt32BE(4);
  return {
    raw: buffer.subarray(0, ZTE_CAG_TUNNEL_HEAD_SIZE),
    word0: buffer.readUInt32BE(0),
    word1,
    word2: buffer.readUInt32BE(8),
    word3: buffer.readUInt32BE(12),
    word4: buffer.readUInt32BE(16),
    word5: buffer.readUInt32BE(20),
    packetType: (word1 >>> 24) & 0xff,
    flagByte: (word1 >>> 16) & 0xff,
    sequence16: word1 & 0xffff,
  };
}

function zteCagTunnelTypeName(packetType) {
  switch (packetType) {
    case ZteCagTunnelType.DATA:
      return 'data';
    case ZteCagTunnelType.CONTROL:
      return 'control';
    case ZteCagTunnelType.BATCH_OR_RETRANSMIT:
      return 'batch_or_retransmit';
    case ZteCagTunnelType.ACK:
      return 'ack';
    case ZteCagTunnelType.SERVER_CONTROL:
      return 'server_control';
    case ZteCagTunnelType.CLIENT_CONTROL:
      return 'client_control';
    default:
      return `unknown_0x${Number(packetType & 0xff).toString(16).padStart(2, '0')}`;
  }
}

function zteCagUdpControlTypeName(type) {
  switch (Number(type) & 0xff) {
    case 0x01:
      return 'client_ready';
    case 0x02:
      return 'peer_ready';
    case 0x06:
      return 'local_key';
    case 0x07:
      return 'server_key';
    case 0x08:
      return 'connect_info';
    case 0x09:
      return 'connect_reply';
    default:
      return `unknown_0x${(Number(type) & 0xff).toString(16).padStart(2, '0')}`;
  }
}

function isKnownZteCagTunnelType(packetType) {
  return Object.values(ZteCagTunnelType).includes(Number(packetType) & 0xff);
}

function looksLikeZteCagTunnelDatagram(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length < 8) return false;
  if (buffer.subarray(0, 4).equals(ZTEC_MAGIC)) return false;
  return isKnownZteCagTunnelType(buffer.readUInt8(4));
}

function looksLikeZteCagPreflightDatagram(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length !== 14 && buffer.length !== 26) return false;
  if (buffer.length === 14) return !buffer.subarray(0, 4).equals(ZTEC_MAGIC);
  if (!buffer.subarray(0, 4).equals(ZTEC_MAGIC)) return false;
  return buffer.readUInt16LE(4) === 6;
}

function parseZteCagPreflightDatagram(input) {
  const buffer = Buffer.from(input || []);
  if (!looksLikeZteCagPreflightDatagram(buffer)) {
    throw new Error('ZTE CAG preflight datagram requires a 26-byte probe or 14-byte echo');
  }
  if (buffer.length === 14) {
    return {
      directionHint: 'cag_echo',
      echoTail: buffer,
      echoTailHex: buffer.toString('hex'),
    };
  }
  const packet = decodeZteCagPacket(buffer);
  return {
    directionHint: 'client_probe',
    packetHead: packet.head,
    probeBody: packet.body,
    probeBodyHex: packet.body.toString('hex'),
    echoTail: packet.rest,
    echoTailHex: packet.rest.toString('hex'),
  };
}

function readOptionalUInt32BE(buffer, offset) {
  return buffer.length >= offset + 4 ? buffer.readUInt32BE(offset) : null;
}

function parseZteCagShortTunnelDatagram(input) {
  const buffer = Buffer.from(input || []);
  if (!looksLikeZteCagTunnelDatagram(buffer)) {
    throw new Error('ZTE CAG short tunnel datagram requires a known packet type at byte 4');
  }
  const word1 = buffer.length >= 8 ? buffer.readUInt32BE(4) : 0;
  const shortTailOffset = Math.min(buffer.length, 20);
  return {
    header: {
      raw: buffer,
      short: true,
      word0: buffer.readUInt32BE(0),
      word1,
      word2: readOptionalUInt32BE(buffer, 8),
      word3: readOptionalUInt32BE(buffer, 12),
      word4: readOptionalUInt32BE(buffer, 16),
      word5: readOptionalUInt32BE(buffer, 20),
      packetType: (word1 >>> 24) & 0xff,
      packetTypeName: zteCagTunnelTypeName((word1 >>> 24) & 0xff),
      flagByte: (word1 >>> 16) & 0xff,
      sequence16: word1 & 0xffff,
      shortTail: buffer.subarray(shortTailOffset),
    },
    payload: Buffer.alloc(0),
    payloadLength: 0,
    payloadLengthMatchesWord4: false,
    tlsRecordOffset: -1,
    hasTlsRecord: false,
    tlsRecord: Buffer.alloc(0),
    short: true,
  };
}

function parseZteCagTunnelDatagram(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length < ZTE_CAG_TUNNEL_HEAD_SIZE) {
    return parseZteCagShortTunnelDatagram(buffer);
  }
  const header = parseZteCagTunnelHeader(buffer);
  const payload = buffer.subarray(ZTE_CAG_TUNNEL_HEAD_SIZE);
  const tlsOffset = findTlsRecordOffset(payload);
  return {
    header: {
      ...header,
      packetTypeName: zteCagTunnelTypeName(header.packetType),
    },
    payload,
    payloadLength: payload.length,
    payloadLengthMatchesWord4: payload.length === header.word4,
    tlsRecordOffset: tlsOffset,
    hasTlsRecord: tlsOffset !== -1,
    tlsRecord: tlsOffset === -1 ? Buffer.alloc(0) : payload.subarray(tlsOffset),
  };
}

function hexUInt32(value) {
  if (value === null || value === undefined) return null;
  return `0x${(Number(value) >>> 0).toString(16).padStart(8, '0')}`;
}

function deriveZteCagTunnelMeta(tunnelOrPayload) {
  const tunnel = Buffer.isBuffer(tunnelOrPayload)
    ? parseZteCagTunnelDatagram(tunnelOrPayload)
    : tunnelOrPayload;
  const header = tunnel.header;
  const meta = {
    type: header.packetTypeName,
    word0: hexUInt32(header.word0),
    short: Boolean(tunnel.short || header.short),
    sequence16: header.sequence16,
    flagByte: header.flagByte,
    word2: hexUInt32(header.word2),
    word3: hexUInt32(header.word3),
    word4: hexUInt32(header.word4),
    word5: hexUInt32(header.word5),
    payloadLength: tunnel.payloadLength,
    payloadLengthMatchesWord4: tunnel.payloadLengthMatchesWord4,
    hasTlsRecord: tunnel.hasTlsRecord,
    tlsRecordOffset: tunnel.tlsRecordOffset,
  };

  if (header.packetType === ZteCagTunnelType.ACK) {
    meta.ackValue = header.word2;
    meta.ackValueHex = hexUInt32(header.word2);
  }
  if (header.packetType === ZteCagTunnelType.CONTROL) {
    meta.controlFlag = header.flagByte;
    meta.controlSequence = header.sequence16;
    if (header.shortTail && header.shortTail.length) {
      meta.shortTailHex = header.shortTail.toString('hex');
    }
  }
  if (header.packetType === ZteCagTunnelType.DATA) {
    meta.dataSequence = header.sequence16;
    meta.fragmentIndex = header.word3;
    meta.advertisedPayloadLength = header.word4;
    meta.payloadClass = tunnel.hasTlsRecord
      ? 'tls_record'
      : tunnel.payloadLengthMatchesWord4
        ? 'single_payload'
        : 'fragmented_or_batched_payload';
  }
  if (header.packetType === ZteCagTunnelType.BATCH_OR_RETRANSMIT) {
    meta.batchSequence = header.sequence16;
    meta.batchHint = header.word5;
  }
  if (header.packetType === ZteCagTunnelType.CLIENT_CONTROL) {
    meta.clientControlLength = header.word4;
  }

  return meta;
}

function summarizeZteCagTunnelSequences(datagrams = []) {
  const summary = {
    total: 0,
    byDirection: {},
    ackValues: [],
    dataSequences: {},
    shortControls: [],
  };

  for (const item of datagrams) {
    const direction = item.direction || item.dir || '';
    const tunnel = item.tunnel || parseZteCagTunnelDatagram(item.payload || item);
    const meta = deriveZteCagTunnelMeta(tunnel);
    const dirKey = direction || 'unknown';
    const typeKey = tunnel.header.packetTypeName;

    summary.total++;
    if (!summary.byDirection[dirKey]) summary.byDirection[dirKey] = {};
    if (!summary.byDirection[dirKey][typeKey]) {
      summary.byDirection[dirKey][typeKey] = {
        count: 0,
        firstSequence16: null,
        lastSequence16: null,
        minSequence16: null,
        maxSequence16: null,
      };
    }
    const bucket = summary.byDirection[dirKey][typeKey];
    bucket.count++;
    bucket.lastSequence16 = tunnel.header.sequence16;
    if (bucket.firstSequence16 === null) bucket.firstSequence16 = tunnel.header.sequence16;
    if (bucket.minSequence16 === null || tunnel.header.sequence16 < bucket.minSequence16) {
      bucket.minSequence16 = tunnel.header.sequence16;
    }
    if (bucket.maxSequence16 === null || tunnel.header.sequence16 > bucket.maxSequence16) {
      bucket.maxSequence16 = tunnel.header.sequence16;
    }

    if (meta.ackValue !== undefined) {
      summary.ackValues.push({
        direction: dirKey,
        sequence16: tunnel.header.sequence16,
        ackValue: meta.ackValue,
      });
    }
    if (tunnel.header.packetType === ZteCagTunnelType.DATA) {
      const key = `${dirKey}:${tunnel.header.sequence16}`;
      if (!summary.dataSequences[key]) {
        summary.dataSequences[key] = {
          direction: dirKey,
          sequence16: tunnel.header.sequence16,
          count: 0,
          payloadLength: 0,
          fragments: [],
          tlsRecords: 0,
        };
      }
      const seq = summary.dataSequences[key];
      seq.count++;
      seq.payloadLength += tunnel.payloadLength;
      seq.fragments.push({
        flagByte: tunnel.header.flagByte,
        word3: tunnel.header.word3,
        word4: tunnel.header.word4,
        word5: tunnel.header.word5,
        payloadLength: tunnel.payloadLength,
        matchesWord4: tunnel.payloadLengthMatchesWord4,
        tlsRecordOffset: tunnel.tlsRecordOffset,
      });
      if (tunnel.hasTlsRecord) seq.tlsRecords++;
    }
    if (meta.short && tunnel.header.packetType === ZteCagTunnelType.CONTROL) {
      summary.shortControls.push({
        direction: dirKey,
        sequence16: tunnel.header.sequence16,
        flagByte: tunnel.header.flagByte,
        word2: tunnel.header.word2,
        word3: tunnel.header.word3,
        word4: tunnel.header.word4,
        shortTailHex: meta.shortTailHex || '',
      });
    }
  }

  summary.dataSequences = Object.values(summary.dataSequences);
  return summary;
}

function summarizeZteCagTunnelDatagrams(datagrams = []) {
  const summary = {
    total: 0,
    countsByType: {},
    countsByDirectionAndType: {},
    tlsRecords: 0,
    payloadLengthMatchesWord4: 0,
    ackPackets: 0,
    clientControlPackets: 0,
  };
  for (const item of datagrams) {
    const direction = item.direction || item.dir || '';
    const tunnel = item.tunnel || parseZteCagTunnelDatagram(item.payload || item);
    const name = tunnel.header.packetTypeName;
    summary.total++;
    summary.countsByType[name] = (summary.countsByType[name] || 0) + 1;
    if (direction) {
      const key = `${direction}:${name}`;
      summary.countsByDirectionAndType[key] = (summary.countsByDirectionAndType[key] || 0) + 1;
    }
    if (tunnel.hasTlsRecord) summary.tlsRecords++;
    if (tunnel.payloadLengthMatchesWord4) summary.payloadLengthMatchesWord4++;
    if (tunnel.header.packetType === ZteCagTunnelType.ACK) summary.ackPackets++;
    if (tunnel.header.packetType === ZteCagTunnelType.CLIENT_CONTROL) summary.clientControlPackets++;
  }
  return summary;
}

function parseZteCagDatagram(input) {
  const buffer = Buffer.from(input || []);
  const ztecOffset = findMagicOffset(buffer);
  const tlsOffset = findTlsRecordOffset(buffer);
  const tunnelLike = looksLikeZteCagTunnelDatagram(buffer);
  const out = {
    length: buffer.length,
    ztecOffset,
    tlsOffset,
    hasZtec: ztecOffset !== -1,
    hasTlsRecord: tlsOffset !== -1,
  };
  if (buffer.length >= ZTE_CAG_UDP_CONTROL_HEAD_SIZE && !buffer.subarray(0, 4).equals(Buffer.from('ZTEC')) && !tunnelLike) {
    out.udpControl = parseZteCagUdpControlDatagram(buffer);
    if (out.udpControl.ztecPacket) out.ztecPacket = out.udpControl.ztecPacket;
    if (out.udpControl.ztecKeyInfo) out.ztecKeyInfo = out.udpControl.ztecKeyInfo;
    if (out.udpControl.ztecOpentelemetryKeyInfo) {
      out.ztecOpentelemetryKeyInfo = out.udpControl.ztecOpentelemetryKeyInfo;
    }
    if (out.udpControl.ztecServerKeyInfo) out.ztecServerKeyInfo = out.udpControl.ztecServerKeyInfo;
    if (out.udpControl.connectReply) out.connectReply = out.udpControl.connectReply;
    if (out.udpControl.dynamicTunnelWord0 !== undefined) {
      out.dynamicTunnelWord0 = out.udpControl.dynamicTunnelWord0;
    }
  }
  if (tlsOffset === ZTE_CAG_TUNNEL_HEAD_SIZE && tunnelLike) {
    const tunnel = parseZteCagTunnelDatagram(buffer);
    out.tunnel = tunnel;
    out.tunnelHeader = tunnel.header;
    out.tlsRecord = buffer.subarray(tlsOffset);
  } else if (tunnelLike) {
    const tunnel = parseZteCagTunnelDatagram(buffer);
    out.tunnel = tunnel;
    out.tunnelHeader = tunnel.header;
  }
  if (ztecOffset >= 0 && buffer.length >= ztecOffset + ZTE_CAG_PACKET_HEAD_SIZE) {
    const packet = decodeZteCagPacket(buffer.subarray(ztecOffset));
    out.ztecPacket = {
      head: packet.head,
      body: packet.body,
    };
    if (packet.head.bodyLength === ZTE_CAG_KEY_BODY_SIZE) {
      out.ztecKeyInfo = decodeZteCagKeyBody(packet.body);
    } else if (packet.head.bodyLength === ZTE_CAG_OPENTELEMETRY_KEY_BODY_SIZE) {
      out.ztecOpentelemetryKeyInfo = decodeZteCagOpentelemetryLocalKeyBody(packet.body);
    } else if (out.udpControl?.header.type === 0x07 && packet.head.bodyLength === 0x24) {
      out.ztecServerKeyInfo = decodeZteCagServerKeyBody(packet.body);
      out.dynamicTunnelWord0 = out.udpControl.header.tunnelId;
    }
  }
  return out;
}

module.exports = {
  ZTEC_MAGIC,
  ZTE_CAG_PACKET_HEAD_SIZE,
  ZTE_CAG_UDP_CONTROL_HEAD_SIZE,
  ZTE_CAG_KEY_BODY_SIZE,
  ZTE_CAG_OPENTELEMETRY_KEY_BODY_SIZE,
  ZTE_CAG_TUNNEL_HEAD_SIZE,
  ZTE_CAG_CONNECT_REPLY_SIZE,
  ZteCagTunnelType,
  ZteCagAuthType,
  decodeZteCagKeyBody,
  decodeZteCagOpentelemetryLocalKeyBody,
  decodeZteCagRadiusConnectInfoBody,
  decodeZteCagPacket,
  decodeZteCagPacketHead,
  decodeZteCagServerKeyBody,
  decodeZteCagServerKeyPacket,
  decodeZteCagIpAddress,
  decodeZteCagCredentialBlock,
  deriveZteCagAesMaterial,
  deriveZteCagTunnelMeta,
  encodeZteCagCredentialBlock,
  encodeZteCagIpAddress,
  encodeZteCagLocalKeyBody,
  encodeZteCagLocalKeyPacket,
  encodeZteCagOpentelemetryLocalKeyBody,
  encodeZteCagOpentelemetryLocalKeyPacket,
  encodeZteCagPacket,
  encodeZteCagPacketHead,
  encodeZteCagRadiusConnectInfoBody,
  encodeZteCagTunnelHeader,
  encodeZteCagUdpControlDatagram,
  encodeZteCagUdpControlHeader,
  findMagicOffset,
  isKnownZteCagTunnelType,
  looksLikeZteCagPreflightDatagram,
  looksLikeZteCagTunnelDatagram,
  looksLikeTlsRecordAt,
  findTlsRecordOffset,
  parseZteCagConnectReply,
  parseZteCagPreflightDatagram,
  parseZteCagUdpControlDatagram,
  parseZteCagUdpControlHeader,
  parseZteCagShortTunnelDatagram,
  parseZteCagTunnelDatagram,
  parseZteCagTunnelHeader,
  parseZteCagDatagram,
  summarizeZteCagTunnelDatagrams,
  summarizeZteCagTunnelSequences,
  xorZteCagPassword,
  zteCagTunnelTypeName,
  zteCagUdpControlTypeName,
  zteCagAesCrypt,
  zteCagConnectInfoLength,
  zteCagPasswordBlockLength,
};
