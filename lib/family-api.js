'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const FAMILY_CONFIG = Object.freeze({
  appKey: 'a2c4f80ec311ce63d06a36e269111b505327e0fe9ddb74767e5ef63bc293c5ce',
  appSecretHex: '1ab7eb793c4aeafa5d6b32e4461183eaa16b531ff2b51de14d77c81ff6be8fa6',
  baseUrl: 'https://soho.komect.com',
  terminalPrefix: '/terminal',
  version: '2.23.1',
  versionNum: '2230100',
  releaseNum: '1',
  gitNum: '176005e',
});

const DEFAULT_STATE_FILE = path.join(os.homedir(), '.cmcc-cloud-alive', 'state.json');
const LEGACY_STATE_FILE = '/etc/yidongyun/state.json';

class FamilyApiError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'FamilyApiError';
    Object.assign(this, details);
  }
}

function stateFileFromEnv() {
  return process.env.CMCC_ALIVE_STATE || DEFAULT_STATE_FILE;
}

function readJsonIfExists(file) {
  try {
    if (!file || !fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new FamilyApiError(`failed to read state ${file}: ${err.message}`, { kind: 'state', cause: err });
  }
}

function loadState(opts = {}) {
  const stateFile = opts.stateFile || stateFileFromEnv();
  const state = readJsonIfExists(stateFile);
  if (state) return { ...state, _stateFile: stateFile, _stateSource: 'primary' };
  if (opts.legacyFallback !== false) {
    const legacy = readJsonIfExists(opts.legacyStateFile || LEGACY_STATE_FILE);
    if (legacy) {
      return { ...legacy, _stateFile: stateFile, _stateSource: 'legacyFallback' };
    }
  }
  return { _stateFile: stateFile, _stateSource: 'empty' };
}

function saveState(next, opts = {}) {
  const stateFile = opts.stateFile || stateFileFromEnv();
  const clean = { ...next };
  delete clean._stateFile;
  delete clean._stateSource;
  fs.mkdirSync(path.dirname(stateFile), { recursive: true });
  fs.writeFileSync(stateFile, `${JSON.stringify(clean, null, 2)}\n`, { mode: 0o600 });
  return { ...clean, _stateFile: stateFile, _stateSource: 'primary' };
}

function mergeState(patch, opts = {}) {
  return saveState({ ...loadState(opts), ...patch }, opts);
}

function maskPhone(phone) {
  return String(phone || '').replace(/(1[3-9]\d)\d{4}(\d{4})/, '$1****$2');
}

function maskState(state = {}) {
  const safe = { ...state };
  for (const key of ['sohoToken', 'publicKey']) {
    if (safe[key]) safe[key] = '***';
  }
  if (safe.phone) safe.phone = maskPhone(safe.phone);
  delete safe._stateFile;
  delete safe._stateSource;
  return safe;
}

function ymd(date = new Date()) {
  return `${String(date.getMonth() + 1).padStart(2, '0')}${String(date.getDate()).padStart(2, '0')}`;
}

function randId(len = 32) {
  return crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
}

function defaultDeviceId() {
  const host = os.hostname() || 'linux';
  const ifaces = os.networkInterfaces();
  let mac = '00:00:00:00:00:00';
  for (const values of Object.values(ifaces)) {
    for (const iface of values || []) {
      if (!iface.internal && iface.mac && iface.mac !== '00:00:00:00:00:00') {
        mac = iface.mac;
        break;
      }
    }
    if (mac !== '00:00:00:00:00:00') break;
  }
  return `${host}-${mac}`;
}

function createSign(method, urlPath, header, body, config = FAMILY_CONFIG) {
  const parts = [];
  for (const key of Object.keys(header)) {
    if (header[key]) parts.push(`${key}=${header[key]}`);
  }
  let signing = `${method}&${urlPath}&${parts.join('&')}`;
  let encoded = JSON.stringify(body || {});
  if (encoded && encoded !== '{}') {
    if (encoded.includes('{')) {
      encoded = JSON.parse(encoded);
      signing += `&body=${encoded.data}`;
    } else {
      signing += `&${encoded}`;
    }
  }
  return crypto
    .createHmac('sha256', Buffer.from(config.appSecretHex, 'hex'))
    .update(signing, 'utf8')
    .digest('hex');
}

function getHeaders(state, urlPath, method, body, config = FAMILY_CONFIG) {
  const platform = 'Linux';
  const timestamp = String(Date.now());
  const deviceId = state.deviceId || defaultDeviceId();
  const header = {
    'X-SOHO-AppKey': config.appKey,
    'X-SOHO-AppType': state.appType || `${platform}|${config.version}|${platform}|-1|-1|${deviceId}|`,
    'X-SOHO-ClientVersion': config.version,
    'X-SOHO-DeviceId': deviceId,
    'X-SOHO-RomVersion': state.romVersion || `${platform}-${config.version}`,
    'X-SOHO-SohoToken': state.sohoToken || '',
    'X-SOHO-Timestamp': timestamp,
    'X-SOHO-UserId': state.userId || '',
    'X-SOHO-Uuid': randId(32),
    'X-SOHO-VersionNum': config.versionNum,
  };
  return {
    ...header,
    'Content-Type': 'application/json',
    'User-Agent': `jtydn-${platform}-${config.version}(${config.releaseNum}.${config.gitNum}.${ymd()})`,
    'X-SOHO-Signature': createSign(method, urlPath, header, body, config),
  };
}

function rsaEncryptBody(data, publicKeyBody) {
  const raw = Buffer.from(JSON.stringify(data), 'utf8');
  const chunks = [];
  const publicKey = `-----BEGIN PUBLIC KEY-----\n${publicKeyBody}\n-----END PUBLIC KEY-----`;
  for (let i = 0; i < Math.ceil(raw.length / 117); i++) {
    const part = raw.subarray(i * 117, (i + 1) * 117);
    const padded = Buffer.concat([Buffer.alloc(128 - part.length), part]);
    chunks.push(crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_NO_PADDING }, padded));
  }
  return { data: Buffer.concat(chunks).toString('base64') };
}

function isSuccessResponse(response) {
  return Number(response?.code) === 2000 || response?.msg === 'SUCCESS';
}

function isOtherLoginResponse(response) {
  return Number(response?.code) === 4043 || Number(response?.businessCode) === 4043;
}

function isHeartbeatAccepted(response) {
  return response && !isOtherLoginResponse(response);
}

function assertBusinessOk(response, context) {
  if (isSuccessResponse(response)) return response;
  throw new FamilyApiError(`${context} business failed: ${response?.code ?? '-'} ${response?.msg || ''}`.trim(), {
    kind: 'business',
    code: response?.code,
    businessCode: response?.businessCode,
    response,
  });
}

async function request(urlPath, data, opts = {}) {
  const config = opts.config || FAMILY_CONFIG;
  const state = opts.state || loadState(opts);
  let body;
  if (data !== null && data !== undefined) {
    if (!state.publicKey) {
      throw new FamilyApiError('missing publicKey; run sms-send first or import a logged-in legacy state', {
        kind: 'state',
      });
    }
    body = rsaEncryptBody(data, state.publicKey);
  }
  const method = opts.method || 'POST';
  const fullUrl = `${config.baseUrl}${config.terminalPrefix}${urlPath}`;
  let res;
  try {
    res = await fetch(fullUrl, {
      method,
      headers: getHeaders(state, urlPath, method, body, config),
      body: body ? JSON.stringify(body) : undefined,
      signal: opts.signal,
    });
  } catch (err) {
    const cause = err.cause || {};
    const detail = [
      cause.code,
      cause.syscall,
      cause.hostname || cause.host,
      cause.address,
      cause.port,
      cause.message,
    ].filter(Boolean).join(' ');
    throw new FamilyApiError(`network failed: ${fullUrl}${detail ? ` (${detail})` : ''}`, {
      kind: 'network',
      cause: err,
    });
  }

  const text = await res.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new FamilyApiError(`non-json response ${res.status}: ${text.slice(0, 200)}`, {
      kind: 'http',
      status: res.status,
      body: text,
      cause: err,
    });
  }
  if (!res.ok) {
    throw new FamilyApiError(`http ${res.status}: ${JSON.stringify(parsed)}`, {
      kind: 'http',
      status: res.status,
      response: parsed,
    });
  }
  return parsed;
}

async function ensurePublicKey(opts = {}) {
  const state = loadState(opts);
  if (state.publicKey) return state.publicKey;
  const response = await request('/login/encryptKey/v1', null, opts);
  assertBusinessOk(response, 'encryptKey');
  mergeState({ publicKey: response.data, deviceId: state.deviceId || defaultDeviceId() }, opts);
  return response.data;
}

async function smsSend(phone, opts = {}) {
  if (!phone) throw new FamilyApiError('missing phone', { kind: 'usage' });
  await ensurePublicKey(opts);
  return request('/login/sms/send/v1', { phone }, opts);
}

async function smsLogin(phone, smsCode, opts = {}) {
  if (!phone || !smsCode) {
    throw new FamilyApiError('usage: sms-login <phone> <code>', { kind: 'usage' });
  }
  await ensurePublicKey(opts);
  const response = await request('/login/sms/login/v1', { phone, smsCode }, opts);
  assertBusinessOk(response, 'smsLogin');
  const user = response.data || {};
  mergeState({
    userId: user.userId,
    nickname: user.nickname || '',
    phone: user.phone || phone,
    sohoToken: user.sohoToken,
    username: user.username,
    isLogined: true,
  }, opts);
  return response;
}

async function listClouds(opts = {}) {
  const response = await request('/cc/cloudPc/list/v6', { pageNum: 1 }, opts);
  assertBusinessOk(response, 'listClouds');
  const list = response.data?.list || [];
  mergeState({
    lastCloudListAt: new Date().toISOString(),
    cloudList: list,
  }, opts);
  return list;
}

function findCloudByUserServiceId(list = [], userServiceId) {
  const id = String(userServiceId || '');
  return list.find((item) => String(item.userServiceId || '') === id) || null;
}

function summarizeCloud(item = null) {
  if (!item) return null;
  return {
    userServiceId: item.userServiceId,
    vmName: item.vmName || item.cloudPcName || '',
    spuCode: item.spuCode || '',
    skuName: item.skuName || '',
    serviceStatus: item.serviceStatus,
    activeStatus: item.activeStatus,
    activate: item.activate,
    expiredStatus: item.expiredStatus,
    vmType: item.vmType,
    vmStatus: item.vmStatus,
    vmStatusShow: item.vmStatusShow || '',
    consumeTime: item.consumeTime,
    shutDownInterval: item.shutDownInterval,
  };
}

async function cloudStatus(userServiceId, opts = {}) {
  const list = await listClouds(opts);
  const item = userServiceId ? findCloudByUserServiceId(list, userServiceId) : list[0] || null;
  return summarizeCloud(item);
}

async function tokenCheck(opts = {}) {
  return request('/token/checkToken/v1', {}, opts);
}

async function heartbeat(userServiceId, opts = {}) {
  if (!userServiceId) throw new FamilyApiError('missing userServiceId', { kind: 'usage' });
  const response = await request('/cc/cloudPc/heartbeat/v2', { userServiceId }, opts);
  if (isOtherLoginResponse(response)) {
    throw new FamilyApiError('heartbeat returned YUN_OTHER_LOGIN/4043', {
      kind: 'business',
      code: response?.code,
      businessCode: response?.businessCode,
      response,
    });
  }
  mergeState({
    lastHeartbeatAt: new Date().toISOString(),
    lastHeartbeatUserServiceId: String(userServiceId),
    lastHeartbeatResponse: {
      code: response.code,
      msg: response.msg,
      businessCode: response.businessCode || '',
      acceptedByClientLogic: isHeartbeatAccepted(response),
    },
  }, opts);
  return response;
}

function cachedCloudList(opts = {}) {
  return loadState(opts).cloudList || [];
}

function importLegacyState(opts = {}) {
  const source = opts.legacyStateFile || LEGACY_STATE_FILE;
  const legacy = readJsonIfExists(source);
  if (!legacy) throw new FamilyApiError(`legacy state not found: ${source}`, { kind: 'state' });
  return saveState(legacy, opts);
}

module.exports = {
  DEFAULT_STATE_FILE,
  FAMILY_CONFIG,
  LEGACY_STATE_FILE,
  FamilyApiError,
  assertBusinessOk,
  cachedCloudList,
  createSign,
  defaultDeviceId,
  ensurePublicKey,
  findCloudByUserServiceId,
  getHeaders,
  heartbeat,
  importLegacyState,
  isHeartbeatAccepted,
  isOtherLoginResponse,
  isSuccessResponse,
  cloudStatus,
  listClouds,
  loadState,
  maskPhone,
  maskState,
  mergeState,
  randId,
  request,
  rsaEncryptBody,
  saveState,
  smsLogin,
  smsSend,
  stateFileFromEnv,
  summarizeCloud,
  tokenCheck,
  ymd,
};
