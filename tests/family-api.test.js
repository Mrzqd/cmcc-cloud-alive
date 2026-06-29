'use strict';

const assert = require('assert');

const {
  FamilyApiError,
  assertBusinessOk,
  createSign,
  findCloudByUserServiceId,
  isHeartbeatAccepted,
  isOtherLoginResponse,
  isSuccessResponse,
  maskPhone,
  maskState,
  summarizeCloud,
} = require('../lib/family-api');

assert.strictEqual(maskPhone('18701080357'), '187****0357');
assert.deepStrictEqual(maskState({
  phone: '18701080357',
  sohoToken: 'token',
  publicKey: 'key',
  userId: 'u1',
  _stateFile: '/tmp/state.json',
  _stateSource: 'primary',
}), {
  phone: '187****0357',
  sohoToken: '***',
  publicKey: '***',
  userId: 'u1',
});

assert.strictEqual(isSuccessResponse({ code: 2000, msg: 'SUCCESS' }), true);
assert.strictEqual(isSuccessResponse({ code: 4043, msg: 'YUN_OTHER_LOGIN' }), false);
assert.strictEqual(isOtherLoginResponse({ code: 4043, msg: 'YUN_OTHER_LOGIN' }), true);
assert.strictEqual(isOtherLoginResponse({ code: 4041, msg: '当前云电脑处于解锁状态,且无密码' }), false);
assert.strictEqual(isHeartbeatAccepted({ code: 4041, msg: '当前云电脑处于解锁状态,且无密码' }), true);
assert.strictEqual(isHeartbeatAccepted({ code: 4043, msg: 'YUN_OTHER_LOGIN' }), false);
const cloudList = [
  { userServiceId: 1, vmName: 'a', vmStatus: 1, vmStatusShow: '运行中' },
  { userServiceId: 2663816, vmName: '家庭云电脑', spuCode: 'zte-cloud-pc', skuName: '家庭版', vmStatus: 16, vmStatusShow: '已关机', serviceStatus: 1 },
];
assert.strictEqual(findCloudByUserServiceId(cloudList, '2663816').vmStatusShow, '已关机');
assert.deepStrictEqual(summarizeCloud(cloudList[1]), {
  userServiceId: 2663816,
  vmName: '家庭云电脑',
  spuCode: 'zte-cloud-pc',
  skuName: '家庭版',
  serviceStatus: 1,
  activeStatus: undefined,
  activate: undefined,
  expiredStatus: undefined,
  vmType: undefined,
  vmStatus: 16,
  vmStatusShow: '已关机',
  consumeTime: undefined,
  shutDownInterval: undefined,
});
assert.strictEqual(assertBusinessOk({ code: 2000, msg: 'SUCCESS' }, 'ok').code, 2000);
assert.throws(
  () => assertBusinessOk({ code: 4043, msg: 'YUN_OTHER_LOGIN', businessCode: '4043' }, 'heartbeat'),
  (err) => err instanceof FamilyApiError &&
    err.kind === 'business' &&
    err.code === 4043 &&
    err.response.msg === 'YUN_OTHER_LOGIN',
);

const header = {
  'X-SOHO-AppKey': 'app-key',
  'X-SOHO-Timestamp': '1',
  'X-SOHO-UserId': 'u1',
};
const body = { data: 'encrypted-body' };
const signA = createSign('POST', '/cc/cloudPc/heartbeat/v2', header, body, {
  appSecretHex: '00'.repeat(32),
});
const signB = createSign('POST', '/cc/cloudPc/heartbeat/v2', header, { data: 'changed' }, {
  appSecretHex: '00'.repeat(32),
});
assert.match(signA, /^[0-9a-f]{64}$/);
assert.notStrictEqual(signA, signB);

console.log('family-api tests passed');
