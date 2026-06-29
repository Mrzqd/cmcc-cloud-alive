# Protocol keepalive

This document tracks the protocol-level keepalive work. It is intentionally separate from the existing Ubuntu VM legacy SDK mode.

## Target

Protocol mode must not start `bootCypc` or `uSmartView_VDI_Client`.

The success signal is:

```text
SCG/CAG auth
TLS
ChuanyunHead framed SPICE main channel
ChuanyunHead framed SPICE display channel
DISPLAY_INIT sent
SURFACE_CREATE / DRAW_COPY / MARK observed
SET_ACK and PING/PONG handled while holding the session
```

`connectDesktop ret val: 0` is only an SDK-mode signal and is not protocol-level proof.

The implementation target is not limited to the macOS/blog route. The blog is used as protocol evidence for the success boundary: a real keepalive must reach the SPICE display channel, send `DISPLAY_INIT`, and observe display surface traffic. The current tested account uses a Linux/ZTE CAG route, so Linux CAG/ZIME reverse engineering is a first-class path, not a fallback after macOS SCG.

Official client binaries may be used during research only as an oracle for captures and local plaintext extraction. Production protocol mode must replace them with Node protocol code and must fail closed before sending uncertain auth/SPICE packets.

## Current Evidence

The Linux client in `/opt/yidongyun/client/opt/chuanyun-vdi-client/resources/app.asar` uses:

```text
/cc/getFirmAuth/v1
```

The renderer passes the response data directly to the ZTE worker:

```text
vmUserName
vmPassword
vmId
vmcIp / vmcPort
cagIp / cagPort
scgIp / scgTcpPort / scgUdpPort
scAuthCode
bizCode
```

On the tested account, `getFirmAuth` returns `bizCode`, CAG target `111.31.3.182:8899`, and an SDK credential carried as `vmPassword`; `scgIp/scgTcpPort` are empty. This differs from the macOS CEM chain described in the blog, so protocol mode must either prove that Linux `getFirmAuth` is equivalent to `getConnectInfo`, or add the CEM chain when required by another client variant.

The new project exposes this as a redacted, no-SDK command:

```bash
sudo node bin/cmcc-cloud-alive.js firm-auth 2663816
```

Observed on 2026-06-30:

```json
{
  "summary": {
    "vmId": "163c68a9-5e1e-4cba-b9bb-68ad599a8abf",
    "spuCode": "zte-cloud-pc",
    "vmcIp": "10.10.2.243",
    "vmcPort": 8443,
    "cagIp": "111.31.3.182",
    "cagPort": 8899,
    "scgIp": "",
    "scgTcpPort": "",
    "hasVmUserName": true,
    "hasVmPassword": true,
    "hasBizCode": true
  },
  "route": {
    "route": "linux-cag",
    "source": "cag",
    "host": "111.31.3.182",
    "port": 8899
  }
}
```

After this command, process and socket checks showed no official client process
and no open connection to `111.31.3.182:8899`. This confirms `getFirmAuth` is
safe as a protocol-material probe, but it is not a keepalive signal. The
returned redacted route remains the Linux CAG/ZIME route, not the blog's SCG
10800 route.

The route can also be probed without sending desktop auth:

```bash
sudo node bin/cmcc-cloud-alive.js protocol-probe 2663816 --tls-probe 1 --timeout-ms 5000
```

Observed CAG TLS result on 2026-06-30:

```json
{
  "route": {
    "route": "linux-cag",
    "host": "111.31.3.182",
    "port": 8899
  },
  "connectInfo": {
    "accessCredentialPresent": true,
    "accessCredentialSource": "vmPassword",
    "scAuthCodePresent": false,
    "vmPasswordAsCredential": true,
    "bizCodePresent": true
  },
  "safe": {
    "sdkStarted": false,
    "desktopConnectSent": false,
    "spiceAuthSent": false
  },
  "cagTcpTls": {
    "protocol": "TLSv1.2",
    "cipher": {
      "standardName": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    },
    "peerSubject": {
      "C": "CN",
      "ST": "JS",
      "O": "ZTE",
      "OU": "SOFT",
      "CN": "DC"
    },
    "fingerprint256": "18:74:AB:57:07:03:11:D9:CB:4C:62:43:54:FE:A4:E9:69:E6:B4:EE:D6:EC:29:21:03:42:39:5B:4E:6D:CA:83"
  }
}
```

Follow-up process/socket checks again showed no official client process and no
remaining open connection to `111.31.3.182:8899`. This safely proves the gateway
is a reachable TLS endpoint, but still does not send the CAG/ZIME auth/control
sequence.

The first CAG control packets can now be planned offline without network send:

```bash
sudo node bin/cmcc-cloud-alive.js cag-plan 2663816 \
  --random-key 0x05297b44 \
  --client-key 00112233445566778899aabbccddeeff \
  --trace-id 00112233445566778899aabbccddeeff \
  --span-id 0011223344556677 \
  --server-key 0x4f21c3da \
  --tunnel-id 0x34db0787 \
  --aes-flags 1
```

Observed offline plan:

```json
{
  "safe": {
    "sendsPackets": false,
    "sdkStarted": false,
    "desktopConnectSent": false,
    "spiceAuthSent": false
  },
  "localKey": {
    "type": "local_key",
    "randomKeyHex": "0x05297b44",
    "routeIdHex": "000000447b2905",
    "datagram": {
      "length": 199,
      "sha256": "8a612448ab3ad6802d7b293bc6a8f63b00be4fb898fe6aabe5f740aabcf1a298"
    },
    "connectInfoLength": 220
  },
  "connectInfo": {
    "type": "connect_info",
    "datagram": {
      "length": 241,
      "sha256": "236db48d9d5124d775d76041686bd2da5dfef73d08a48d62c253e79803c52ad5"
    },
    "payloadLength": 220,
    "vmcIp": "10.10.2.243",
    "vmcPort": 8443,
    "usernamePresent": true,
    "passwordPresent": true
  }
}
```

This is an implementation step toward native CAG/ZIME send: the project can now
construct the observed `local_key` layout exactly for fixed test vectors and
construct a `connect_info` datagram from `getFirmAuth` plus captured server
key/tunnel id. It is still fail-closed: `cag-plan` only prints lengths, hashes,
and non-secret metadata by default.

## Family HTTP Heartbeat Candidate

The installed family Linux client was audited locally from:

```text
/opt/yidongyun/client/opt/chuanyun-vdi-client/resources/app.asar
```

The family client constants include:

```text
BASE_URL: https://soho.komect.com
GET_CLOUD: /cc/cloudPc/list/v6
HEART_BEAT: /cc/cloudPc/heartbeat/v2
TIME_ZONE_HEART_BEAT: /timeZone/heartbeat/v1
YUN_OTHER_LOGIN: 4043
```

The normal cloud-PC heartbeat function sends only:

```js
request({
  url: CONSTANTS.URL.HEART_BEAT,
  data: { userServiceId }
})
```

The family client source treats `4043` as the important stop/kick signal:

```text
if d.code == YUN_OTHER_LOGIN:
  alert/disconnect
  return

otherwise:
  schedule the next heartbeat timer
```

Therefore this project must not use the generic `code === 2000` rule for this
endpoint. For `/cc/cloudPc/heartbeat/v2`, the current client-aligned acceptance
rule is:

```text
JSON response received and code/businessCode is not 4043
```

This is intentionally different from login/list endpoints, where non-2000
business codes remain failures and must be surfaced directly instead of being
converted into network/failover errors.

Long-running `heartbeat-loop` mirrors that endpoint-specific behavior:

```text
4043 / YUN_OTHER_LOGIN -> stop and surface the response
network/fetch/http transient error -> log, count failure, retry next interval
other JSON response -> record code/msg/businessCode and schedule next interval
```

This is required for a real keepalive loop. A temporary `fetch failed` must not
turn into "保活失败，已自动停止" unless the operator explicitly uses
`--stop-on-error 1` for debugging.

Local verification on 2026-06-30 using the existing family account state:

```bash
sudo node bin/cmcc-cloud-alive.js list
sudo node bin/cmcc-cloud-alive.js heartbeat 2663816
```

Observed response:

```json
{
  "acceptedByClientLogic": true,
  "code": 4041,
  "msg": "当前云电脑处于解锁状态,且无密码",
  "businessCode": "90020129"
}
```

This call did not start `bootCypc`, `uSmartView_VDI_Client`, CAG, ZIME, or SPICE
traffic. It is a strong candidate for a non-occupying family-edition HTTP
keepalive, but it is not yet final proof. The remaining proof is a long-duration
run showing that this HTTP heartbeat alone prevents sleep and does not kick an
active official client session.

Additional short-loop verification on 2026-06-30:

```text
host:
  timeout 12s sudo node bin/cmcc-cloud-alive.js heartbeat-loop 2663816 --interval-ms 5000
  observed 3 accepted heartbeat responses at 5-second cadence

docker:
  timeout 12s docker run --rm \
    -v /etc/yidongyun/state.json:/etc/yidongyun/state.json:ro \
    cmcc-cloud-alive:local heartbeat-loop 2663816 --interval-ms 5000
  observed 3 accepted heartbeat responses at 5-second cadence
```

Both paths produced full Asia/Shanghai timestamps and elapsed-duration logs.
The Docker path used a read-only legacy state bind mount for verification only;
normal container use should log in through `sms-send` and `sms-login` into the
named state volume.

The `verify-http` command now turns this into a repeatable evidence report:

```bash
sudo node bin/cmcc-cloud-alive.js verify-http 2663816 \
  --duration-ms 15000 --interval-ms 5000
```

For final HTTP-route proof, the command must be run with a powered/running VM,
longer than the expected idle window, and with the strict proof gate enabled:

```bash
sudo node bin/cmcc-cloud-alive.js verify-http 2663816 \
  --duration-ms 3600000 \
  --interval-ms 30000 \
  --wait-powered-ms 600000 \
  --require-sleep-proof 1 \
  --report-file ./reports/http-proof.json
```

`--wait-powered-ms` is a precheck window. It polls `cloud-status`; the proof
timer starts only after the VM is powered/running. If the VM remains `已关机`,
the command exits non-zero and writes a report explaining that the proof did
not start.

In strict mode the command exits non-zero unless:

```text
httpPathOk=true
all cloud status snapshots are powered/running
durationMs >= minProofDurationMs
no official client process is started
no CAG 8899 packets/connections are observed
```

Observed on 2026-06-30:

```json
{
  "acceptedCount": 3,
  "errorCount": 0,
  "stoppedByOtherLogin": false,
  "cloudStatusBefore": {
    "vmStatus": 16,
    "vmStatusShow": "已关机"
  },
  "cloudStatusAfter": {
    "vmStatus": 16,
    "vmStatusShow": "已关机"
  },
  "officialProcessesBefore": [],
  "officialProcessesAfter": [],
  "cagConnectionsBefore": [],
  "cagConnectionsAfter": [],
  "tcpdump": {
    "packetLines": [],
    "stderr": "0 packets captured"
  },
  "noOfficialClientStarted": true,
  "noCagConnectionObserved": true,
  "httpPathOk": true,
  "poweredStatusSnapshots": 0,
  "sleepPreventionProof": false,
  "ok": true
}
```

This evidence proves the short-run HTTP heartbeat path is not the old SDK
wrapper and does not occupy the observed Linux CAG/ZIME route. It also proves
why the current response must not be overclaimed: the account's cloud PC was
already `已关机`, so accepted HTTP heartbeat responses do not prove sleep
prevention. The remaining claim is behavioral: the VM must be powered/running,
stay awake beyond the normal idle window, and the normal official client must
not be kicked during concurrent use.

## Upstream Repository Audit

The repository at `https://github.com/gjz518/yidongyun` was reviewed on 2026-06-30:

```text
refs/heads/main -> b0fc93d Document Ubuntu VM legacy keepalive
```

It contains only the legacy CLI, install scripts, README, changelog, and Ubuntu VM legacy documentation. Full-text search found no implementation of:

```text
DISPLAY_INIT
SURFACE_CREATE
DRAW_COPY
MARK
SET_ACK
PING/PONG
REDQ
ChuanyunHead
SpiceLink
```

The upstream CLI starts the official SDK process `bootCypc` and sends SDK socket commands with `vmUserName`, `vmPassword`, `vmID`, `vmcIP/vmcPort`, and `cagIP/cagPort`. Therefore that repository is useful evidence for the SOHO API and legacy SDK fallback path, but it is not the blog's protocol-level keepalive implementation. It cannot be counted as protocol success because it depends on the official client process and does not independently send `DISPLAY_INIT` or observe display surface messages.

This was rechecked against a fresh shallow clone on 2026-06-30. The only protocol-adjacent source hits are `/cc/getFirmAuth/v1`, `bootCypc`, and SDK socket fields such as `cagIP`/`cagPort`. There is still no direct implementation of the blog's SCG auth, Chuanyun trunk, REDQ, or SPICE display flow in that repository.

## Capture Evidence

A short SDK run was captured with:

```bash
sudo tcpdump -i ens3 -nn -s 0 -U -w /tmp/yidongyun-cag-8899.pcap 'host 111.31.3.182 and port 8899'
sudo node bin/yidongyun.js keepalive --mode sdk --index 0 --duration 15
```

Observed transport:

```text
TCP 192.168.1.48:* -> 111.31.3.182:8899
  first payload: TLS ClientHello
  server certificate subject: C=CN, ST=JS, O=ZTE, OU=SOFT, CN=DC

UDP 192.168.1.48:* -> 111.31.3.182:8899
  early packet contains ASCII magic: ZTEC
  later packets contain a 24-byte tunnel header followed by TLS records
```

The observed UDP/CAG branch uses `connect_to_access_gateway_opentelemetry`, not the smaller 0x2c local-key path. The real local-key packet appears inside a 21-byte UDP control wrapper:

```text
outer UDP payload length: 199
outer ZTEC offset: 21
inner packet: ZTEC + length 0x00ac + 172-byte body
firstWord: 0x65
randomKey: 0x2f4bd52a
connectInfoLength: 0xdc
flags: 0x0b0b0004
traceId: 89d445d22658b6a6553f6cdedd39f518
spanId: 7ed90069beaa2181
```

Example UDP tunnel payload from the capture:

```text
e1db878d 81000150 00000000 00000000 00000005 02000000
1603010200...
```

This is not the same byte layout as the blog's SCG `10800` AES-then-TLS path. The current Linux/ZTE client appears to use a CAG `8899` variant with TCP TLS plus UDP ZTEC/tunnel traffic. The high-level target remains the same: reach the display channel far enough to send `DISPLAY_INIT` and observe Surface/screen messages without starting the official client.

The CAG connect-info packet is now partially reproduced offline from the capture:

```text
UDP control header: 21 bytes
RADIUS connect-info body: 0xdc bytes
[0x00:0x02] destination port, little-endian
[0x04:0x14] IPv4 address in a 16-byte field
[0x14:0x3c] VM ID, fixed ASCII field
[0x3c:0x7c] AES credential block for vmUserName
[0x7c:0xbc] AES credential block for vmPassword
[0xbc:0xdc] flags/reserved tail
```

The captured username block decrypts to the expected `vmUserName` when using `randomKey=0x2f4bd52a`, `serverKey=0x4ded5776`, and `aesFlags=1`. This reproduces the non-sensitive header and username bytes exactly. The password block is intentionally not written into tests or documentation.

One important unresolved detail: the captured server-key ZTEC packet carries flags that map to `0x102` in the TCP `recv_access_gateway_key` routine, but the captured connect-info credential block is reproduced with `aesFlags=1`. This means the UDP/opentelemetry path cannot safely be reduced to the TCP local-key parser yet. Real network send code must stay disabled until this mapping and the tunnel sequencing are fully explained.

The 24-byte tunnel header is now parsed conservatively:

```text
[0x00:0x04] magic = e1db878d
[0x04]      packet type
[0x05]      flag/sequence byte
[0x06:0x08] 16-bit sequence-like field
[0x08:0x18] five opaque 32-bit words total including word2..word5
[0x18:]     payload
```

Observed packet types in the current capture:

```text
0x81 data-bearing packets; often carry TLS records or encrypted application data
0x82 control packets
0x85 batch/retransmit-like server packets
0x86 24-byte ACK-like packets with no payload
0x87 server control packets
0x89 client control/heartbeat-like packets
```

For simple `0x81`/`0x89` packets, `word4` often equals the payload length; for TLS and batch/retransmit packets it does not, so `word4` must not be treated as a universal length field.

Native library search found `libZIMEDataEngine.so` with LSQUIC, SCTP, data-channel, packet-out, and UDP byte accounting symbols, plus `SCGDir/sdk_config.json` containing `retransmit`, `ack_loop_period`, and `udp_session_timeout` settings. That is strong evidence that the observed CAG `8899` UDP stream is mediated by the ZIME data engine rather than a trivial custom UDP wrapper. The next implementation step should therefore target ZIME framing/transport behavior or capture local plaintext before ZIME encapsulation, not invent a sender from only the 24-byte tunnel header.

Loopback plaintext capture from a short official SDK run shows the local GSpice-to-proxy streams clearly:

```text
client -> local proxy:
  164-byte ExtInfo preface
  REDQ SpiceLinkMess

local proxy -> client:
  1-byte local channel prefix
  REDQ SpiceLinkReply
  4-byte auth result
  SPICE full data messages
```

Confirmed stream examples from `/tmp/yidongyun-loopback-spice.pcap`:

```text
43390->42323 main client stream:
  ExtInfo channelClass=1, field9e=1, REDQ at offset 164
  SpiceLinkMess channelType=1, connectionId=0, linkSize=713

42323->43390 main server stream:
  channelPrefix=1, replySize=322, DER pubkey length=294
  auth result=0
  first data message: MAIN_INIT, serial=1, size=64

43398->42323 display client stream:
  ExtInfo channelClass=3, field9e=2, REDQ at offset 164
  SpiceLinkMess channelType=2, connectionId=757708470, linkSize=717
  first client data frame after auth: DISPLAY_INIT, serial=1, size=19

42323->43398 display server stream:
  channelPrefix=2, replySize=194, DER pubkey length=162
  auth result=0
  first data message: SET_ACK, serial=1, size=8
  early display messages: SET_ACK, SET_ACK, 0x6c, SURFACE_CREATE, MARK
```

This means the Linux route cannot hard-code the blog's 162-byte RSA key assumption or mini-header-only parsing. The protocol layer now supports dynamic DER-length `SpiceLinkReply` parsing and SPICE full data headers.

The loopback analyzer now emits a direct success-evidence line for the observed display channel:

```text
43398->42323 displayInit=true setAck=true surfaceCreate=true mark=true protocolSuccessEvidence=true
```

This proves that the SDK run reached the same protocol-level boundary described by the blog: display auth completed, `DISPLAY_INIT` was sent, and the display server returned surface/render completion signals. It is still capture evidence, not standalone protocol mode, because the SDK produced the traffic.

A later synchronized capture used one SDK run while capturing both loopback and CAG traffic:

```text
/tmp/yidongyun-sync-loopback-20260630-023415.pcap
/tmp/yidongyun-sync-cag-20260630-023415.pcap
/tmp/yidongyun-sync-run-20260630-023415.log
```

The loopback side again proved the display success boundary:

```text
52418->39363 displayInit=true setAck=true surfaceCreate=true mark=true protocolSuccessEvidence=true
events=[
  DISPLAY_INIT 1782758060.527213,
  SET_ACK      1782758060.528531,
  SURFACE_CREATE 1782758060.560831,
  MARK           1782758060.560831
]
```

The simultaneous CAG side showed the same session was carried through Linux/ZTE CAG `8899` using a dynamic 4-byte tunnel magic:

```text
remoteHost=111.31.3.182
tunnel word0 example: 34db0787
tunnelSummary={"total":988,"countsByType":{"data":477,"control":13,"batch_or_retransmit":10,"ack":10,"client_control":478},"tlsRecords":13}
```

This corrects an earlier assumption: the tunnel header first word is not fixed to `e1db878d`. The parser now treats byte 4 as the packet type discriminator and accepts known CAG tunnel types with dynamic `word0`.

The synchronized CAG capture now decodes the UDP control handshake directly:

```text
local_key:
  UDP control type=6
  randomKey=0x05297b44
  connectInfoLength=0xdc
  traceId=bb0ff3ff89ba0d0f0ca7d033a5f8b522

server_key:
  UDP control type=7
  routeId=000000447b2905
  tunnelId=0x34db0787
  serverKey=0x4f21c3da
  flags=0x00000003
  sdkAesFlags=0x102

connect_info:
  UDP control type=8
  tunnelId=0x34db0787
  payloadLength=0xdc

connect_reply:
  UDP control type=9
  tunnelId=0x34db0787
  code=200
```

This establishes the Linux CAG route's first independently parsed state chain:

```text
getFirmAuth -> local_key -> server_key/tunnelId -> connect_info -> connect_reply 200 -> dynamic-tunnel data
```

The standalone sender now reaches the same CAG control-auth boundary without
starting the official SDK:

```text
cmcc-cloud-alive cag-handshake 2663816 --send-connect-info 1
local_key sent
server_key received
connect_info sent
connect_reply code=200
sdkStarted=false
desktopConnectSent=false
spiceAuthSent=false
```

It is still not standalone keepalive. The unresolved boundary is now after
`connect_reply 200`: the ZIME/reliable UDP tunnel must carry TLS/application
data correctly until the SPICE main/display sequence reaches the same
`DISPLAY_INIT` and surface-message success boundary observed on loopback.

On the current account, `cloud-status` reports `vmStatus=16` / `已关机`.
Experimental `--send-ready 1` currently reaches `connect_reply 200` and then
times out waiting for `peer_ready`; a short tcpdump captured the outgoing
`client_ready` but no server reply. This may be because the VM is powered off,
because the ready sequence is derived from `connect_reply`/ZIME state rather
than fixed constants, or because a pre-ZIME control step is still missing.

The official Linux client also sends periodic 26-byte CAG preflight probes on
another UDP source port. The server replies by echoing the 14-byte tail. This is
now parsed by `extract-cag-handshake` as `preflight_probe/preflight_echo`, but
the capture shows it continues periodically after the main handshake, so it is
currently treated as connectivity/NAT evidence rather than proof of a missing
auth step.

Time-window analysis around the synchronized display success window shows the
external CAG/ZIME packet families active during the local SPICE events:

```text
window: 1782758060.500000..1782758060.570000
visiblePackets=59
tunnelSummary={
  "data": 28,
  "control": 23,
  "batch_or_retransmit": 3,
  "ack": 3,
  "client_control": 1
}
```

Notable alignment:

```text
1782758060.527213 loopback client DISPLAY_INIT
1782758060.528531 loopback server SET_ACK
1782758060.560831 loopback server SURFACE_CREATE/MARK

1782758060.526320 cag->client 0x81 data payloadLength=226
1782758060.528324 cag->client 0x81 data payloadLength=34
1782758060.528510 cag->client 0x85 batch/retransmit
1782758060.560509 cag->client 0x81 data payloadLength=146 tlsRecordOffset=140
```

The next reverse-engineering boundary is therefore the CAG/ZIME reliable
transport layer: `0x81` data, short `0x82` controls, `0x85` batch/retransmit,
`0x86` ACK, and `0x89` client control. The parser now handles short 22-byte
`0x82` tunnel controls without misclassifying them as UDP control datagrams.

## Implemented

- `lib/protocol/events.js`: protocol-stage event model and DISPLAY_INIT-level success predicate.
- `lib/protocol/scg.js`: SCG auth plaintext builder, AES-128-CTR helper with caller-supplied key/iv, and the blog-described `[0x01, ciphertext_len % 256, ciphertext]` auth packet wrapper.
- `lib/protocol/cag-tls.js`: CAG TCP TLS probe.
- `lib/protocol/cem.js`: CEM RSA/header helpers and explicit environment-based CEM probe configuration checks.
- `lib/protocol/probe.js`: safe route classification for `blog-scg`, `scg-other`, and `linux-cag`, with no SDK startup and no desktop/SPICE auth packets.
- `lib/family-api.js`: family SOHO API signing/RSA encryption support for SMS login, cloud list caching, token check, and `/cc/cloudPc/heartbeat/v2` with endpoint-specific `4043` stop handling.
- `lib/protocol/zte-cag.js`: observed ZTE CAG UDP `ZTEC`/control/tunnel/TLS-record detector, 21-byte UDP control wrapper encoder/parser, 24-byte tunnel header encoder/parser, 0x2c local-key codec, and opentelemetry 0xac local-key codec verified against captured traffic.
- `lib/protocol/zte-cag.js`: RADIUS connect-info body parser/encoder, CAG credential AES helper, and password XOR helper verified offline against captured non-sensitive fields.
- `lib/protocol/zte-cag.js`: conservative tunnel datagram parser and sequence summarizer for observed `0x81/0x82/0x85/0x86/0x87/0x89` packet families, including dynamic tunnel magic values such as `34db0787`.
- `lib/protocol/zte-cag.js`: UDP control semantic parser for observed `local_key`, `server_key`, `connect_info`, and `connect_reply`, including extraction of dynamic `tunnelId`, server key, AES flags, and connect reply code `200`.
- `lib/protocol/cag-udp-handshake.js`: native UDP sender for `local_key -> server_key` and explicit `--send-connect-info 1` continuation through `connect_reply 200`, with redacted reports and partial-report timeout diagnostics.
- `lib/protocol/chuanyun.js`: 24-byte ChuanyunHead frame codec.
- `lib/protocol/spice.js`: SPICE constants, REDQ link header/request/reply codecs including dynamic DER public-key length, Mini Header codec, full data header codec, DISPLAY_INIT encoder, SET_ACK parser, and ACK/PONG encoders.
- `lib/protocol/local-spice.js`: Linux local GSpice/proxy ExtInfo parser, client `0x0a channel length` frame parser, local prefixed REDQ server reply parser, and padded server full-data-message parser, verified against sanitized loopback capture fragments.
- `scripts/analyze-loopback-spice.js`: loopback pcap analyzer that emits `protocolSuccessEvidence=true` when display `DISPLAY_INIT`, `SET_ACK`, `SURFACE_CREATE`, and `MARK` are all observed.
- `scripts/analyze-loopback-spice.js`: per-event pcap timestamps for local display success signals, used to correlate loopback plaintext with external CAG tunnel packets.
- `scripts/analyze-cag-transport.js`: CAG pcap analyzer that emits TCP/UDP event summaries, ZTEC control packets, dynamic tunnel headers, packet families, TLS-record hints, tunnel counts, and optional `--from/--to` time-window filtering.
- `lib/protocol/connect-info.js`: normalized protocol connect info from `getFirmAuth`.
- `cmcc-cloud-alive protocol-probe`: fetches SOHO `getFirmAuth`, classifies the returned transport route, optionally probes CAG TCP TLS, and redacts credentials in the report.
- `cmcc-cloud-alive cag-handshake`: fetches real auth data and performs the verified native CAG UDP control handshake without SDK startup.
- Web UI scheduler config persists `mode=sdk|protocol`.

## Current Probe Result

`protocol-probe` was run on 2026-06-30 with the current login state:

```text
route: linux-cag
host: 111.31.3.182
port: 8899
protocolAligned: false
reason: getFirmAuth returned Linux/ZTE CAG instead of the blog SCG route
safe.sdkStarted: false
safe.desktopConnectSent: false
safe.spiceAuthSent: false
CAG TCP TLS: TLSv1.2, certificate CN=DC, O=ZTE
```

The report intentionally redacts credential values. This is evidence that the current Linux account path is not directly the blog's SCG `10800` path.

## Extracted Protocol From The Blog

The blog describes one SCG route, not the only valid route:

```text
SOHO token
getFirmAuth -> scAuthCode
CEM oauth/token -> access_token
CEM getConnectInfo -> scgIp:10800 + fresh scAuthCode
TCP SCG auth packet -> AES-128-CTR encrypted payload
STARTTLS/TLS
ChuanyunHead(type=2) welcome -> session_id
ChuanyunHead(type=1, channel=main) + ExtInfo + token + REDQ
RSA ticket auth
MAIN_INIT -> spice_session_id
ClientInfo + ATTACH_CHANNELS
CHANNELS_LIST
ChuanyunHead(type=1, channel=display) + REDQ
RSA ticket auth
DISPLAY_INIT
SET_ACK / SURFACE_CREATE / DRAW_COPY / MARK
PING -> PONG while holding the session
```

The reusable parts already extracted into code are:

```text
SCG auth plaintext layout
AES-128-CTR wrapper with explicit key/iv
ChuanyunHead 24-byte framing
SPICE REDQ link request/reply parsing
SPICE mini-message framing
DISPLAY_INIT payload
SET_ACK / ACK_SYNC / ACK / PING/PONG message shapes
success predicate requiring DISPLAY_INIT plus display surface signals
```

The parts that cannot be extracted from `gjz518/yidongyun` are the core protocol steps after `getFirmAuth`, because that repository delegates them to the official SDK process.

## Route Strategy

The project must support multiple route families behind one protocol-level success definition:

```text
shared goal:
  SPICE main/display auth -> DISPLAY_INIT -> SURFACE_CREATE/DRAW_COPY/MARK

route A: blog/macOS SCG
  CEM getConnectInfo -> SCG 10800 -> AES-CTR auth -> TLS -> ChuanyunHead -> SPICE

route B: observed Linux/ZTE CAG
  getFirmAuth -> CAG 8899 -> ZTEC/control -> ZIME/LSQUIC-like reliable UDP/TLS tunnel -> local SPICE-equivalent plaintext -> DISPLAY_INIT
```

Route A is useful because the blog exposes the clean layered design. Route B is the route observed on the deployed Linux client and therefore must be implemented, not dismissed as a non-blog path.

The safest extraction order for Route B is:

```text
1. Capture official SDK local loopback plaintext.
2. Decode ExtInfo, REDQ, RSA ticket auth, MAIN_INIT, CHANNELS_LIST, DISPLAY_INIT, SET_ACK, PING/PONG.
3. Reproduce the SPICE/Chuanyun payloads offline with deterministic tests.
4. Correlate local plaintext frames to external CAG/ZTEC/ZIME packets.
5. Implement only the parts whose byte layout and state transitions are proven.
```

This avoids guessing tunnel packets from external ciphertext and avoids account-locking mistakes such as sending malformed credential material.

## Atomic Implementation Plan

The protocol mode is not complete until the final verification item passes.

1. Freeze success semantics.
   - Require no `bootCypc` or `uSmartView_VDI_Client` in protocol mode.
   - Require display-channel auth completion.
   - Require `DISPLAY_INIT` to be sent.
   - Require at least two display surface signals from `SURFACE_CREATE`, `DRAW_COPY`, and `MARK`.
   - Require SET_ACK/PING handling during the hold window.
2. Build the Linux local-plaintext oracle.
   - Start the official SDK only in an explicit capture command, never in protocol mode.
   - Capture loopback TCP during a short known-good SDK run.
   - Reconstruct TCP streams by sequence number and direction.
   - Detect per-channel streams by `REDQ`, local port, and channel order from SDK logs.
   - Save sanitized frame summaries as fixtures.
3. Decode the Linux local SPICE preface.
   - Parse the pre-`REDQ` ExtInfo block.
   - Identify channel type, channel id, VM/session fields, and fixed flags.
   - Extract the 16-byte token boundary.
   - Add parser/encoder tests using captured non-secret bytes.
4. Decode main-channel SPICE.
   - Parse client `SpiceLinkMess`.
   - Parse server `SpiceLinkReply`.
   - Decode RSA ticket-auth packet boundaries without storing secrets.
   - Parse auth result.
   - Parse `MAIN_INIT` and extract `spice_session_id`.
   - Parse `CHANNELS_LIST` and confirm display availability.
5. Decode display-channel SPICE.
   - Parse display `SpiceLinkMess` with `connection_id = spice_session_id`.
   - Parse display auth result.
   - Extract the exact official Linux `DISPLAY_INIT` data message: full header type `0x65`, payload size `19`, local client frame `0x0a 0x02`.
   - Parse server full data headers for `SET_ACK`, `SURFACE_CREATE`, `DRAW_COPY`, and `MARK`.
   - Add deterministic tests for these message boundaries.
6. Reproduce local SPICE behavior offline.
   - Implement encoders for ExtInfo, link requests, ticket-auth wrapper, ClientInfo, ATTACH_CHANNELS, and DISPLAY_INIT.
   - Add a fake SPICE server fixture that sends the captured reply sequence.
   - Pass the success predicate without any SDK process.
7. Map Linux local plaintext to external CAG transport.
   - Correlate local channel data sizes/timing with CAG `0x81` data packets.
   - Use the decoded ZTEC 21-byte control wrapper and server-key packets as the CAG session bootstrap.
   - Resolve the opentelemetry server-key flags versus credential AES mode mismatch.
   - Reverse the 24-byte tunnel header sequence, ACK, retransmit, and close semantics.
   - Identify where TLS records sit inside the ZIME/CAG stream.
8. Implement Linux CAG protocol sender.
   - Send only verified CAG control and connect-info packets.
   - Establish the reliable tunnel without SDK.
   - Carry the decoded SPICE main/display flow through the tunnel.
   - Hold the session and respond to SET_ACK/PING.
   - Stop before any step whose packet semantics are not proven.
9. Keep SCG/blog route as a parallel route, not the only path.
   - Add a safe CEM probe for `oauth/token` and `getConnectInfo`.
   - If `scgIp:10800` is available, use the existing SCG AES-CTR and Chuanyun/SPICE modules.
   - Share the same SPICE success predicate with Linux CAG.
10. Define release criteria.
   - `yidongyun keepalive --mode protocol` must not spawn official binaries.
   - Logs must show route, display auth, `DISPLAY_INIT`, surface messages, ACK/PONG counts, and hold duration.
   - A packet capture must show no SDK local socket usage in protocol mode.
   - Cloud VM must remain online past the idle shutdown window.

## Not Implemented

- Extract or verify SCG AES key/iv for the blog `10800` variant.
- Derive or verify the Linux CAG `client_ready/peer_ready` sequence rules in a powered/running VM session.
- Reverse the observed Linux/ZTE CAG UDP reliable datagram sequencing, ACK, retransmission, and close behavior after `connect_reply 200`.
- Reverse the remaining observed 24-byte ZTE CAG tunnel header field semantics and sequencing.
- Reverse or instrument `libZIMEDataEngine.so` enough to understand packet-out, ACK, retransmit, and data-channel callbacks.
- Resolve the UDP/opentelemetry server-key flags versus observed connect-info AES mode mismatch.
- Implement main-channel REDQ/auth/MAIN_INIT/CHANNELS_LIST.
- Implement display-channel REDQ/auth/DISPLAY_INIT flow.
- Parse display messages and respond to SET_ACK/PING.
- Confirm real keepalive by observing SURFACE_CREATE/DRAW_COPY/MARK.

## Next Capture Work

Use `tcpdump` around a short SDK connection to identify the external transport endpoint and packet timing:

```bash
sudo tcpdump -i ens3 -nn -s 0 -w /tmp/yidongyun-cag-8899.pcap host 111.31.3.182 and port 8899
```

This pcap will not reveal TLS plaintext. It is useful for endpoint/timing verification only. Protocol constants still need binary reverse engineering or local plaintext interception before replacing the SDK.
