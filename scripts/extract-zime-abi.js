#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const DEFAULT_LIB =
  '/opt/yidongyun/client/opt/chuanyun-vdi-client/resources/app.asar.unpacked/node_modules/chuanyunAddOn-zte/ccsdk/lib/libZIMEDataEngine.so';

const FUNCTION_WINDOWS = [
  {
    name: 'ZIME_CreateDataEngine',
    start: '0x008b1c0',
    stop: '0x008b1f0',
    evidence: [
      {
        id: 'wrapper_handle_size_0x28',
        needle: 'mov    $0x28,%edi',
        interpretation: 'C wrapper allocates a 0x28-byte handle.',
      },
      {
        id: 'engine_pointer_at_offset_0',
        needle: 'mov    %rax,(%rbx)',
        interpretation: 'The native C++ engine pointer is stored at handle offset 0x0.',
      },
      {
        id: 'handle_zeroed_offsets_0_20',
        needle: 'movq   $0x0,0x20(%rax)',
        interpretation: 'Wrapper-owned fields span through at least offset 0x20.',
      },
    ],
  },
  {
    name: 'ZIME_Init',
    start: '0x008c210',
    stop: '0x008c650',
    evidence: [
      {
        id: 'init_param_cert_string',
        needle: 'mov    0x8(%rsi),%r14',
        interpretation: '_T_ZIMEInitParam offset 0x08 is copied as a pointer-sized string field.',
      },
      {
        id: 'init_param_cert_len',
        needle: 'movzwl 0x10(%rsi),%r12d',
        interpretation: '_T_ZIMEInitParam offset 0x10 is the 16-bit length for the offset-0x08 string.',
      },
      {
        id: 'init_param_private_key_string',
        needle: 'mov    0x28(%rbx),%r15',
        interpretation: '_T_ZIMEInitParam offset 0x28 is another pointer-sized string field.',
      },
      {
        id: 'init_param_private_key_len',
        needle: 'movzwl 0x30(%rbx),%r12d',
        interpretation: '_T_ZIMEInitParam offset 0x30 is the 16-bit length for the offset-0x28 string.',
      },
      {
        id: 'init_param_third_string',
        needle: 'mov    0x18(%rbx),%rax',
        interpretation: '_T_ZIMEInitParam offset 0x18 is a third pointer-sized string field.',
      },
      {
        id: 'init_param_third_len',
        needle: 'movzwl 0x20(%rbx),%r12d',
        interpretation: '_T_ZIMEInitParam offset 0x20 is the 16-bit length for the offset-0x18 string.',
      },
      {
        id: 'init_param_role',
        needle: 'mov    (%rbx),%eax',
        interpretation: '_T_ZIMEInitParam offset 0x00 is copied as a 32-bit role/protocol field.',
      },
      {
        id: 'init_param_support_protocol',
        needle: 'mov    0x38(%rbx),%eax',
        interpretation: '_T_ZIMEInitParam offset 0x38 is copied as a 32-bit support/protocol field.',
      },
      {
        id: 'init_param_flag_0x3c',
        needle: 'movzbl 0x3c(%rbx),%eax',
        interpretation: '_T_ZIMEInitParam offset 0x3c is copied as an 8-bit flag.',
      },
    ],
  },
  {
    name: 'ZIME_ReceiveData',
    start: '0x008b400',
    stop: '0x008b4a0',
    evidence: [
      {
        id: 'socket_param_prefix_copy',
        needle: 'movdqu (%rsi),%xmm0',
        interpretation: '_T_ZIMESocketParam begins with a 16-byte prefix copied from caller memory.',
      },
      {
        id: 'socket_param_body_copy_size_0x200',
        needle: 'mov    $0x200,%esi',
        interpretation: '_T_ZIMESocketParam copies 0x200 bytes from caller offset 0x10.',
      },
      {
        id: 'socket_param_flag_0x50',
        needle: 'movzbl 0x50(%rsi),%ecx',
        interpretation: '_T_ZIMESocketParam offset 0x50 is an 8-bit field read by the wrapper.',
      },
      {
        id: 'receive_data_vtable_0x78',
        needle: 'call   *0x78(%rax)',
        interpretation: 'ReceiveData dispatches to engine vtable offset 0x78.',
      },
    ],
  },
  {
    name: 'ZIME_SendData2',
    start: '0x008b4a0',
    stop: '0x008b540',
    evidence: [
      {
        id: 'senddata2_default_profile_size',
        needle: 'movl   $0x24,(%rsp)',
        interpretation: 'Default _T_ZIMEDataProfile starts with dword 0x24.',
      },
      {
        id: 'profile_offset_0',
        needle: 'mov    (%r9),%r10d',
        interpretation: 'Caller profile offset 0x00 is copied as uint32.',
      },
      {
        id: 'profile_offset_0x8',
        needle: 'mov    0x8(%r9),%r9',
        interpretation: 'Caller profile offset 0x08 is copied as uint64.',
      },
      {
        id: 'profile_offset_0x10',
        needle: 'movzbl 0x10(%r9),%r10d',
        interpretation: 'Caller profile offset 0x10 is copied as uint8.',
      },
      {
        id: 'profile_offset_0x18',
        needle: 'mov    0x18(%r9),%r10',
        interpretation: 'Caller profile offset 0x18 is copied as uint64.',
      },
    ],
  },
  {
    name: 'ZIME_SendData',
    start: '0x008b540',
    stop: '0x008b570',
    evidence: [
      {
        id: 'senddata_null_profile',
        needle: 'xor    %r9d,%r9d',
        interpretation: 'ZIME_SendData calls the same engine send path with a null profile.',
      },
      {
        id: 'senddata_vtable_0x70',
        needle: 'mov    0x70(%rax),%rax',
        interpretation: 'SendData dispatches to engine vtable offset 0x70.',
      },
    ],
  },
  {
    name: 'ZIME_SetDataChannelCallback',
    start: '0x008c060',
    stop: '0x008c100',
    evidence: [
      {
        id: 'callback_impl_stored_handle_0x8',
        needle: 'mov    %r13,0x8(%rbx)',
        interpretation: 'C wrapper stores the callback adapter at handle offset 0x08.',
      },
    ],
  },
  {
    name: 'ZIME_SetDataExternalTransport',
    start: '0x008c100',
    stop: '0x008c1a0',
    evidence: [
      {
        id: 'external_transport_impl_stored_handle_0x18',
        needle: 'mov    %r13,0x18(%rbx)',
        interpretation: 'C wrapper stores the external transport adapter at handle offset 0x18.',
      },
    ],
  },
];

const REQUIRED_C_EXPORTS = [
  'ZIME_CreateDataEngine',
  'ZIME_LogInit',
  'ZIME_SetLogLevel',
  'ZIME_Init',
  'ZIME_SetDataChannelCallback',
  'ZIME_SetDataExternalTransport',
  'ZIME_CreateDataChannel',
  'ZIME_CreateDataStream',
  'ZIME_SendData',
  'ZIME_SendData2',
  'ZIME_ReceiveData',
  'ZIME_DestroyDataStream',
  'ZIME_DestroyDataChannel',
  'ZIME_Release',
];

const OPTIONAL_C_EXPORTS = [
  'ZIME_SetDataTransportBatch',
];

const REQUIRED_STRINGS = [
  'ZIMEDataEngineCore::CreateDataChannel failed, callback[set:%u] or external_transport[set:%d] not set.',
  'ZIME_CreateDataChannel failed, the configured param i_pContext is null.',
  'dc_role[%d] is configured as an illegal value',
  'support_dc_protocol[%d] is configured as an illegal value',
  'packets_out_callback failed',
  'dtls_handshake successfully',
];

function usage() {
  console.error('Usage: node scripts/extract-zime-abi.js [libZIMEDataEngine.so]');
  process.exit(2);
}

function run(command, args, input) {
  const result = spawnSync(command, args, {
    input,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    ok: !result.error && result.status === 0,
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error?.message,
  };
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function parseSymbols(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.match(/^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$/))
    .filter(Boolean)
    .map((match) => ({
      address: `0x${match[1].replace(/^0+/, '') || '0'}`,
      size: Number(match[2]),
      bind: match[3],
      visibility: match[4],
      section: match[5],
      name: match[6].trim(),
    }));
}

function demangle(text) {
  const result = run('c++filt', [], text);
  return result.ok ? result.stdout : text;
}

function disassemble(file, start, stop) {
  const result = run('objdump', ['-d', '--demangle', `--start-address=${start}`, `--stop-address=${stop}`, file]);
  return result.ok ? result.stdout : '';
}

function analyzeDisassembly(file) {
  return FUNCTION_WINDOWS.map((fn) => {
    const disassembly = disassemble(file, fn.start, fn.stop);
    const evidence = fn.evidence.map((item) => ({
      ...item,
      observed: disassembly.includes(item.needle),
    }));
    return {
      name: fn.name,
      window: { start: fn.start, stop: fn.stop },
      allEvidenceObserved: evidence.every((item) => item.observed),
      evidence,
    };
  });
}

function main(argv = process.argv.slice(2)) {
  if (argv.includes('-h') || argv.includes('--help')) usage();
  const lib = path.resolve(argv[0] || DEFAULT_LIB);
  if (!fs.existsSync(lib)) {
    console.log(JSON.stringify({
      lib,
      exists: false,
      error: 'libZIMEDataEngine.so not found; pass an explicit path from the installed family Linux client',
    }, null, 2));
    return;
  }

  const readelf = run('readelf', ['-Ws', lib]);
  const strings = run('strings', ['-a', lib]);
  const demangledSymbols = readelf.ok ? parseSymbols(demangle(readelf.stdout)) : [];
  const cExports = demangledSymbols
    .filter((sym) => sym.bind === 'GLOBAL' && sym.visibility === 'DEFAULT' && /^ZIME_/.test(sym.name))
    .filter((sym, index, list) => list.findIndex((item) => item.name === sym.name && item.address === sym.address) === index)
    .sort((a, b) => a.name.localeCompare(b.name) || a.address.localeCompare(b.address));
  const exportNames = new Set(cExports.map((sym) => sym.name));
  const stringText = strings.stdout || '';

  console.log(JSON.stringify({
    lib,
    exists: true,
    generatedAt: new Date().toISOString(),
    sha256: sha256(lib),
    cWrapperExports: {
      required: REQUIRED_C_EXPORTS.map((name) => ({ name, present: exportNames.has(name) })),
      optional: OPTIONAL_C_EXPORTS.map((name) => ({ name, present: exportNames.has(name) })),
      presentCount: cExports.length,
      exports: cExports,
    },
    disassemblyEvidence: analyzeDisassembly(lib),
    stringEvidence: REQUIRED_STRINGS.map((needle) => ({
      needle,
      present: stringText.includes(needle),
    })),
    inferredAbi: {
      handle: {
        size: '0x28',
        offsets: {
          '0x00': 'ZIMEDataEngineImpl/ZIMEDataEngine C++ pointer',
          '0x08': 'DataChannelCallback C adapter pointer',
          '0x18': 'ExternalTransport C adapter pointer',
          '0x20': 'wrapper-owned nullable field',
        },
        confidence: 'disassembly-observed',
      },
      initParam: {
        '0x00': 'uint32 role/protocol-like field',
        '0x08/0x10': 'string pointer + uint16 length',
        '0x18/0x20': 'string pointer + uint16 length',
        '0x28/0x30': 'string pointer + uint16 length',
        '0x32': 'uint8 flag copied by wrapper',
        '0x38': 'uint32 support/protocol-like field',
        '0x3c': 'uint8 flag copied by wrapper',
        confidence: 'disassembly-observed; semantic names still require harness validation',
      },
      socketParam: {
        minimumCallerReadableBytes: '0x211',
        fields: {
          '0x00..0x0f': '16-byte prefix copied as-is',
          '0x10..0x20f': '0x200-byte address/body area copied by zte_memcpy_s',
          '0x50': 'uint8 field read by wrapper',
        },
        confidence: 'disassembly-observed',
      },
      dataProfile: {
        defaultFirstDword: '0x24',
        copiedCallerOffsets: ['0x00 uint32', '0x08 uint64', '0x10 uint8', '0x18 uint64'],
        confidence: 'disassembly-observed',
      },
    },
    implementationBoundary: {
      sdkStarted: false,
      networkUsed: false,
      liveKeepaliveProven: false,
      nextStep: 'Build an offline ZIME harness that sets callback + external transport, creates SCTP/QUIC channel/stream, and records packets_out before any live CAG send.',
    },
    toolErrors: [
      readelf.ok ? null : `readelf failed: ${readelf.error || readelf.stderr || readelf.status}`,
      strings.ok ? null : `strings failed: ${strings.error || strings.stderr || strings.status}`,
    ].filter(Boolean),
  }, null, 2));
}

main();
