/*
 * 生成一个“演示用”小端 PCAP：samples/demo.pcap
 * 内含：
 *   - 一条完整 TCP 连接（握手、乱序、相同重传、字节冲突、缺口、snaplen 截断）；
 *   - 同一四元组复用的第二次会话（FIN 关闭后新 ISN 重连，RST 收尾）；
 *   - 两次会话之间夹杂的另一条连接（验证拆分状态按四元组隔离）；
 *   - 一个非 IPv4 帧（展示“未纳入重组”）。
 * 运行：node test/make-sample.js
 */
'use strict';
const fs = require('fs');
const path = require('path');

const GLOBAL_HEADER = Buffer.from([
  0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
  0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x00, 0x00, 0x01, 0, 0, 0
]);
const FLAGS = { FIN: 0x01, SYN: 0x02, ACK: 0x10, PSH: 0x08 };

function tcp(seq, ack, flags, payload, sp = 40000, dp = 8080) {
  const b = Buffer.alloc(20 + payload.length);
  b.writeUInt16BE(sp, 0); b.writeUInt16BE(dp, 2);
  b.writeUInt32BE(seq >>> 0, 4); b.writeUInt32BE(ack >>> 0, 8);
  b[12] = 0x50; b[13] = flags;
  payload.copy(b, 20);
  return b;
}
function ip(src, dst, l4) {
  const b = Buffer.alloc(20 + l4.length);
  b[0] = 0x45; b.writeUInt16BE(b.length, 2); b[8] = 64; b[9] = 6;
  src.split('.').map(Number).forEach((x, i) => (b[12 + i] = x));
  dst.split('.').map(Number).forEach((x, i) => (b[16 + i] = x));
  l4.copy(b, 20);
  return b;
}
function eth(payload) {
  const b = Buffer.alloc(14 + payload.length);
  b[12] = 0x08; b[13] = 0x00;
  payload.copy(b, 14);
  return b;
}
let ts = 1700000000 * 1e6;
function rec(frame, { inclLen = null, origLen = null } = {}) {
  const data = inclLen === null ? frame : frame.slice(0, inclLen);
  const r = Buffer.alloc(16 + data.length);
  r.writeUInt32LE(Math.floor(ts / 1e6), 0);
  r.writeUInt32LE(ts % 1e6, 4);
  ts += 12000;
  r.writeUInt32LE(data.length, 8);
  r.writeUInt32LE(origLen === null ? frame.length : origLen, 12);
  data.copy(r, 16);
  return r;
}
const C = '192.168.1.10', S = '93.184.216.34';
const pkt = (seq, ack, flags, body, fromClient = true, opts) =>
  rec(
    eth(
      fromClient
        ? ip(C, S, tcp(seq, ack, flags, body, 40000, 8080))
        : ip(S, C, tcp(seq, ack, flags, body, 8080, 40000))
    ),
    opts
  );

const ISN_C = 1000, ISN_S = 7000;
const records = [];
records.push(pkt(ISN_C, 0, FLAGS.SYN, Buffer.alloc(0), true));          // 握手
records.push(pkt(ISN_S, ISN_C + 1, FLAGS.SYN | FLAGS.ACK, Buffer.alloc(0), false));
records.push(pkt(ISN_C + 1, ISN_S + 1, FLAGS.ACK, Buffer.alloc(0), true));

// 客户端请求 "GET /demo HTTP/1.0\r\n\r\n"（22 字节），故意乱序 + 重传 + 冲突
const req = Buffer.from('GET /demo HTTP/1.0\r\n\r\n'); // seq 1001..1022
records.push(pkt(1001 + 10, ISN_S + 1, FLAGS.ACK, req.slice(10), true)); // 先到尾段
records.push(pkt(1001, ISN_S + 1, FLAGS.PSH | FLAGS.ACK, req.slice(0, 10), true)); // 后到头段
records.push(pkt(1001 + 10, ISN_S + 1, FLAGS.ACK, req.slice(10), true)); // 完全相同重传
// 冲突：把第 15 字节（位置 1015，原 '/' 附近）发成 'Z'
const evil = Buffer.from(req); evil[14] = 0x5a;
records.push(pkt(1001 + 14, ISN_S + 1, FLAGS.ACK, evil.slice(14, 16), true));

// 服务端响应，故意留一个缺口：位置 8..11（4 字节）不到
const resp = Buffer.from('Hello, this is a reassembled TCP response body for the demo!!'); // 60B
records.push(pkt(ISN_S + 1, ISN_C + 20, FLAGS.PSH | FLAGS.ACK, resp.slice(0, 8), false));
records.push(pkt(ISN_S + 1 + 12, ISN_C + 20, FLAGS.ACK, resp.slice(12, 40), false)); // 跳过 8..12 => 缺口
records.push(pkt(ISN_S + 1 + 40, ISN_C + 20, FLAGS.ACK, resp.slice(40), false));

// 一个非 IPv4 帧（EtherType ARP 0x0806），展示“未纳入重组”
const arpFrame = Buffer.alloc(42);
arpFrame[12] = 0x08; arpFrame[13] = 0x06;
records.push(rec(arpFrame));

// ---- 会话 1 正常关闭（双向 FIN + 末尾 ACK）----
// 客户端已发 22 字节（seq 1001..1022），服务端已发 60 字节（seq 7001..7060）
records.push(pkt(ISN_C + 1 + 22, ISN_S + 1 + 60, FLAGS.FIN | FLAGS.ACK, Buffer.alloc(0), true));
records.push(pkt(ISN_S + 1 + 60, ISN_C + 1 + 23, FLAGS.FIN | FLAGS.ACK, Buffer.alloc(0), false));
records.push(pkt(ISN_C + 1 + 23, ISN_S + 1 + 61, FLAGS.ACK, Buffer.alloc(0), true));

// ---- 两次会话之间夹杂的另一条连接（不同四元组）----
const other = (seq, ack, flags, body, fromA) =>
  rec(
    eth(
      fromA
        ? ip('10.9.0.5', '10.9.0.6', tcp(seq, ack, flags, body, 51000, 443))
        : ip('10.9.0.6', '10.9.0.5', tcp(seq, ack, flags, body, 443, 51000))
    )
  );
records.push(other(31337, 0, FLAGS.SYN, Buffer.alloc(0), true));
records.push(other(80000, 31338, FLAGS.SYN | FLAGS.ACK, Buffer.alloc(0), false));
records.push(other(31338, 80001, FLAGS.ACK, Buffer.from('interleaved connection'), true));

// ---- 同一四元组复用的第二次会话：新 ISN 重连，RST 异常收尾 ----
const ISN_C2 = 0x20000010, ISN_S2 = 0x60000020;
records.push(pkt(ISN_C2, 0, FLAGS.SYN, Buffer.alloc(0), true));
records.push(pkt(ISN_S2, ISN_C2 + 1, FLAGS.SYN | FLAGS.ACK, Buffer.alloc(0), false));
records.push(pkt(ISN_C2 + 1, ISN_S2 + 1, FLAGS.ACK, Buffer.alloc(0), true));
const req2 = Buffer.from('GET /second HTTP/1.0\r\n\r\n'); // 24 字节
records.push(pkt(ISN_C2 + 1, ISN_S2 + 1, FLAGS.PSH | FLAGS.ACK, req2, true));
const resp2 = Buffer.from('SECOND SESSION RESPONSE (same 4-tuple)');
records.push(pkt(ISN_S2 + 1, ISN_C2 + 1 + req2.length, FLAGS.PSH | FLAGS.ACK, resp2, false));
records.push(pkt(ISN_C2 + 1 + req2.length, ISN_S2 + 1 + resp2.length, FLAGS.RST | FLAGS.ACK, Buffer.alloc(0), true));

const outDir = path.join(__dirname, '..', 'samples');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'demo.pcap'), Buffer.concat([GLOBAL_HEADER, ...records]));
console.log('已生成 samples/demo.pcap，共', records.length, '个记录，',
  (GLOBAL_HEADER.length + records.reduce((n, r) => n + r.length, 0)), '字节');
