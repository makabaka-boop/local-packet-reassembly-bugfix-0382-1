/*
 * Node 对拍测试：用手工构造的小端 PCAP 样本验证解析与重组。
 * 覆盖：乱序、重传（相同去重 / 不同冲突）、缺口、序号回绕、
 *      文件头整份拒绝、截断包留证据、2000 包上限、非 IPv4/TCP、snaplen 截断。
 *
 * 运行：node test/run-tests.js
 */
'use strict';

const assert = require('assert');
const PcapLib = require('../src/pcap.js');
const ReassemblyLib = require('../src/reassemble.js');

// ---------------- 样本 PCAP 构造器 ----------------

const GLOBAL_HEADER = Buffer.from([
  0xd4, 0xc3, 0xb2, 0xa1, // 小端经典 pcap 魔数
  0x02, 0x00, 0x04, 0x00, // 2.4
  0x00, 0x00, 0x00, 0x00, // thiszone
  0x00, 0x00, 0x00, 0x00, // sigfigs
  0xff, 0xff, 0x00, 0x00, // snaplen 65535
  0x01, 0x00, 0x00, 0x00 // LINKTYPE_ETHERNET
]);

function ipv4ToBytes(ip) {
  return ip.split('.').map(Number);
}

function buildTcp({ seq, ack = 0, flags = 0x10, payload = Buffer.alloc(0), srcPort, dstPort }) {
  const dataOffset = 20;
  const buf = Buffer.alloc(20 + payload.length);
  buf.writeUInt16BE(srcPort, 0);
  buf.writeUInt16BE(dstPort, 2);
  buf.writeUInt32BE(seq >>> 0, 4);
  buf.writeUInt32BE(ack >>> 0, 8);
  buf[12] = (dataOffset / 4) << 4;
  buf[13] = flags;
  buf.writeUInt16BE(0, 14); // window
  buf.writeUInt16BE(0, 16); // checksum（不校验）
  buf.writeUInt16BE(0, 18); // urgent
  payload.copy(buf, 20);
  return buf;
}

function buildIpv4({ srcIp, dstIp, protocol = 6, payload }) {
  const ihl = 20;
  const totalLen = ihl + payload.length;
  const buf = Buffer.alloc(ihl + payload.length);
  buf[0] = 0x45; // v4 + IHL 5
  buf[1] = 0;
  buf.writeUInt16BE(totalLen, 2);
  buf.writeUInt16BE(0, 4); // id
  buf.writeUInt16BE(0, 6); // flags/frag
  buf[8] = 64; // ttl
  buf[9] = protocol;
  buf.writeUInt16BE(0, 10); // checksum
  Buffer.from(ipv4ToBytes(srcIp)).copy(buf, 12);
  Buffer.from(ipv4ToBytes(dstIp)).copy(buf, 16);
  payload.copy(buf, 20);
  return buf;
}

function buildEther({ ethertype = 0x0800, payload }) {
  const buf = Buffer.alloc(14 + payload.length);
  // dst MAC [0..5] / src MAC [6..11] 任意；EtherType 在 [12..13]（网络字节序）
  buf[12] = (ethertype >> 8) & 0xff;
  buf[13] = ethertype & 0xff;
  payload.copy(buf, 14);
  return buf;
}

let tsCounter = 1000000;
function pcapRecord(frame, { inclLen = null, origLen = null } = {}) {
  const data = inclLen === null ? frame : frame.slice(0, inclLen);
  const rec = Buffer.alloc(16 + data.length);
  const tsSec = Math.floor(tsCounter / 1000000);
  const tsUsec = tsCounter % 1000000;
  tsCounter += 1000;
  rec.writeUInt32LE(tsSec, 0);
  rec.writeUInt32LE(tsUsec, 4);
  rec.writeUInt32LE(data.length, 8);
  rec.writeUInt32LE(origLen === null ? frame.length : origLen, 12);
  data.copy(rec, 16);
  return rec;
}

function buildPcap(records, { globalHeader = GLOBAL_HEADER } = {}) {
  return Buffer.concat([globalHeader, ...records]);
}

const FLAGS = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10 };

function tcpPkt({
  seq,
  ack = 0,
  flags = FLAGS.ACK,
  payload = Buffer.alloc(0),
  srcIp = '10.0.0.1',
  dstIp = '10.0.0.2',
  srcPort = 1111,
  dstPort = 80,
  ethertype = 0x0800,
  protocol = 6,
  inclLen = null,
  origLen = null
} = {}) {
  let frame;
  if (ethertype === 0x0800) {
    const tcp = buildTcp({ seq, ack, flags, payload, srcPort, dstPort });
    const ip = buildIpv4({ srcIp, dstIp, protocol, payload: tcp });
    frame = buildEther({ ethertype, payload: ip });
  } else {
    frame = buildEther({ ethertype, payload: Buffer.alloc(20) });
  }
  return pcapRecord(frame, { inclLen, origLen });
}

function parseBuf(buf, opts) {
  return PcapLib.parse(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength), opts);
}
function buildFromBuf(buf, opts) {
  const parsed = parseBuf(buf, opts);
  const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  return { parsed, model: ReassemblyLib.buildModel(parsed, bytes) };
}
function runText(model, connIndex, dir) {
  const conn = model.connections[connIndex];
  return (dir === 'AtoB' ? conn.directionAtoB : conn.directionBtoA).text;
}
function runBytes(model, connIndex, dir) {
  const conn = model.connections[connIndex];
  const d = dir === 'AtoB' ? conn.directionAtoB : conn.directionBtoA;
  return Buffer.concat(d.runs.map((r) => Buffer.from(r.bytes)));
}

// ---------------- 测试用例 ----------------

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

test('乱序 + 相同重传去重 + 字节冲突 + 缺口（单方向对拍）', () => {
  // ISN = 1000；展开坐标 0 为 SYN，数据字节位于 1..10。乱序到达：
  //  包1 SYN(seq=1000)
  //  包2 seq=1005 payload full[4..7]      先捕获中段（位置 5..8）
  //  包3 seq=1001 payload full[0..3]      后捕获首段（位置 1..4）
  //  包4 seq=1004 payload "XX" 位置4,5     位置4 与包3冲突（包3先捕获，保留 full[3]）
  //                                        位置5 与包2冲突（包2先捕获，保留 full[4]）
  //  包5 seq=1005 payload full[4..7]      与包2完全相同 => 重传去重 4 字节
  //  包6 seq=1010 payload full[9]         位置10；位置9（full[8]）缺失 => 缺口
  tsCounter = 1000000;
  const full = Buffer.from('ABCDEFGHIJ');
  const recs = [
    tcpPkt({ seq: 1000, flags: FLAGS.SYN }),
    tcpPkt({ seq: 1005, payload: full.slice(4, 8) }),
    tcpPkt({ seq: 1001, payload: full.slice(0, 4) }),
    tcpPkt({ seq: 1004, payload: Buffer.from('XX') }),
    tcpPkt({ seq: 1005, payload: full.slice(4, 8) }),
    tcpPkt({ seq: 1010, payload: full.slice(9, 10) })
  ];
  const { model } = buildFromBuf(buildPcap(recs));

  assert.strictEqual(model.connections.length, 1);
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.coveredBytes, 9, '应覆盖 9 个字节（位置 9 缺失）');
  assert.strictEqual(d.gapBytes, 1, '缺口 1 字节');
  assert.strictEqual(d.gaps.length, 1);
  assert.deepStrictEqual([d.gaps[0].start, d.gaps[0].end], [9, 10], '缺口在展开坐标 [9,10)');
  assert.strictEqual(d.conflicts.length, 2, '位置 4、5 两个冲突字节');

  // 展示保留“文件中先捕获”的字节；冲突证据列出双方。
  assert.strictEqual(d.conflicts[0].pos, 4);
  assert.strictEqual(d.conflicts[0].keptByte, 'D'.charCodeAt(0), '位置4 先捕获者是包3的 D');
  assert.strictEqual(d.conflicts[0].packets[1].byte, 0x58);
  assert.strictEqual(d.conflicts[1].pos, 5);
  assert.strictEqual(d.conflicts[1].keptByte, 'E'.charCodeAt(0), '位置5 先捕获者是包2的 E');
  assert.strictEqual(d.conflicts[1].packets[1].byte, 0x58);

  // 两个覆盖 run：[1..9] = ABCDEFGH，[10..11] = J；缺口两侧不得拼成 ...HJ
  const assembled = runBytes(model, 0, 'AtoB');
  assert.deepStrictEqual(assembled.slice(0, 8), full.slice(0, 8));
  assert.strictEqual(assembled.length, 9);
  assert.strictEqual(assembled[8], 'J'.charCodeAt(0));
  assert.ok(runText(model, 0, 'AtoB').includes('[缺口 1 字节]'), '文本必须显式标注缺口');

  // 重传统计：包5（pktIndex=4）4 字节全为相同重叠；包4（pktIndex=3）2 字节冲突
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 4).retransmitBytes, 4);
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 3).conflictBytes, 2);
});

test('32 位序号回绕边界：...fffffffe 之后连续拼接到 00000000', () => {
  tsCounter = 2000000;
  const payload = Buffer.from('WRAP_DATA_0123456789'); // 21 字节
  const ISN = 0xfffffffe;
  // 数据 seq 从 0xffffffff 开始（ISN+1），发 5 字节；回绕后 seq=4 发剩余 16 字节。
  const recs = [
    tcpPkt({ seq: ISN, flags: FLAGS.SYN }),
    tcpPkt({ seq: 0xffffffff, payload: payload.slice(0, 5) }),
    tcpPkt({ seq: 4, payload: payload.slice(5) })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.gaps.length, 0, '回绕处连续，不应有缺口');
  assert.strictEqual(d.conflicts.length, 0);
  assert.strictEqual(d.coveredBytes, payload.length);
  assert.deepStrictEqual(runBytes(model, 0, 'AtoB'), payload, '回绕后内容必须无缝拼接');
});

test('回绕之后仍有缺口：显式留空且不拼接', () => {
  tsCounter = 3000000;
  // anchor SYN=fffffffe（位置0）。
  // seq=ffffffff,5B 'ABCDE' 覆盖位置1..6？不：5 字节占 seq ff,00,01,02,03 => 位置1..6(end=6)。
  // seq=5,1B 'G' 展开位置 7 => 缺位置6（seq=4），恰好 1 字节，缺口跨在回绕点之后。
  const recs = [
    tcpPkt({ seq: 0xfffffffe, flags: FLAGS.SYN }),
    tcpPkt({ seq: 0xffffffff, payload: Buffer.from('ABCDE') }),
    tcpPkt({ seq: 5, payload: Buffer.from('G') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.gaps.length, 1);
  assert.deepStrictEqual([d.gaps[0].start, d.gaps[0].end], [6, 7], '位置 6（seq=4）缺失');
  assert.deepStrictEqual(runBytes(model, 0, 'AtoB'), Buffer.from('ABCDEG'));
  assert.ok(runText(model, 0, 'AtoB').includes('[缺口 1 字节]'));
});

test('无 SYN 时以首个数据段 seq 为锚点，不乱报前置缺口', () => {
  tsCounter = 4000000;
  const recs = [
    tcpPkt({ seq: 0x77777770, payload: Buffer.from('hello') }),
    tcpPkt({ seq: 0x77777775, payload: Buffer.from(' world') })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.isnRaw, null);
  assert.strictEqual(d.gaps.length, 0);
  assert.strictEqual(runText(model, 0, 'AtoB'), 'hello world');
  assert.strictEqual(d.packets[0].relSeq, 0);
});

test('双向四元组归并与方向归一化', () => {
  tsCounter = 5000000;
  const recs = [
    tcpPkt({ seq: 100, flags: FLAGS.SYN, srcIp: '10.0.0.1', srcPort: 1111, dstIp: '10.0.0.2', dstPort: 80 }),
    tcpPkt({ seq: 500, flags: FLAGS.SYN, srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1111 }),
    tcpPkt({ seq: 101, payload: Buffer.from('req'), srcIp: '10.0.0.1', srcPort: 1111, dstIp: '10.0.0.2', dstPort: 80 }),
    tcpPkt({ seq: 501, payload: Buffer.from('resp'), srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1111 })
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 1);
  const conn = model.connections[0];
  // IP 字典序归一化：10.0.0.1 为 A
  assert.strictEqual(conn.endpointA.key, '10.0.0.1:1111');
  assert.strictEqual(conn.endpointB.key, '10.0.0.2:80');
  assert.strictEqual(conn.directionAtoB.text, 'req');
  assert.strictEqual(conn.directionBtoA.text, 'resp');
  assert.strictEqual(conn.directionAtoB.isnRaw, 100);
  assert.strictEqual(conn.directionBtoA.isnRaw, 500);
});

test('冻结快照与工作缓冲隔离：深拷贝，后续解析不影响已冻结对象', () => {
  tsCounter = 6000000;
  const buf1 = buildPcap([
    tcpPkt({ seq: 1, flags: FLAGS.SYN }),
    tcpPkt({ seq: 2, payload: Buffer.from('FIRST') })
  ]);
  const r1 = buildFromBuf(buf1);
  const snap = ReassemblyLib.freezeModel(r1.model, { fileName: 'a.pcap' });
  assert.strictEqual(snap.model.connections[0].directionAtoB.runs[0].bytes[0], 'F'.charCodeAt(0));
  // 冻结对象是普通数组深拷贝，与 Uint8Array 工作缓冲无共享
  assert.ok(Array.isArray(snap.model.connections[0].directionAtoB.runs[0].bytes));
  assert.strictEqual(snap.meta.fileName, 'a.pcap');
  assert.ok(snap.snapshotId);

  // 再解析第二份文件，快照不变
  const buf2 = buildPcap([
    tcpPkt({ seq: 1, flags: FLAGS.SYN }),
    tcpPkt({ seq: 2, payload: Buffer.from('SECOND_FILE') })
  ]);
  buildFromBuf(buf2);
  assert.strictEqual(
    Buffer.from(snap.model.connections[0].directionAtoB.runs[0].bytes).toString(),
    'FIRST'
  );
});

test('错误魔数 / 大端 / pcapng：整份拒绝', () => {
  const badMagic = Buffer.from(GLOBAL_HEADER);
  badMagic.writeUInt32LE(0x12345678, 0);
  assert.throws(() => parseBuf(badMagic), /魔数/);

  const bigEndian = Buffer.from(GLOBAL_HEADER);
  bigEndian[0] = 0xa1; bigEndian[1] = 0xb2; bigEndian[2] = 0xc3; bigEndian[3] = 0xd4;
  assert.throws(() => parseBuf(bigEndian), /大端/);

  const pcapng = Buffer.from(GLOBAL_HEADER);
  pcapng[0] = 0x4d; pcapng[1] = 0x3c; pcapng[2] = 0xb2; pcapng[3] = 0xa1;
  assert.throws(() => parseBuf(pcapng), /pcapng/);

  assert.throws(() => parseBuf(Buffer.alloc(10)), /全局文件头/);
});

test('非以太网链路层：整份拒绝', () => {
  const gh = Buffer.from(GLOBAL_HEADER);
  gh.writeUInt16LE(12, 20); // LINKTYPE_RAW
  assert.throws(() => parseBuf(buildPcap([], { globalHeader: gh })), /链路层/);
});

test('单个截断包：保留文件偏移证据并停止，此前包仍可见', () => {
  tsCounter = 7000000;
  const good = tcpPkt({ seq: 1, flags: FLAGS.SYN });
  const good2 = tcpPkt({ seq: 2, payload: Buffer.from('abc') });
  let truncated = buildPcap([good, good2]);

  // 情况 A：记录头被截断（文件尾只剩 10 字节）
  const cutHeader = Buffer.concat([truncated, GLOBAL_HEADER.slice(0, 10)]);
  const parsedA = parseBuf(cutHeader);
  assert.strictEqual(parsedA.packets.length, 2);
  assert.ok(parsedA.truncated);
  assert.strictEqual(parsedA.truncated.kind, 'record_header_truncated');
  assert.strictEqual(parsedA.truncated.packetIndex, 2);
  assert.strictEqual(parsedA.truncated.availableBytes, 10);
  assert.ok(parsedA.truncated.fileOffset >= 0);

  // 情况 B：记录头声称 incl_len=100，但文件只剩 5 字节数据
  const rec = pcapRecord(Buffer.from('hello world'));
  rec.writeUInt32LE(100, 8); // incl_len
  const cutData = Buffer.concat([truncated, rec.slice(0, 16 + 5)]);
  const parsedB = parseBuf(cutData);
  assert.strictEqual(parsedB.packets.length, 2);
  assert.strictEqual(parsedB.truncated.kind, 'record_data_truncated');
  assert.strictEqual(parsedB.truncated.inclLen, 100);
  assert.strictEqual(parsedB.truncated.availableBytes, 5);
});

test('2000 包上限：第 2001 个包停止并给出证据', () => {
  tsCounter = 8000000;
  const recs = [];
  for (let i = 0; i < 2005; i++) recs.push(tcpPkt({ seq: i, payload: Buffer.from([65 + (i % 26)]) }));
  const parsed = parseBuf(buildPcap(recs));
  assert.strictEqual(parsed.packets.length, 2000);
  assert.strictEqual(parsed.truncated.kind, 'packet_limit');
  assert.strictEqual(parsed.truncated.packetIndex, 2000);
});

test('非 IPv4 EtherType / 非 TCP 协议：列入“未纳入重组”，TCP 连接不受影响', () => {
  tsCounter = 9000000;
  const recs = [
    tcpPkt({ seq: 1, flags: FLAGS.SYN }),
    tcpPkt({ seq: 2, payload: Buffer.from('ok') }),
    tcpPkt({ ethertype: 0x0806 }), // ARP
    tcpPkt({ protocol: 17, payload: Buffer.from('udp-ish') }) // UDP
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.connections.length, 1);
  assert.strictEqual(model.unclassifiedCount, 2);
  assert.strictEqual(model.unclassified[0].ignored.layer, 'ethernet');
  assert.strictEqual(model.unclassified[1].ignored.layer, 'ipv4');
  assert.strictEqual(runText(model, 0, 'AtoB'), 'ok');
});

test('snaplen 截断（origLen > inclLen）：标记但不当作文件损坏', () => {
  tsCounter = 9500000;
  const longPayload = Buffer.alloc(100, 0x41);
  const recs = [
    tcpPkt({ seq: 1, flags: FLAGS.SYN }),
    tcpPkt({ seq: 2, payload: longPayload, inclLen: 40 }) // 帧截到 40：14 eth + 20 ip + 6 字节 TCP
  ];
  const parsed = parseBuf(buildPcap(recs));
  assert.strictEqual(parsed.truncated, null, 'snaplen 截断不是文件截断');
  const pkt = parsed.packets[1];
  assert.strictEqual(pkt.snapTruncated, true);
  assert.ok(pkt.ignored);
  assert.match(pkt.ignored.reason, /TCP/);
});

test('重叠冲突时“文件先捕获者胜”，与 IP 标识顺序无关地对拍确认', () => {
  tsCounter = 9800000;
  // 同一个位置，先抓到字节 Z（乱序后到的数据段先写入文件），再抓到真正的 A
  const recs = [
    tcpPkt({ seq: 1000, flags: FLAGS.SYN }),
    tcpPkt({ seq: 1005, payload: Buffer.from([0x5a]) }), // 文件先捕获：位置 5 = 'Z'
    tcpPkt({ seq: 1001, payload: Buffer.from('ABCDEFG') }) // 文件后捕获：位置 5 应为 'F'
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.conflicts.length, 1);
  // 位置5 对应 'ABCDEFG' 索引4 = 'E'(69)；先捕获的 Z(90) 被保留
  assert.strictEqual(d.conflicts[0].keptByte, 0x5a, '保留文件先捕获的 Z');
  assert.strictEqual(d.conflicts[0].packets[1].byte, 'E'.charCodeAt(0));
  // pktIndex 为全局包号：SYN=#1(index0)、Z 段=#2(index1)、ABCDEFG=#3(index2)
  assert.strictEqual(d.conflicts[0].ownerPkt, 1);
  assert.strictEqual(d.conflicts[0].packets[0].pktIndex, 1);
  assert.strictEqual(d.conflicts[0].packets[1].pktIndex, 2);
  const bytes = runBytes(model, 0, 'AtoB');
  assert.strictEqual(bytes.toString(), 'ABCDZFG', '展示流使用先捕获字节，不按到达顺序覆盖');
});

test('连续多字节冲突：逐位置独立标记，先捕获者全部保留', () => {
  tsCounter = 9600000;
  const recs = [
    tcpPkt({ seq: 100, flags: FLAGS.SYN }),
    tcpPkt({ seq: 101, payload: Buffer.from('ZZZZZZ') }), // 文件先捕获 6 个 Z
    tcpPkt({ seq: 101, payload: Buffer.from('ABCDEF') })  // 后到 6 个不同字节
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.conflicts.length, 6);
  assert.deepStrictEqual(d.conflicts.map((c) => c.keptByte), Array.from(Buffer.from('ZZZZZZ')));
  assert.deepStrictEqual(d.conflicts.map((c) => c.packets[1].byte), Array.from(Buffer.from('ABCDEF')));
  assert.strictEqual(runText(model, 0, 'AtoB'), 'ZZZZZZ');
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 2).conflictBytes, 6);
  assert.strictEqual(d.gaps.length, 0);
});

test('多字节相同重传（乱序后整段重复）：全部去重、无冲突、无缺口', () => {
  tsCounter = 9650000;
  const recs = [
    tcpPkt({ seq: 5000, flags: FLAGS.SYN }),
    tcpPkt({ seq: 5006, payload: Buffer.from('worLD!') }), // 乱序中段先到
    tcpPkt({ seq: 5001, payload: Buffer.from('hello') }), // 首段后到
    tcpPkt({ seq: 5001, payload: Buffer.from('hello') }), // 完全相同重传
    tcpPkt({ seq: 5006, payload: Buffer.from('worLD!') }) // 完全相同重传
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.conflicts.length, 0);
  assert.strictEqual(d.gaps.length, 0);
  assert.strictEqual(d.coveredBytes, 11);
  assert.strictEqual(runText(model, 0, 'AtoB'), 'helloworLD!');
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 3).retransmitBytes, 5, '第4个包 hello 完全重传');
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 4).retransmitBytes, 6, '第5个包 worLD! 完全重传');
});

test('回绕边界附近乱序重叠：重复字节去重，不产生伪造缺口', () => {
  tsCounter = 9700000;
  // SYN ffffffd=位置0；段X fffffffe,4B 'abcd' 覆盖 seq fe,ff,00,01（位置1..5，跨回绕）；
  // 段Y seq=2,4B 'stuv' 覆盖位置5..9。乱序：Y 先到、X 后到，二者在 seq=1/2 边界相邻不重叠。
  const recs = [
    tcpPkt({ seq: 0xfffffffd, flags: FLAGS.SYN }),
    tcpPkt({ seq: 0x00000002, payload: Buffer.from('stuv') }), // 回绕后段先到
    tcpPkt({ seq: 0xfffffffe, payload: Buffer.from('abcd') }), // 回绕前段后到
    tcpPkt({ seq: 0x00000002, payload: Buffer.from('stuv') }) // 完全相同重传
  ];
  const { model } = buildFromBuf(buildPcap(recs));
  const d = model.connections[0].directionAtoB;
  assert.strictEqual(d.conflicts.length, 0);
  assert.strictEqual(d.gaps.length, 0, '回绕两侧乱序到达后仍应无缝');
  assert.strictEqual(d.coveredBytes, 8);
  assert.strictEqual(runText(model, 0, 'AtoB'), 'abcdstuv');
  assert.strictEqual(d.packets.find((p) => p.pktIndex === 3).retransmitBytes, 4);
});

test('IP 分片（MF / 偏移）不参与重组', () => {
  tsCounter = 9900000;
  const tcp = buildTcp({ seq: 2, flags: FLAGS.ACK, payload: Buffer.from('xx'), srcPort: 1, dstPort: 2 });
  let ip = buildIpv4({ srcIp: '1.1.1.1', dstIp: '2.2.2.2', payload: tcp });
  ip.writeUInt16BE(0x2000, 6); // MF=1
  const frame = buildEther({ payload: ip });
  const recs = [tcpPkt({ seq: 1, flags: FLAGS.SYN, srcIp: '1.1.1.1', dstIp: '2.2.2.2', srcPort: 1, dstPort: 2 }), pcapRecord(frame)];
  const { model } = buildFromBuf(buildPcap(recs));
  assert.strictEqual(model.unclassifiedCount, 1);
  assert.match(model.unclassified[0].ignored.reason, /分片/);
});

// ---------------- 运行 ----------------

let pass = 0;
let fail = 0;
for (const t of tests) {
  try {
    t.fn();
    console.log('  ✓ ' + t.name);
    pass++;
  } catch (e) {
    console.error('  ✗ ' + t.name);
    console.error('    ' + (e && e.stack ? e.stack.split('\n').slice(0, 3).join('\n    ') : e));
    fail++;
  }
}
console.log('\n' + pass + ' 通过，' + fail + ' 失败');
process.exit(fail ? 1 : 0);
