/*
 * TCP 双向字节流重组。
 *
 * 核心原则（对应需求）：
 *   - 按双向四元组归并连接，每个方向独立重组；
 *   - 相同字节的重传重叠去重（不重复计数、不伪造内容）；
 *   - 缺失区间显式留空（gap），绝不拿后到字节填补成“看起来连续”的流；
 *   - 重叠位置字节不一致 => 标记 conflict；展示保留“文件中先捕获”的字节，
 *     但每个冲突位置都完整列出各到达包的实际字节与包号，不凭到达顺序悄悄覆盖；
 *   - 32 位序号回绕：以每方向锚点（SYN 的 ISN，否则首个数据段的 seq）展开成
 *     单调序号空间（RFC1982 风格 signed diff），回绕处可自然连续拼接；
 *   - 若段间跨度达到 2^31（8MB 文件内物理上不可能），标记序号歧义异常，
 *     只展示事实、不猜测。
 *
 * 两遍算法：
 *   1) 展开序号后排序，求覆盖区间的并集 -> runs（缺口即 run 之间的空间）；
 *   2) 按“文件捕获顺序”把每个字节落到 run 上：首见者占有位置，
 *      相同重叠计重传去重，不同则记冲突与双方证据。
 *
 * 可被 Worker 与 Node 测试同时加载。
 */
(function (global, factory) {
  const api = factory();
  global.ReassemblyLib = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  const TWO32 = 0x100000000;
  const HALF2 = 0x80000000; // 2^31

  /**
   * 32 位模空间的有符号差值：b - a。
   * 无符号差 d ∈ [0,2^32)：d ≤ 2^31 取正方向，d > 2^31 取负方向（d-2^32），
   * 结果落在 (-2^31, 2^31]。
   *
   * 为什么把恰为 2^31 的距离归为正：本工具输入被限定为 ≤8MB / 2000 包，
   * 同一方向真实字节跨度绝不可能达到 2^31；因此落在该边界的序号只可能是
   * “数据跨过 0xffffffff 回绕点”。归为正方向后，回绕点前（d=1）与回绕点后
   * （d=2^31 起）的段在同一展开空间内自然连续，不会被错切成缺口。
   */
  function seqDiff(b, a) {
    const d = (b - a) >>> 0;
    return d > HALF2 ? d - TWO32 : d;
  }

  function makeEndpoint(ip, port) {
    return { ip, port, key: ip + ':' + port };
  }

  /** 四元组归一化：IP 字典序、再端口，小者为 A。 */
  function endpointOrder(a, b) {
    if (a.ip !== b.ip) return a.ip < b.ip ? -1 : 1;
    return a.port - b.port;
  }

  function flagsList(flags) {
    const names = [
      ['syn', 'SYN'],
      ['ack', 'ACK'],
      ['fin', 'FIN'],
      ['rst', 'RST'],
      ['psh', 'PSH']
    ];
    const out = [];
    names.forEach(([f, name]) => {
      if (flags[f]) out.push(name);
    });
    return out;
  }

  class DirectionAssembler {
    constructor(label) {
      this.label = label; // 'AtoB' | 'BtoA'
      this.segments = []; // 文件捕获顺序的数据段
      this.packets = []; // 该方向所有 TCP 包（含纯控制段）
      this.anchorRaw = null; // 展开坐标用的原始 32 位锚点
      this.anchorPkt = null;
      this.isnRaw = null; // SYN 的 ISN（展示用）
      this.finSeq = null; // FIN 在数据之后占用的序号（原始 32 位）
      this.anomalies = [];
    }

    addPacket(pkt) {
      const t = pkt.tcp;
      this.packets.push({
        pktIndex: pkt.index,
        timestamp: pkt.timestamp,
        seq: t.seq,
        ack: t.ack,
        flags: Object.assign({}, t.flags),
        payloadLen: t.payloadLen,
        snapTruncated: !!pkt.snapTruncated
      });

      if (t.flags.syn && this.isnRaw === null) this.isnRaw = t.seq;

      // 锚点只确定一次：优先首个 SYN 的 ISN；否则第一个数据段的 seq。
      // 后续 SYN/SYN-ACK 不得改变锚点，否则已收集数据段的展开坐标会被错位。
      if (this.anchorRaw === null && (t.flags.syn || t.payloadLen > 0)) {
        this.anchorRaw = t.seq;
        this.anchorPkt = pkt.index;
      }

      if (t.payloadLen > 0) {
        this.segments.push({
          pktIndex: pkt.index,
          rawSeq: t.seq,
          bytes: new Uint8Array(
            pkt._fileBuffer.buffer,
            pkt._fileBuffer.byteOffset + t.payloadStart,
            t.payloadLen
          )
        });
      }

      if (t.flags.fin) this.finSeq = (t.seq + Math.max(0, t.payloadLen)) >>> 0;
    }

    finalize() {
      const anchor = this.anchorRaw;
      // 展开坐标即以锚点为 0 的相对序号空间：有 SYN 时 SYN 占 0、首字节数据为 1；
      // 无 SYN 时首个数据段 seq 为 0。
      const relBase = 0;

      // ---- 展开 32 位序号（同时正确处理回绕 / 乱序 / 缺口）----
      // 按捕获顺序维护“已到达最高字节水位”，且水位以【段尾】表示：
      //   hiExp = 已到达最高字节的下一个展开位置；hiRaw = 其原始 32 位 seq。
      // 对新段取 fwd = (seq - hiRaw) mod 2^32：
      //   fwd ≤ 2^31 => 前进 d=fwd（跨 0 回绕时 fwd 仍是小正数，天然连续）；
      //   fwd > 2^31 => 乱序后到 d=fwd-2^32（start 落在已覆盖区，只重叠不覆盖）。
      //   start = hiExp + d。
      // 回绕点两侧因此无缝；回绕后若还缺字节，fwd 跳过空缺使 run 并集自然留空。
      // 必须用段尾 (seq+len) 推进水位；若用段首，下一段 fwd 会少算本段长度，
      // 在回绕边界产生 off-by-segment-length 错位。≤8MB 文件跨度远小于 2^31。
      const startBySeg = new Map();
      let hiRaw = anchor;
      let hiExp = 0;
      for (const s of this.segments) {
        const fwd = (s.rawSeq - hiRaw) >>> 0;
        const d = fwd <= HALF2 ? fwd : fwd - TWO32;
        const start = hiExp + d;
        if (d > 0 && s.rawSeq < hiRaw) {
          this.anomalies.push({
            type: 'sequence_wrap',
            pktIndex: s.pktIndex,
            message: '包 #' + (s.pktIndex + 1) + ' 跨越 32 位序号回绕点（0x' +
              (hiRaw >>> 0).toString(16) + ' → 0x' + (s.rawSeq >>> 0).toString(16) +
              '），回绕点前后的字节已连续展开，未产生虚假缺口。'
          });
        }
        startBySeg.set(s, start);
        const segEnd = start + s.bytes.length;
        if (segEnd > hiExp) {
          hiRaw = (s.rawSeq + s.bytes.length) >>> 0; // 水位推进到段尾
          hiExp = segEnd;
        }
      }

      const segs = this.segments.map((s) => {
        const start = startBySeg.get(s);
        return { pktIndex: s.pktIndex, rawSeq: s.rawSeq, start, end: start + s.bytes.length, bytes: s.bytes };
      });

      for (const s of segs) {
        if (s.end - s.start >= HALF2 || s.start <= -HALF2) {
          this.anomalies.push({
            type: 'sequence_span_ambiguity',
            pktIndex: s.pktIndex,
            message:
              '包 #' + (s.pktIndex + 1) + ' 相对锚点的序号跨度达到 2^31 边界，' +
              '32 位序号方向存在歧义；已保留原始段，不做拼接假设。'
          });
        }
      }

      // ---- 第一遍：求覆盖区间并集 ----
      const sorted = segs.slice().sort((a, b) => a.start - b.start || a.pktIndex - b.pktIndex);
      const intervals = []; // {start,end}
      for (const s of sorted) {
        const last = intervals[intervals.length - 1];
        if (last && s.start <= last.end) {
          if (s.end > last.end) last.end = s.end;
        } else {
          intervals.push({ start: s.start, end: s.end });
        }
      }

      // 每个 run 分配字节与位置 owner（首见包）。
      const runs = intervals.map((iv) => ({
        start: iv.start,
        end: iv.end,
        bytes: new Uint8Array(iv.end - iv.start),
        owners: new Int32Array(iv.end - iv.start).fill(-1)
      }));

      // run 上界二分：找到 end > pos 的第一个 run。
      const findRunIndex = (pos) => {
        let lo = 0, hi = runs.length;
        while (lo < hi) {
          const mid = (lo + hi) >> 1;
          if (runs[mid].end > pos) hi = mid;
          else lo = mid + 1;
        }
        return lo;
      };

      // ---- 第二遍：按文件捕获顺序落字节 ----
      const conflictMap = new Map(); // pos -> {keptByte, ownerPkt, incoming:[]}
      const pktStats = new Map();
      const bump = (pktIndex, key) => {
        let st = pktStats.get(pktIndex);
        if (!st) {
          st = { retransmitBytes: 0, conflictBytes: 0 };
          pktStats.set(pktIndex, st);
        }
        st[key]++;
      };

      for (const s of segs) {
        if (!runs.length) break;
        let ri = findRunIndex(s.start);
        for (let p = s.start; p < s.end; p++) {
          // 推进到包含 p 的 run（理论上不会跳过，因为每个 p 都属于某段并集）
          while (ri < runs.length && runs[ri].end <= p) ri++;
          if (ri >= runs.length) break;
          const run = runs[ri];
          if (p < run.start) {
            // 落在 gap 中——理论不可能（p 来自构成并集的段），防御性跳过。
            continue;
          }
          const idx = p - run.start;
          const byte = s.bytes[p - s.start];
          const owner = run.owners[idx];
          if (owner === -1) {
            run.bytes[idx] = byte;
            run.owners[idx] = s.pktIndex;
          } else if (run.bytes[idx] === byte) {
            // 相同字节重传：去重。
            bump(s.pktIndex, 'retransmitBytes');
          } else {
            // 字节不一致：冲突，保留首见字节，记录双方证据。
            bump(s.pktIndex, 'conflictBytes');
            let c = conflictMap.get(p);
            if (!c) {
              c = { pos: p, keptByte: run.bytes[idx], ownerPkt: owner, incoming: [] };
              conflictMap.set(p, c);
            }
            c.incoming.push({ pktIndex: s.pktIndex, byte });
          }
        }
      }

      // ---- 缺口 ----
      const gaps = [];
      for (let i = 1; i < runs.length; i++) {
        const gapStart = runs[i - 1].end;
        const gapEnd = runs[i].start;
        gaps.push({ start: gapStart, end: gapEnd, length: gapEnd - gapStart, betweenRuns: true });
      }
      let leadingGap = null;
      // 有 SYN 时展开坐标 0 是 SYN 自身占用的序号位，首字节数据位于 1；
      // 只有首个数据 run 晚于 1 才是真正的前置数据缺口。
      if (runs.length && this.isnRaw !== null && runs[0].start > 1) {
        leadingGap = { start: 1, end: runs[0].start, length: runs[0].start - 1, leading: true };
        gaps.unshift(leadingGap);
      }
      for (const g of gaps) {
        if (g.length >= HALF2) {
          this.anomalies.push({
            type: 'sequence_span_ambiguity',
            pktIndex: null,
            message:
              '缺口相对序号 [' + g.start + ', ' + g.end + ') 跨度达到 2^31，' +
              '可能为序号回绕歧义而非真实缺失；此处按显式缺口留空，未做任何拼接。'
          });
        }
      }

      const coveredBytes = runs.reduce((n, r) => n + r.bytes.length, 0);
      const streamStart = runs.length ? runs[0].start : 0;
      const streamEnd = runs.length ? runs[runs.length - 1].end : 0;
      const totalSpan = streamEnd - streamStart;
      const gapBytes = gaps.reduce((n, g) => n + g.length, 0);

      const outputRuns = runs.map((run) => ({
        start: run.start,
        relStart: run.start + relBase,
        end: run.end,
        relEnd: run.end + relBase,
        bytes: run.bytes
      }));

      // ---- 重组文本：缺口处显式占位，绝不把缺口两侧文本直接相连 ----
      const decoder = new TextDecoder('utf-8');
      let text = '';
      if (runs.length) {
        const lead = runs[0].start - (this.isnRaw !== null ? 1 : 0);
        if (lead > 0) text += '␠[前置缺口 ' + lead + ' 字节]';
        for (let i = 0; i < outputRuns.length; i++) {
          text += decoder.decode(outputRuns[i].bytes);
          if (i < outputRuns.length - 1) {
            text += '␠[缺口 ' + (gaps[leadingGap ? i + 1 : i].length) + ' 字节]';
          }
        }
      }

      const conflicts = Array.from(conflictMap.values())
        .sort((a, b) => a.pos - b.pos)
        .map((c) => ({
          pos: c.pos,
          relPos: c.pos + relBase,
          keptByte: c.keptByte,
          ownerPkt: c.ownerPkt,
          packets: [{ pktIndex: c.ownerPkt, byte: c.keptByte }].concat(c.incoming)
        }));

      // 每个包的展开序号：携带数据的包直接取其首段展开起点；
      // 纯控制段（如 SYN/ACK）用同一水位规则独立展开，仅用于展示。
      const segStartByPkt = new Map();
      for (const s of this.segments) {
        if (!segStartByPkt.has(s.pktIndex)) segStartByPkt.set(s.pktIndex, startBySeg.get(s));
      }
      const packetEntries = this.packets.map((p) => {
        const st = pktStats.get(p.pktIndex) || { retransmitBytes: 0, conflictBytes: 0 };
        let relSeq;
        if (anchor === null) {
          relSeq = null;
        } else if (segStartByPkt.has(p.pktIndex)) {
          relSeq = segStartByPkt.get(p.pktIndex) + relBase;
        } else {
          relSeq = seqDiff(p.seq, anchor) + relBase;
        }
        return {
          pktIndex: p.pktIndex,
          timestamp: p.timestamp,
          seq: p.seq,
          relSeq,
          ack: p.ack,
          flags: p.flags,
          flagsText: flagsList(p.flags).join(',') || '(无标志)',
          payloadLen: p.payloadLen,
          retransmitBytes: st.retransmitBytes,
          conflictBytes: st.conflictBytes,
          snapTruncated: p.snapTruncated
        };
      });

      return {
        label: this.label,
        anchorRaw: anchor,
        anchorPkt: this.anchorPkt,
        isnRaw: this.isnRaw,
        finSeq: this.finSeq,
        relBase,
        packetCount: this.packets.length,
        segmentCount: this.segments.length,
        coveredBytes,
        gapBytes,
        totalSpan,
        leadingGap,
        gaps,
        conflicts,
        runs: outputRuns,
        text,
        packets: packetEntries,
        anomalies: this.anomalies
      };
    }
  }

  /**
   * 由 parse() 的结果构建完整重组模型。
   * @param {Object} parseResult
   * @param {Uint8Array} fileBuffer 原始字节（payload 为其上的视图，需要保活）
   */
  function buildModel(parseResult, fileBuffer) {
    const connections = new Map();
    const unclassified = [];
    let baseTs = null;

    for (const pkt of parseResult.packets) {
      if (baseTs === null) baseTs = pkt.timestamp;
      pkt._fileBuffer = fileBuffer;
      if (!pkt.tcp) {
        unclassified.push({
          pktIndex: pkt.index,
          timestamp: pkt.timestamp,
          inclLen: pkt.inclLen,
          ignored: pkt.ignored
        });
        continue;
      }
      const epA0 = makeEndpoint(pkt.ip.srcIp, pkt.tcp.srcPort);
      const epB0 = makeEndpoint(pkt.ip.dstIp, pkt.tcp.dstPort);
      const ordered = endpointOrder(epA0, epB0) <= 0 ? [epA0, epB0] : [epB0, epA0];
      const connKey = ordered[0].key + '<->' + ordered[1].key;

      let conn = connections.get(connKey);
      if (!conn) {
        conn = {
          key: connKey,
          endpointA: ordered[0],
          endpointB: ordered[1],
          atob: new DirectionAssembler('AtoB'),
          btoa: new DirectionAssembler('BtoA'),
          packetIndices: []
        };
        connections.set(connKey, conn);
      }
      const dir =
        pkt.ip.srcIp === conn.endpointA.ip && pkt.tcp.srcPort === conn.endpointA.port
          ? conn.atob
          : conn.btoa;
      dir.addPacket(pkt);
      conn.packetIndices.push(pkt.index);
    }

    const connList = [];
    for (const conn of connections.values()) {
      connList.push({
        key: conn.key,
        endpointA: conn.endpointA,
        endpointB: conn.endpointB,
        directionAtoB: conn.atob.finalize(),
        directionBtoA: conn.btoa.finalize(),
        packetCount: conn.packetIndices.length,
        firstPktIndex: conn.packetIndices[0]
      });
    }
    connList.sort((a, b) => a.firstPktIndex - b.firstPktIndex);

    return {
      baseTimestamp: baseTs,
      packetTotal: parseResult.packets.length,
      tcpConnectionCount: connList.length,
      unclassifiedCount: unclassified.length,
      unclassified,
      connections: connList,
      truncated: parseResult.truncated,
      stoppedReason: parseResult.stoppedReason,
      snapLen: parseResult.snapLen,
      version: parseResult.version
    };
  }

  /**
   * 冻结当前重组结果：深拷贝（含 run 字节），返回与工作缓冲无关的不可变快照。
   * 后续重新导入 / 取消都不会改变已冻结对象；导出始终引用它。
   */
  function freezeModel(model, meta) {
    return {
      snapshotId: 'frozen-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8),
      frozenAt: new Date().toISOString(),
      meta: meta || {},
      model: cloneModel(model)
    };
  }

  function cloneModel(model) {
    return JSON.parse(
      JSON.stringify(model, (key, value) => (value instanceof Uint8Array ? Array.from(value) : value))
    );
  }

  return { buildModel, freezeModel, seqDiff, DirectionAssembler };
});
