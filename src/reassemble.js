/*
 * TCP 双向字节流重组。
 *
 * 核心原则（对应需求）：
 *   - 按双向四元组归并连接，每个方向独立重组；
 *   - 同一四元组被复用（先后多次 TCP 会话）时，依据连接生命周期证据拆分为
 *     多个会话实例，每个会话独立重组，绝不把两次传输拼成一条流；
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
 * 会话拆分（同四元组复用）只依据序号与标志位事实，不猜测：
 *   - 新 SYN（不带 ACK）且与本会话同方向已有 SYN 的 ISN 不同，或会话已越过
 *     纯 SYN 阶段 => 新会话；同 ISN 的 SYN 是重传，双向 SYN 属同时打开，均不拆；
 *   - SYN+ACK 的 ISN 与本会话不符、且其 ack 也未确认本会话的 SYN => 新会话；
 *   - 会话已关闭（任一方向 RST，或双向 FIN）后，序号不落在已覆盖区间内的包
 *     => 新会话；完全落在已覆盖区间内的包是旧会话的迟到重传，仍归旧会话；
 *   - 本方向 FIN 之后又出现越过 FIN 序号位的数据（同一连接不可能）=> 新会话；
 *   - 数据序号落在本方向 ISN 之前（同一连接不可能）=> 新会话；
 *   - 当前会话解释不了、但某个更早会话能完整覆盖/容纳的包（迟到重传、迟到
 *     控制包），归回其来源会话，不污染当前会话的冲突/缺口证据；
 *   - 每个 TCP 包恰好归属一个会话；拆分依据随会话保存并进入导出。
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
      // ---- 会话拆分 / 归属判定用的增量状态（与 finalize 同一套展开规则）----
      this.synSeqs = []; // 本方向所有 SYN 类包的原始 seq（识别同 ISN 重传）
      this.ackValues = new Set(); // 本方向 ACK 包的 ack 值（跨方向核验 SYN 归属）
      this.hiRaw = 0; // 水位：已到达最高字节【段尾】的原始 32 位 seq
      this.hiExp = 0; // 水位对应的展开位置（最高字节的下一个位置）
      this.loExp = null; // 已到达数据段的最低展开起点
      this.finSeen = false;
      this.finExp = null; // FIN 占用序号位的展开位置
      this.synWithPayload = false; // SYN 携带数据时数据可合法位于展开坐标 0
    }

    /**
     * 按“最高字节水位（段尾）”规则计算 rawSeq 的展开起点，不修改状态。
     *   fwd = (seq - hiRaw) mod 2^32：
     *   fwd ≤ 2^31 => 前进 d=fwd（跨 0 回绕时 fwd 仍是小正数，天然连续）；
     *   fwd > 2^31 => 乱序后到 d=fwd-2^32（start 落在已覆盖区，只重叠不覆盖）。
     * 必须用段尾 (seq+len) 推进水位；若用段首，下一段 fwd 会少算本段长度，
     * 在回绕边界产生 off-by-segment-length 错位。≤8MB 文件跨度远小于 2^31。
     */
    _walk(rawSeq) {
      const fwd = (rawSeq - this.hiRaw) >>> 0;
      const d = fwd <= HALF2 ? fwd : fwd - TWO32;
      return { start: this.hiExp + d, d };
    }

    /** 假设段在当前水位下的展开起点；锚点未建立时返回 null。 */
    walkStart(rawSeq) {
      return this.anchorRaw === null ? null : this._walk(rawSeq).start;
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

      if (t.flags.ack) this.ackValues.add(t.ack >>> 0);
      if (t.flags.syn) {
        this.synSeqs.push(t.seq >>> 0);
        if (t.payloadLen > 0) this.synWithPayload = true;
      }
      if (t.flags.syn && this.isnRaw === null) this.isnRaw = t.seq;

      // 锚点只确定一次：优先首个 SYN 的 ISN；否则第一个数据段的 seq。
      // 后续 SYN/SYN-ACK 不得改变锚点，否则已收集数据段的展开坐标会被错位。
      if (this.anchorRaw === null && (t.flags.syn || t.payloadLen > 0)) {
        this.anchorRaw = t.seq;
        this.anchorPkt = pkt.index;
        this.hiRaw = t.seq >>> 0;
        this.hiExp = 0;
      }

      if (t.payloadLen > 0) {
        // 展开坐标在加包时确定（捕获顺序与 finalize 的两遍算法一致）；
        // 会话拆分判定与最终重组因此使用同一坐标系，证据不会自相矛盾。
        const w = this._walk(t.seq);
        if (w.d > 0 && t.seq < this.hiRaw) {
          this.anomalies.push({
            type: 'sequence_wrap',
            pktIndex: pkt.index,
            message: '包 #' + (pkt.index + 1) + ' 跨越 32 位序号回绕点（0x' +
              (this.hiRaw >>> 0).toString(16) + ' → 0x' + (t.seq >>> 0).toString(16) +
              '），回绕点前后的字节已连续展开，未产生虚假缺口。'
          });
        }
        this.segments.push({
          pktIndex: pkt.index,
          rawSeq: t.seq,
          start: w.start,
          bytes: new Uint8Array(
            pkt._fileBuffer.buffer,
            pkt._fileBuffer.byteOffset + t.payloadStart,
            t.payloadLen
          )
        });
        if (this.loExp === null || w.start < this.loExp) this.loExp = w.start;
        const segEnd = w.start + t.payloadLen;
        if (segEnd > this.hiExp) {
          this.hiRaw = (t.seq + t.payloadLen) >>> 0; // 水位推进到段尾
          this.hiExp = segEnd;
        }
      }

      if (t.flags.fin) {
        this.finSeq = (t.seq + Math.max(0, t.payloadLen)) >>> 0;
        this.finSeen = true;
        // FIN 占用的序号位（数据之后的一个位置）的展开坐标；用于判定
        // “FIN 之后又有越过它的数据”这一同一连接内不可能的事件。
        this.finExp = this.anchorRaw === null ? null : this._walk(this.finSeq).start;
      }
    }

    finalize() {
      const anchor = this.anchorRaw;
      // 展开坐标即以锚点为 0 的相对序号空间：有 SYN 时 SYN 占 0、首字节数据为 1；
      // 无 SYN 时首个数据段 seq 为 0。
      const relBase = 0;

      // ---- 展开 32 位序号（同时正确处理回绕 / 乱序 / 缺口）----
      // 各数据段的展开起点已在 addPacket 时按捕获顺序用同一水位规则确定，
      // 这里直接取用；拆分判定所见的状态与最终重组结果因此严格一致。
      const segs = this.segments.map((s) => ({
        pktIndex: s.pktIndex,
        rawSeq: s.rawSeq,
        start: s.start,
        end: s.start + s.bytes.length,
        bytes: s.bytes
      }));

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
        if (!segStartByPkt.has(s.pktIndex)) segStartByPkt.set(s.pktIndex, s.start);
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

  // ------------------------------------------------------------------
  // 同四元组会话拆分
  //
  // 每个四元组维护一个按捕获顺序增长的会话序列；每个 TCP 包依据序号与
  // 标志位事实归属到恰好一个会话。只在有硬证据时拆分，绝不凭启发式猜测：
  // 没有握手、没有关闭、序号也不矛盾时，包仍留在当前会话（缺口/冲突照实展示）。
  // ------------------------------------------------------------------

  function hex8(n) {
    return '0x' + (n >>> 0).toString(16).padStart(8, '0');
  }

  /** 数据段 [seq, seq+len) 是否完全落在该方向已覆盖区间 [loExp, hiExp] 内。 */
  function fullyCovered(asm, seq, len) {
    if (asm.anchorRaw === null || asm.loExp === null) return false;
    const start = asm.walkStart(seq);
    return start >= asm.loExp && start + len <= asm.hiExp;
  }

  /** 数据段是否与已覆盖区间相邻或重叠（边沿扩展、乱序、重传都算）。 */
  function touchesWindow(asm, seq, len) {
    if (asm.anchorRaw === null || asm.loExp === null) return false;
    const start = asm.walkStart(seq);
    return start <= asm.hiExp + 1 && start + len >= asm.loExp;
  }

  /** 纯控制包（无载荷）的序号位是否落在该方向已用序号空间 [lo, hi+1] 内。 */
  function fitsControlWindow(asm, seq) {
    if (asm.anchorRaw === null) return false;
    const pos = asm.walkStart(seq);
    const lo = asm.loExp !== null ? asm.loExp : (asm.isnRaw !== null ? 1 : 0);
    const hi = (asm.loExp !== null ? asm.hiExp : (asm.isnRaw !== null ? 1 : 0)) + 1;
    return pos >= lo && pos <= hi;
  }

  /** 会话是否已关闭：任一方向 RST，或两个方向都见过 FIN。 */
  function sessionClosed(sess) {
    return sess.rstSeen || (sess.atob.finSeen && sess.btoa.finSeen);
  }

  /** 会话是否仍处于纯 SYN 阶段（迄今所有包都是不带 ACK 的 SYN）。 */
  function sessionFresh(sess) {
    return !sess.sawNonSynNoAck;
  }

  /** 对向已捕获的 ACK 是否确认过 synSeq+1（该 SYN 属于本会话的硬证据）。 */
  function ackConsistent(sess, dirLabel, synSeq) {
    const other = dirLabel === 'AtoB' ? sess.btoa : sess.atob;
    return other.ackValues.has((synSeq + 1) >>> 0);
  }

  function dirAssembler(sess, dirLabel) {
    return dirLabel === 'AtoB' ? sess.atob : sess.btoa;
  }

  function makeSession(tupleState, splitReason) {
    const sess = {
      sessionIndex: tupleState.sessions.length + 1,
      atob: new DirectionAssembler('AtoB'),
      btoa: new DirectionAssembler('BtoA'),
      packetIndices: [],
      rstSeen: false,
      sawNonSynNoAck: false,
      splitReason: splitReason || null // {type, pktIndex, message}
    };
    tupleState.sessions.push(sess);
    return sess;
  }

  function startSession(tupleState, pkt, type, detail) {
    return makeSession(tupleState, {
      type,
      pktIndex: pkt.index,
      message: '包 #' + (pkt.index + 1) + ' ' + detail + '；自本包起拆分为该四元组的第 ' +
        (tupleState.sessions.length + 1) + ' 个会话。'
    });
  }

  /**
   * 在当前会话解释不了 pkt 时，检查某个更早会话能否完整容纳它
   * （迟到重传 / 迟到控制包应归回其来源会话，不污染当前会话的证据）。
   */
  function findOlderSession(tupleState, pkt, dirLabel) {
    const t = pkt.tcp;
    const sessions = tupleState.sessions;
    for (let i = sessions.length - 2; i >= 0; i--) {
      const asm = dirAssembler(sessions[i], dirLabel);
      if (t.payloadLen > 0) {
        if (fullyCovered(asm, t.seq, t.payloadLen)) return sessions[i];
      } else if (fitsControlWindow(asm, t.seq)) {
        return sessions[i];
      }
    }
    return null;
  }

  /** 判定 pkt 归属的会话（必要时新建），返回会话对象。 */
  function assignPacket(tupleState, pkt, dirLabel) {
    const t = pkt.tcp;
    let cur = tupleState.sessions[tupleState.sessions.length - 1];
    if (!cur) return makeSession(tupleState, null);

    const ds = dirAssembler(cur, dirLabel);
    const ods = dirAssembler(cur, dirLabel === 'AtoB' ? 'BtoA' : 'AtoB');

    // R1：SYN（不带 ACK）——新连接请求。
    if (t.flags.syn && !t.flags.ack) {
      if (ds.synSeqs.indexOf(t.seq >>> 0) !== -1) return cur; // 同 ISN：SYN 重传
      // 纯 SYN 阶段且本方向尚无 SYN：首个 SYN，或同时打开的第二个 SYN。
      if (sessionFresh(cur) && ds.synSeqs.length === 0) return cur;
      // 对向 ACK 确认过该 ISN+1：原 SYN 漏抓、这是本会话自己的迟到 SYN。
      if (ackConsistent(cur, dirLabel, t.seq)) return cur;
      return startSession(tupleState, pkt, 'syn_new_isn',
        '携带新的 SYN（ISN ' + hex8(t.seq) +
        (ds.isnRaw !== null ? '，与本会话同方向 ISN ' + hex8(ds.isnRaw) + ' 不同' : '') +
        '），同一四元组被复用');
    }

    // SYN+ACK：握手应答。ISN 与本会话不符且 ack 也不确认本会话的 SYN 时，
    // 它是另一次连接的应答（其 SYN 可能漏抓）。
    if (t.flags.syn && t.flags.ack) {
      if (ds.synSeqs.indexOf(t.seq >>> 0) !== -1) return cur; // 同 ISN：重传
      if (
        sessionFresh(cur) && ds.packets.length === 0 && ods.synSeqs.length > 0 &&
        (t.ack >>> 0) === ((ods.synSeqs[0] + 1) >>> 0)
      ) {
        return cur; // 正常握手应答（含同时打开的应答），ack 确认本会话的 SYN
      }
      if (ackConsistent(cur, dirLabel, t.seq)) return cur; // 对向已确认该 ISN+1
      return startSession(tupleState, pkt, 'synack_new_isn',
        '携带新的 SYN+ACK（ISN ' + hex8(t.seq) +
        (ds.isnRaw !== null ? '，与本会话同方向 ISN ' + hex8(ds.isnRaw) + ' 不同' : '') +
        '），且未确认本会话的 SYN，属于同一四元组的另一次连接');
    }

    // 以下均为非 SYN 包。
    // R2：会话已关闭（RST 或双向 FIN）——只有落在已覆盖区间内的包才可能是
    // 旧会话的迟到重传；其余一律属于新会话。
    if (sessionClosed(cur)) {
      const fits = t.payloadLen > 0
        ? fullyCovered(ds, t.seq, t.payloadLen)
        : fitsControlWindow(ds, t.seq);
      if (fits) return cur;
      const older = findOlderSession(tupleState, pkt, dirLabel);
      if (older) return older;
      return startSession(tupleState, pkt, 'after_close',
        '出现在上一会话关闭（' + (cur.rstSeen ? 'RST' : '双向 FIN') + '）之后，' +
        '且其序号不在上一会话已覆盖的序号空间内');
    }

    if (t.payloadLen > 0) {
      // R2a：本方向 FIN 之后又出现越过 FIN 序号位的数据——同一连接不可能。
      if (ds.finSeen && ds.finExp !== null) {
        const start = ds.walkStart(t.seq);
        if (start !== null && start + t.payloadLen > ds.finExp) {
          const older = findOlderSession(tupleState, pkt, dirLabel);
          if (older) return older;
          return startSession(tupleState, pkt, 'data_after_fin',
            '的数据越过本方向 FIN 占用的序号位（FIN 之后本方向不可能再有新数据）');
        }
      }
      // R3：数据序号落在本方向 ISN 之前——同一连接不可能。
      if (ds.isnRaw !== null) {
        const start = ds.walkStart(t.seq);
        const minPos = ds.synWithPayload ? 0 : 1;
        if (start !== null && start < minPos) {
          const older = findOlderSession(tupleState, pkt, dirLabel);
          if (older) return older;
          return startSession(tupleState, pkt, 'seq_before_isn',
            '的数据序号落在本方向 ISN ' + hex8(ds.isnRaw) + ' 之前（同一连接不可能）');
        }
      }
      // 迟到重传回属：当前会话的覆盖窗口碰不到它、但某个更早会话能完整覆盖。
      if (!touchesWindow(ds, t.seq, t.payloadLen)) {
        const older = findOlderSession(tupleState, pkt, dirLabel);
        if (older) return older;
      }
    } else {
      // 迟到控制包回属：序号位不在当前会话窗口内、但在某个更早会话窗口内。
      if (!fitsControlWindow(ds, t.seq)) {
        const older = findOlderSession(tupleState, pkt, dirLabel);
        if (older) return older;
      }
    }
    return cur;
  }

  /**
   * 由 parse() 的结果构建完整重组模型。
   * @param {Object} parseResult
   * @param {Uint8Array} fileBuffer 原始字节（payload 为其上的视图，需要保活）
   */
  function buildModel(parseResult, fileBuffer) {
    const tuples = new Map(); // 归一化四元组 -> {sessions:[...]}
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

      let tupleState = tuples.get(connKey);
      if (!tupleState) {
        tupleState = {
          key: connKey,
          endpointA: ordered[0],
          endpointB: ordered[1],
          sessions: []
        };
        tuples.set(connKey, tupleState);
      }
      const dirLabel =
        pkt.ip.srcIp === tupleState.endpointA.ip && pkt.tcp.srcPort === tupleState.endpointA.port
          ? 'AtoB'
          : 'BtoA';

      // 归属判定只看该四元组自己的会话序列，其他连接的夹杂互不影响。
      const sess = assignPacket(tupleState, pkt, dirLabel);
      dirAssembler(sess, dirLabel).addPacket(pkt);
      sess.packetIndices.push(pkt.index);
      if (pkt.tcp.flags.rst) sess.rstSeen = true;
      if (!(pkt.tcp.flags.syn && !pkt.tcp.flags.ack)) sess.sawNonSynNoAck = true;
    }

    const connList = [];
    for (const tupleState of tuples.values()) {
      const sessionCount = tupleState.sessions.length;
      for (const sess of tupleState.sessions) {
        connList.push({
          key: tupleState.key + (sessionCount > 1 ? '#' + sess.sessionIndex : ''),
          tupleKey: tupleState.key,
          sessionIndex: sess.sessionIndex,
          tupleSessionCount: sessionCount,
          splitReason: sess.splitReason,
          endpointA: tupleState.endpointA,
          endpointB: tupleState.endpointB,
          directionAtoB: sess.atob.finalize(),
          directionBtoA: sess.btoa.finalize(),
          packetCount: sess.packetIndices.length,
          firstPktIndex: sess.packetIndices[0],
          lastPktIndex: sess.packetIndices[sess.packetIndices.length - 1]
        });
      }
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
