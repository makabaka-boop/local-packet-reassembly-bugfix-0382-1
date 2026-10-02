/*
 * TCP 双向字节流重组 + 同四元组多会话拆分。
 *
 * 核心原则（对应需求）：
 *   - 先按双向四元组归并端点对，再在每个四元组内【按捕获顺序做会话拆分】：
 *     同一对 IP:port 先后建立两次 TCP 连接（端口复用）时，两次会话各自独立重组，
 *     第二次会话的字节绝不会落到第一次的序号空间里被误报为重传/冲突/缺口；
 *   - 会话拆分只依据序号与控制位事实，不做完整 TCP 状态机推断：
 *       · SYN：本方向已见过 SYN 时，ISN 相同 => 同一连接的重传 SYN；
 *         ISN 不同 => 四元组复用的新会话；会话已关闭（FIN/FIN 或 RST）后再到 SYN
 *                 => 一律新会话（即使 ISN 偶然相同）；
 *       · RST：归属当前会话并将其终止，之后同四元组的包进入新会话；
 *       · FIN：只关闭本方向；两个方向都 FIN 后会话正常关闭。半关闭期间另一方向
 *         继续到达的数据仍属同一会话。关闭后的尾随纯 ACK / 序号仍在旧窗口内的
 *         重传段归旧会话，不凭空造会话；窗口外的数据则开新会话；
 *       · 没有任何 SYN/FIN/RST 证据的单向片段：按一个“中途捕获”会话处理，
 *         不猜测、不乱拆。
 *   - 每个会话的每个方向独立重组；相同字节的重传重叠去重（不重复计数、不伪造内容）；
 *   - 缺失区间显式留空（gap），绝不拿后到字节填补成“看起来连续”的流；
 *   - 重叠位置字节不一致 => 标记 conflict；展示保留“文件中先捕获”的字节，
 *     但每个冲突位置都完整列出各到达包的实际字节与包号，不凭到达顺序悄悄覆盖；
 *   - 32 位序号回绕：以每方向锚点（SYN 的 ISN，否则首个数据段的 seq）展开成
 *     单调序号空间（RFC1986 风格 signed diff），回绕处可自然连续拼接；
 *   - 若段间跨度达到 2^31（8MB 文件内物理上不可能），标记序号歧义异常，
 *     只展示事实、不猜测。
 *
 * 单方向两遍算法（在拆好的会话内）：
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
      this.segments = []; // 文件捕获顺序的数据段（start 在 addPacket 时就地展开）
      this.packets = []; // 该方向所有 TCP 包（含纯控制段）
      this.anchorRaw = null; // 展开坐标用的原始 32 位锚点
      this.anchorPkt = null;
      this.isnRaw = null; // SYN 的 ISN（展示用）
      this.finSeq = null; // FIN 在数据之后占用的序号（原始 32 位）
      this.anomalies = [];
      // 随 addPacket 增量维护的展开窗口（与 finalize 的水位算法同一规则），
      // 供会话拆分器判断“关闭后迟到的包是否仍属于本会话的序号窗口”。
      this.hiRaw = null;
      this.hiExp = null;
      this.loExp = null;
    }

    /**
     * 依据当前已到达水位，把一个原始 seq 展开到本会话的单调坐标。
     * 必须保证锚点已建立（调用方只在有 SYN 或数据时使用结果）。
     */
    expandSeq(rawSeq) {
      const fwd = (rawSeq - this.hiRaw) >>> 0;
      const d = fwd <= HALF2 ? fwd : fwd - TWO32;
      return this.hiExp + d;
    }

    /**
     * 一个携带数据（或给定长度）的段，其展开区间是否仍落在本会话窗口内。
     * 用于“会话已 FIN/RST 关闭后又到包”的归属：
     *   与已见数据区间重叠，或在窗口前后各 SLACK 字节以内的迟到段（尾丢重传、
     *   FIN/ACK 等）都算旧会话；跨度远超窗口（典型为新连接的 ISN）则不属于。
     * 锚点未建立（本方向只有控制包）时返回 null，表示无法用序号判定。
     */
    coversDataRange(rawSeq, len) {
      if (this.hiRaw === null) return null;
      const SLACK = 65536; // ≤8MB/2000 包限定下，远超任何真实重传/探测跨度
      const start = this.expandSeq(rawSeq);
      const end = start + len;
      // 已见数据覆盖的展开区间为 [loExp, hiExp)；锚点自身（SYN 或首数据段）在 0。
      const loExp = this.loExp;
      return end > loExp - SLACK && start < this.hiExp + SLACK;
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
      // （同一会话内 ISN 相同的重传 SYN 由会话拆分器挡在外面，不会走到这里。）
      if (this.anchorRaw === null && (t.flags.syn || t.payloadLen > 0)) {
        this.anchorRaw = t.seq;
        this.anchorPkt = pkt.index;
        this.hiRaw = t.seq;
        this.hiExp = 0;
        this.loExp = t.flags.syn ? 0 : null; // SYN 占用坐标 0；纯数据锚点的下界待数据确定
      }

      if (t.payloadLen > 0) {
        // 展开水位以【段尾】表示：必须用 (seq+len) 推进，否则下一段 fwd 会少算
        // 本段长度，在回绕边界产生 off-by-segment-length 错位。≤8MB 跨度远小于 2^31。
        const start = this.expandSeq(t.seq);
        const end = start + t.payloadLen;
        const advance = (t.seq - this.hiRaw) >>> 0;
        if (advance <= HALF2 && advance > 0 && t.seq < this.hiRaw) {
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
          start,
          bytes: new Uint8Array(
            pkt._fileBuffer.buffer,
            pkt._fileBuffer.byteOffset + t.payloadStart,
            t.payloadLen
          )
        });
        if (this.loExp === null || start < this.loExp) this.loExp = start;
        if (end > this.hiExp) {
          this.hiRaw = (t.seq + t.payloadLen) >>> 0; // 水位推进到段尾
          this.hiExp = end;
        }
      }

      if (t.flags.fin) this.finSeq = (t.seq + Math.max(0, t.payloadLen)) >>> 0;
    }

    finalize() {
      const anchor = this.anchorRaw;
      const relBase = 0;
      // ---- 展开坐标在 addPacket 中已按同一水位规则逐段算好（s.start）----
      // 展开坐标即以锚点为 0 的相对序号空间：有 SYN 时 SYN 占 0、首字节数据为 1；
      // 无 SYN 时首个数据段 seq 为 0。回绕 / 乱序 / 缺口的处理见 addPacket 注释。
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

  /**
   * 由 parse() 的结果构建完整重组模型。
   *
   * 先按归一化双向四元组把包归到端点对，再在每个四元组内按【捕获顺序】跑一遍
   * 轻量会话拆分器：输出列表每一项是一次独立的 TCP 会话（一条流），而不是一个
   * 四元组。两次复用同一地址端口的会话因此各自独立重组，序号锚点、缺口、冲突、
   * 文本视图与导出证据都按会话归属，互不污染。
   *
   * @param {Object} parseResult
   * @param {Uint8Array} fileBuffer 原始字节（payload 为其上的视图，需要保活）
   */
  function buildModel(parseResult, fileBuffer) {
    const tuples = new Map(); // connKey -> 四元组状态（含按顺序产生的会话）
    const unclassified = [];
    let baseTs = null;

    const startSession = (st, reason, pktIndex, direction) => {
      // 取代尚处于打开状态的旧会话：其关闭过程未被抓到，留下显式说明。
      if (st.current && st.current.state === 'open') {
        st.current.state = 'superseded';
        st.current.events.push({
          type: 'superseded_open',
          pktIndex,
          direction: null,
          refOrdinal: st.sessions.indexOf(st.current) + 2 // 新会话序数 = 旧 + 1
        });
      }
      const session = {
        key: st.key,
        endpointA: st.endpointA,
        endpointB: st.endpointB,
        atob: new DirectionAssembler('AtoB'),
        btoa: new DirectionAssembler('BtoA'),
        // 每方向的 SYN/FIN 事实只在当前会话内有效，新会话重新计数。
        dirA: { synSeq: null, finSeq: null, finSeen: false },
        dirB: { synSeq: null, finSeq: null, finSeen: false },
        packetIndices: [],
        state: 'open', // open | closed_fin | reset | superseded
        events: []
      };
      st.sessions.push(session);
      st.current = session;
      if (reason) {
        session.events.push({ type: reason, pktIndex, direction });
      }
      return session;
    };

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
      const fromA = pkt.ip.srcIp === ordered[0].ip && pkt.tcp.srcPort === ordered[0].port;
      const dirName = fromA ? 'AtoB' : 'BtoA';

      let st = tuples.get(connKey);
      if (!st) {
        st = { key: connKey, endpointA: ordered[0], endpointB: ordered[1], sessions: [], current: null };
        tuples.set(connKey, st);
      }

      const flags = pkt.tcp.flags;

      // ---- 1) SYN：同一连接的重传 SYN vs 四元组复用的新会话 ----
      if (flags.syn) {
        let session = st.current;
        if (!session) {
          // 端点对的首个 SYN：普通新连接，不产生额外会话事件。
          session = startSession(st, null, pkt.index, dirName);
        } else if (session.state !== 'open') {
          // 关闭/复位后再到 SYN：一律新会话（即使 ISN 偶然相同）。
          const reason = session.state === 'reset' ? 'resumed_after_reset' : 'resumed_after_close';
          session = startSession(st, reason, pkt.index, dirName);
        } else {
          const dirState = fromA ? session.dirA : session.dirB;
          const assembler = fromA ? session.atob : session.btoa;
          if (dirState.synSeq === null) {
            // 本方向此前没抓到 SYN：若数据锚点已定且 ISN 与数据序号不连续，
            // 这是中途捕获片段之后另一条复用连接的 SYN => 新会话。
            if (assembler.anchorRaw !== null && assembler.anchorRaw !== pkt.tcp.seq) {
              session = startSession(st, 'midcapture_syn_isn', pkt.index, dirName);
            }
            // 否则是同一连接在 SYN 丢失后补抓到的 SYN，留在本会话。
          } else if (dirState.synSeq !== pkt.tcp.seq) {
            // 已见过 SYN 且 ISN 不同 => 新会话；ISN 相同则为重传 SYN，留在本会话。
            session = startSession(st, 'new_syn', pkt.index, dirName);
          }
        }
        const ds = fromA ? session.dirA : session.dirB;
        if (ds.synSeq === null) ds.synSeq = pkt.tcp.seq;
        (fromA ? session.atob : session.btoa).addPacket(pkt);
        session.packetIndices.push(pkt.index);
        continue;
      }

      // ---- 2) 非 SYN 包：没有活动会话 => 一段“中途捕获（未见握手）”会话 ----
      if (!st.current) {
        startSession(st, 'midcapture_data', pkt.index, dirName);
      }

      const session = st.current;
      const assembler = fromA ? session.atob : session.btoa;
      const dirState = fromA ? session.dirA : session.dirB;

      // ---- 3) RST：复位当前会话（关闭后的 RST 仅作为该会话证据，不改变状态）----
      if (flags.rst) {
        assembler.addPacket(pkt);
        session.packetIndices.push(pkt.index);
        if (session.state === 'open') {
          session.state = 'reset';
          session.events.push({ type: 'closed_reset', pktIndex: pkt.index, direction: dirName });
        }
        continue;
      }

      // ---- 4) 已关闭/复位会话的尾随数据：窗口内迟到重传归旧会话；窗口外另开新会话 ----
      // 纯 ACK 或序号无法判定（无锚点）时一律归旧会话，绝不凭空造会话。
      if (session.state !== 'open' && pkt.tcp.payloadLen > 0) {
        const inWindow = assembler.coversDataRange(pkt.tcp.seq, pkt.tcp.payloadLen);
        if (inWindow === false) {
          const next = startSession(st, 'data_after_close_new', pkt.index, dirName);
          (fromA ? next.atob : next.btoa).addPacket(pkt);
          next.packetIndices.push(pkt.index);
          continue;
        }
      }

      // ---- 5) 常规归属：数据 / ACK / FIN ----
      assembler.addPacket(pkt);
      session.packetIndices.push(pkt.index);

      // FIN 只关闭本方向；双向 FIN 才整体正常关闭（半关闭期间对端数据仍属本会话）。
      if (flags.fin && session.state === 'open') {
        dirState.finSeen = true;
        dirState.finSeq = (pkt.tcp.seq + Math.max(0, pkt.tcp.payloadLen)) >>> 0;
        if (session.dirA.finSeen && session.dirB.finSeen) {
          session.state = 'closed_fin';
          session.events.push({ type: 'closed_graceful', pktIndex: pkt.index, direction: dirName });
        }
      }
    }

    // ---- 输出：每个会话一条流 ----
    const connList = [];
    for (const st of tuples.values()) {
      st.sessions.forEach((session, i) => {
        const ordinal = i + 1;
        const events = session.events.map((ev) => ({
          type: ev.type,
          pktIndex: ev.pktIndex,
          direction: ev.direction,
          message: buildEventMessage(ev.type, ordinal, ev.refOrdinal)
        }));
        const dirA = session.atob.finalize();
        const dirB = session.btoa.finalize();
        injectSessionEvents(dirA, events, 'AtoB');
        injectSessionEvents(dirB, events, 'BtoA');

        connList.push({
          key: session.key,
          endpointA: session.endpointA,
          endpointB: session.endpointB,
          sessionOrdinal: ordinal,
          sessionCountInTuple: st.sessions.length,
          state: session.state,
          events,
          directionAtoB: dirA,
          directionBtoA: dirB,
          packetCount: session.packetIndices.length,
          firstPktIndex: session.packetIndices[0],
          lastPktIndex: session.packetIndices[session.packetIndices.length - 1]
        });
      });
    }
    connList.sort((a, b) => a.firstPktIndex - b.firstPktIndex);

    return {
      baseTimestamp: baseTs,
      packetTotal: parseResult.packets.length,
      tcpConnectionCount: connList.length, // 流（TCP 会话）总数
      endpointPairCount: tuples.size, // 不同端点对（四元组）数
      unclassifiedCount: unclassified.length,
      unclassified,
      connections: connList,
      truncated: parseResult.truncated,
      stoppedReason: parseResult.stoppedReason,
      snapLen: parseResult.snapLen,
      version: parseResult.version
    };
  }

  /** 会话边界事件 -> 统一的中文证据说明（保证各视图/导出引用一致）。 */
  function buildEventMessage(type, ordinal, refOrdinal) {
    switch (type) {
      case 'new_syn':
        return '见到 ISN 与上一会话（#' + (ordinal - 1) +
          '）不同的新 SYN：同一端点对端口复用，已拆为独立会话 #' + ordinal +
          '，两段数据各自重组，互不做重传去重或冲突判定。';
      case 'resumed_after_close':
        return '上一会话（#' + (ordinal - 1) + '）双向 FIN 正常关闭后再次见到 SYN，会话 #' +
          ordinal + ' 为端口复用的新连接。';
      case 'resumed_after_reset':
        return '上一会话（#' + (ordinal - 1) + '）被 RST 异常复位后再次见到 SYN，会话 #' +
          ordinal + ' 为端口复用的新连接。';
      case 'midcapture_syn_isn':
        return '未抓到握手、先有数据；随后捕获到的 SYN 的 ISN 与数据序号不连续，已按端口复用拆为会话 #' +
          ordinal + '（若实为同一连接的迟到 SYN，可用包号与序号核对）。';
      case 'midcapture_data':
        return '本会话未捕获到 SYN 握手（中途片段），以首个数据段 seq 为锚点独立重组，未对连接归属做猜测。';
      case 'data_after_close_new':
        return '上一会话（#' + (ordinal - 1) + '）关闭后到达的数据段序号远在其窗口之外，已按新会话 #' +
          ordinal + ' 处理。';
      case 'closed_graceful':
        return '双向 FIN：会话正常关闭。此后的纯 ACK 与窗口内重传仍归本会话，SYN/窗口外数据另开新会话。';
      case 'closed_reset':
        return 'RST：会话被异常复位。此后的纯 ACK 与窗口内重传仍归本会话，SYN/窗口外数据另开新会话。';
      case 'superseded_open':
        return '未见 FIN/RST 即被会话 #' + refOrdinal +
          ' 的新 SYN 取代：关闭过程未被抓到（或旧连接异常终止）；本会话全部字节与包证据原样保留。';
      default:
        return type;
    }
  }

  /**
   * 把会话边界事件附到对应方向的异常列表最前面（会话级证据优先展示）。
   * 关闭/复位/新建这类“整条会话”事实在两个方向都展示；
   * 方向本身已在 ev.direction 的事件只在该方向展示。
   */
  const CONNECTION_WIDE_EVENTS = {
    new_syn: true,
    resumed_after_close: true,
    resumed_after_reset: true,
    midcapture_syn_isn: true,
    midcapture_data: true,
    data_after_close_new: true,
    closed_graceful: true,
    closed_reset: true,
    superseded_open: true
  };
  function injectSessionEvents(dirOutput, events, direction) {
    const extra = [];
    for (const ev of events) {
      if (!CONNECTION_WIDE_EVENTS[ev.type] && ev.direction !== null && ev.direction !== direction) {
        continue;
      }
      extra.push({ type: ev.type, pktIndex: ev.pktIndex, message: ev.message, sessionEvent: true });
    }
    dirOutput.anomalies = extra.concat(dirOutput.anomalies);
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
