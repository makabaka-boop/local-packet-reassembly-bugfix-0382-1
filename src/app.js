/*
 * 页面主程序：
 *   - 仅在浏览器本地读取文件并交给 Worker；文件绝不上传；
 *   - 会话用递增 token 标识：重新导入 / 取消会 terminate 旧 Worker，
 *     迟到结果一律丢弃，不能替换当前文件；
 *   - 8MB / 2000 包限制；文件头错误整份拒绝，截断包保留证据并停止。
 */
(function () {
  'use strict';

  const MAX_FILE_BYTES = 8 * 1024 * 1024;
  const MAX_PACKETS = 2000;
  const MAX_HEX_RENDER_BYTES = 64 * 1024; // 页面渲染上限，导出仍是完整内容

  const el = (id) => document.getElementById(id);
  const ui = {
    fileInput: el('fileInput'),
    pickLabel: el('pickLabel'),
    cancelBtn: el('cancelBtn'),
    exportBtn: el('exportBtn'),
    exportTextBtn: el('exportTextBtn'),
    dropZone: el('dropZone'),
    banner: el('banner'),
    main: el('main'),
    connList: el('connList'),
    connCount: el('connCount'),
    uncCount: el('uncCount'),
    uncToggle: el('unclassifiedToggle'),
    uncPanel: el('uncPanel'),
    uncClose: el('unclassifiedClose'),
    uncBody: el('uncBody'),
    connTitle: el('connTitle'),
    connStats: el('connStats'),
    dirAtoB: el('dirAtoB'),
    dirBtoA: el('dirBtoA'),
    packetsBody: el('packetsBody'),
    gapsView: el('gapsView'),
    conflictsView: el('conflictsView'),
    textView: el('textView'),
    hexView: el('hexView'),
    hexCapNote: el('hexCapNote'),
    anomaliesView: el('anomaliesView'),
    statusLine: el('statusLine')
  };

  // ---- 会话状态 ----
  let sessionToken = 0;
  let session = null; // {worker, fileName, fileSize, model, snapshot} | null
  let selectedConn = 0;
  let selectedDir = 'AtoB';
  let activeTab = 'packets';

  function setStatus(text) {
    ui.statusLine.textContent = text;
  }

  function showBanner(kind, html) {
    ui.banner.className = 'banner ' + kind;
    ui.banner.innerHTML = html;
  }
  function hideBanner() {
    ui.banner.className = 'banner hidden';
    ui.banner.textContent = '';
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }
  function hex2(n) {
    return n.toString(16).padStart(2, '0');
  }

  // ---- 文件读入（仅本地）----
  async function handleFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      // 超限：不启动 Worker，旧结果保持不动并明确告知。
      showBanner(
        'fatal',
        '文件 <b>' + escapeHtml(file.name) + '</b> 为 ' + file.size.toLocaleString() +
          ' 字节，超过限定版 8 MB（' + MAX_FILE_BYTES.toLocaleString() + ' 字节）上限，已拒绝读取。'
      );
      setStatus('已拒绝：超过 8 MB 上限。');
      return;
    }

    // 开始新会话：先终结旧 Worker，使它的迟到结果不可能替换当前文件。
    beginNewSession(file);

    let buffer;
    try {
      buffer = await file.arrayBuffer();
    } catch (e) {
      if (!isCurrentSession(sessionToken)) return; // 已被取消/替换
      showBanner('fatal', '本地读取文件失败：' + escapeHtml(e.message));
      setStatus('读取失败。');
      return;
    }
    if (!isCurrentSession(sessionToken)) return; // 读取期间已重新导入/取消：结果作废

    const token = sessionToken;
    let worker;
    try {
      worker = new Worker('worker.js');
    } catch (e) {
      showBanner(
        'fatal',
        '无法创建 Worker：' + escapeHtml(e.message) +
          '。若以 file:// 打开，请改用本地静态服务器（见页脚说明）。'
      );
      setStatus('Worker 创建失败。');
      return;
    }
    session.worker = worker;
    worker.onmessage = (ev) => {
      const msg = ev.data;
      // 旧 Worker 的迟到结果：直接丢弃。
      if (msg.token !== token || !isCurrentSession(token)) return;
      if (msg.ok) {
        session.model = msg.model;
        session.snapshot = msg.snapshot;
        onParsed();
      } else {
        onParseFailed(msg);
      }
    };
    worker.onerror = (ev) => {
      if (!isCurrentSession(token)) return;
      showBanner('fatal', 'Worker 运行错误：' + escapeHtml(ev.message || '(无消息)'));
      setStatus('解析失败（Worker 错误）。');
    };

    setStatus('正在 Worker 中解析 “' + file.name + '”（文件不会离开本机）…');
    worker.postMessage(
      {
        type: 'parse',
        token,
        buffer,
        fileName: file.name,
        fileSize: file.size,
        maxPackets: MAX_PACKETS
      },
      [buffer]
    );
  }

  function isCurrentSession(token) {
    return session !== null && session.token === token;
  }

  function beginNewSession(file) {
    if (session && session.worker) {
      try { session.worker.terminate(); } catch (_) { /* 忽略 */ }
    }
    sessionToken++;
    session = { token: sessionToken, worker: null, fileName: file.name, fileSize: file.size, model: null, snapshot: null };
    hideBanner();
    ui.main.classList.add('hidden');
    ui.uncPanel.classList.add('hidden');
    ui.cancelBtn.disabled = false;
    ui.exportBtn.disabled = true;
    ui.exportTextBtn.disabled = true;
    selectedConn = 0;
    selectedDir = 'AtoB';
    activeTab = 'packets';
  }

  function cancelSession() {
    if (session && session.worker) {
      try { session.worker.terminate(); } catch (_) { /* 忽略 */ }
    }
    session = null;
    sessionToken++; // 使任何在途读取/消息失效
    ui.main.classList.add('hidden');
    ui.uncPanel.classList.add('hidden');
    ui.dropZone.classList.remove('hidden');
    ui.cancelBtn.disabled = true;
    ui.exportBtn.disabled = true;
    ui.exportTextBtn.disabled = true;
    hideBanner();
    setStatus('已取消，旧 Worker 的迟到结果将被丢弃。');
  }

  function onParseFailed(msg) {
    if (msg.fatal) {
      // 文件头错误等：整份拒绝，清空视图。
      ui.main.classList.add('hidden');
      showBanner('fatal', '整份文件已拒绝：' + escapeHtml(msg.message));
      setStatus('已拒绝：文件头/格式错误。');
    } else {
      showBanner('fatal', '解析中止：' + escapeHtml(msg.message));
      setStatus('解析中止。');
    }
    ui.cancelBtn.disabled = false;
  }

  function onParsed() {
    const model = session.model;
    ui.main.classList.remove('hidden');
    ui.dropZone.classList.add('hidden');
    ui.cancelBtn.disabled = false;
    ui.exportBtn.disabled = false;
    ui.exportTextBtn.disabled = false;
    setStatus(
      '解析完成：' + model.packetTotal + ' 个包，' + model.tcpConnectionCount + ' 条 TCP 连接' +
      (model.truncated ? '；解析在文件尾部提前停止（见提示）' : '') + '。冻结快照：' +
      session.snapshot.snapshotId
    );

    // 截断 / 限量停止：保留位置证据并显式展示。
    if (model.truncated) {
      const t = model.truncated;
      showBanner(
        'warn',
        '<b>解析提前停止（位置证据已保留）</b><br>' +
          escapeHtml(t.message) +
          (t.fileOffset != null ? '<br>文件偏移：<code>' + t.fileOffset + '</code>' : '') +
          (t.inclLen != null ? '<br>声明 incl_len：<code>' + t.inclLen + '</code>，orig_len：<code>' + t.origLen + '</code>' : '')
      );
    } else {
      hideBanner();
    }

    renderConnectionList();
    renderUnclassified();
    if (model.connections.length) selectConnection(0);
    else renderEmptyConn();
  }

  // ---- 连接列表 ----
  function renderConnectionList() {
    const model = session.model;
    ui.connCount.textContent = model.connections.length;
    ui.connList.innerHTML = '';
    model.connections.forEach((conn, i) => {
      const li = document.createElement('li');
      li.className = 'conn-item' + (i === selectedConn ? ' active' : '');
      const dA = conn.directionAtoB;
      const dB = conn.directionBtoA;
      li.innerHTML =
        '<div class="ep">' + escapeHtml(conn.endpointA.key) + ' ↔ ' + escapeHtml(conn.endpointB.key) + '</div>' +
        '<div class="meta">' + conn.packetCount + ' 包' +
        ' · A→B ' + dA.coveredBytes + 'B/' + dA.gaps.length + '缺/' + dA.conflicts.length + '冲突' +
        ' · B→A ' + dB.coveredBytes + 'B/' + dB.gaps.length + '缺/' + dB.conflicts.length + '冲突' +
        '</div>';
      li.addEventListener('click', () => selectConnection(i));
      ui.connList.appendChild(li);
    });
  }

  function renderEmptyConn() {
    ui.connTitle.textContent = '没有可重组的 TCP 连接';
    ui.connStats.innerHTML = '';
    ui.packetsBody.innerHTML = '';
    ['gapsView', 'conflictsView', 'anomaliesView'].forEach((v) => (el(v).innerHTML = ''));
    ui.textView.textContent = '';
    ui.hexView.textContent = '';
  }

  function selectConnection(i) {
    selectedConn = i;
    Array.from(ui.connList.children).forEach((li, j) => li.classList.toggle('active', j === i));
    renderConnection();
  }

  function currentConnection() {
    return session.model.connections[selectedConn] || null;
  }
  function currentDirection() {
    const conn = currentConnection();
    if (!conn) return null;
    return selectedDir === 'AtoB' ? conn.directionAtoB : conn.directionBtoA;
  }

  function renderConnection() {
    const conn = currentConnection();
    if (!conn) return renderEmptyConn();
    ui.connTitle.textContent = conn.endpointA.key + '  ↔  ' + conn.endpointB.key;
    ui.dirAtoB.textContent = 'A → B  (' + conn.endpointA.key + '  →  ' + conn.endpointB.key + ')';
    ui.dirBtoA.textContent = 'B → A  (' + conn.endpointB.key + '  →  ' + conn.endpointA.key + ')';
    ui.dirAtoB.classList.toggle('active', selectedDir === 'AtoB');
    ui.dirBtoA.classList.toggle('active', selectedDir === 'BtoA');
    renderActivePanel();
  }

  function renderConnStats() {
    const d = currentDirection();
    ui.connStats.innerHTML =
      '<span>包 <b>' + d.packetCount + '</b></span>' +
      '<span>数据段 <b>' + d.segmentCount + '</b></span>' +
      '<span>已覆盖字节 <b>' + d.coveredBytes + '</b></span>' +
      '<span class="gap">缺口 <b>' + d.gaps.length + '</b> 个 / ' + d.gapBytes + ' 字节</span>' +
      '<span class="conflict">冲突 <b>' + d.conflicts.length + '</b> 字节</span>' +
      '<span>跨度 <b>' + d.totalSpan + '</b></span>' +
      (d.isnRaw !== null ? '<span class="muted">ISN 0x' + (d.isnRaw >>> 0).toString(16) + '</span>' : '<span class="muted">未见 SYN（无 ISN）</span>');
  }

  // ---- 面板 ----
  function renderActivePanel() {
    renderConnStats();
    const d = currentDirection();
    if (!d) return;
    ui.packetsBody.innerHTML = '';
    if (activeTab === 'packets') renderPackets(d);
    if (activeTab === 'gaps') renderGaps(d);
    if (activeTab === 'conflicts') renderConflicts(d);
    if (activeTab === 'text') renderText(d);
    if (activeTab === 'hex') renderHex(d);
    if (activeTab === 'anomalies') renderAnomalies(d);
  }

  function renderPackets(d) {
    const base = session.model.baseTimestamp;
    const frag = document.createDocumentFragment();
    for (const p of d.packets) {
      const tr = document.createElement('tr');
      const notes = [];
      if (p.retransmitBytes > 0) notes.push('<span class="tag retrans">重传去重 ' + p.retransmitBytes + '</span>');
      if (p.conflictBytes > 0) notes.push('<span class="tag conflict">冲突 ' + p.conflictBytes + '</span>');
      if (p.snapTruncated) notes.push('<span class="tag snap">snaplen 截断</span>');
      tr.innerHTML =
        '<td>' + (p.pktIndex + 1) + '</td>' +
        '<td>' + (p.timestamp - base).toFixed(6) + '</td>' +
        '<td>' + escapeHtml(p.flagsText) + '</td>' +
        '<td>0x' + (p.seq >>> 0).toString(16).padStart(8, '0') + '</td>' +
        '<td>' + (p.relSeq === null ? '—' : p.relSeq) + '</td>' +
        '<td>0x' + (p.ack >>> 0).toString(16).padStart(8, '0') + '</td>' +
        '<td>' + p.payloadLen + '</td>' +
        '<td>' + p.retransmitBytes + '</td>' +
        '<td>' + p.conflictBytes + '</td>' +
        '<td class="wrap">' + notes.join(' ') + '</td>';
      frag.appendChild(tr);
    }
    ui.packetsBody.appendChild(frag);
    if (!d.packets.length) {
      ui.packetsBody.innerHTML = '<tr><td colspan="10" class="empty">该方向没有 TCP 包。</td></tr>';
    }
  }

  function renderGaps(d) {
    if (!d.gaps.length) {
      ui.gapsView.innerHTML = '<div class="empty">没有缺口：该方向已覆盖区间内所有字节均有来源。</div>';
      return;
    }
    ui.gapsView.innerHTML = d.gaps
      .map((g, i) => {
        const relStart = g.start + d.relBase;
        const relEnd = g.end + d.relBase;
        return (
          '<div class="gap-card">缺口 #' + (i + 1) +
          (g.leading ? '（连接起点之前的前置缺口）' : '') +
          '<div class="pos">相对序号区间 [' + relStart + ', ' + relEnd + ') · 长度 ' + g.length + ' 字节</div>' +
          (g.length >= 0x80000000 ? '<div class="muted">跨度达到 2^31：可能为序号回绕歧义，已按缺口显式留空，未猜测内容。</div>' : '') +
          '<div class="muted">缺口处不填充、不拼接任何字节；文本/十六进制视图均显式标注。</div></div>'
        );
      })
      .join('');
  }

  function byteInfo(entry) {
    return '包 #' + (entry.pktIndex + 1) + ' 字节 0x' + hex2(entry.byte) + ' (' + entry.byte + ')';
  }

  function renderConflicts(d) {
    if (!d.conflicts.length) {
      ui.conflictsView.innerHTML = '<div class="empty">没有重叠冲突：所有重叠位置的字节一致（仅重传去重）。</div>';
      return;
    }
    ui.conflictsView.innerHTML = d.conflicts
      .map((c, i) => {
        const kept = '0x' + hex2(c.keptByte);
        const lines = c.packets
          .map((p, j) => (j === 0
            ? '<div>保留（文件中先捕获）：' + byteInfo(p) + '</div>'
            : '<div>不一致到达：' + byteInfo(p) + '</div>'))
          .join('');
        return (
          '<div class="conflict-card">冲突 #' + (i + 1) +
          '<div class="pos">相对序号位置 ' + c.relPos + '（展开坐标 ' + c.pos + '）· 保留字节 ' + kept + '</div>' +
          '<div class="bytes-line">' + lines + '</div>' +
          '<div class="muted">重叠字节不一致；未凭到达顺序覆盖内容，各方证据均保留。</div></div>'
        );
      })
      .join('');
  }

  function renderText(d) {
    if (!d.runs.length) {
      ui.textView.textContent = '（该方向没有有效载荷）';
      return;
    }
    const esc = escapeHtml(d.text);
    ui.textView.innerHTML = esc.replace(/␠\[[^\]]*\]/g, (m) => '<span class="gapmark">' + m + '</span>');
  }

  function renderAnomalies(d) {
    const all = d.anomalies.slice();
    if (d.anchorRaw === null) {
      all.unshift({ message: '该方向未见 SYN 也无数据段，无法定义相对序号锚点。' });
    }
    if (!all.length) {
      ui.anomaliesView.innerHTML = '<div class="empty">未发现序号歧义等异常。</div>';
      return;
    }
    ui.anomaliesView.innerHTML = all
      .map((a) => '<div class="ano-card">' +
        (a.type ? '<span class="tag conflict">' + escapeHtml(a.type) + '</span> ' : '') +
        escapeHtml(a.message) + '</div>')
      .join('');
  }

  /**
   * 十六进制视图：按 run 输出，run 之间显式打印缺口标记；
   * 冲突字节红底标注。渲染量超过上限时截断展示（导出不受影响）。
   */
  function renderHex(d) {
    if (!d.runs.length) {
      ui.hexView.textContent = '（该方向没有有效载荷）';
      ui.hexCapNote.textContent = '';
      return;
    }
    const conflictPositions = new Set(d.conflicts.map((c) => c.pos));
    const lines = [];
    let rendered = 0;
    let capped = false;
    let leadingGap = d.leadingGap;
    if (leadingGap) {
      lines.push('<span class="gapmark">␠ 前置缺口 ' + leadingGap.length +
        ' 字节（相对序号 ' + (leadingGap.start + d.relBase) + '..' + (leadingGap.end + d.relBase - 1) + ' 无数据，留空）</span>');
    }

    for (let ri = 0; ri < d.runs.length && !capped; ri++) {
      const run = d.runs[ri];
      if (ri > 0) {
        const g = d.gaps.find((x) => x.start === d.runs[ri - 1].end && x.end === run.start);
        lines.push('<span class="gapmark">␠ 缺口 ' + (g ? g.length : run.start - d.runs[ri - 1].end) +
          ' 字节（相对序号 ' + (d.runs[ri - 1].relEnd + 1) + '..' + run.relStart + '，未填充）</span>');
      }
      for (let off = 0; off < run.bytes.length && !capped; ) {
        if (rendered >= MAX_HEX_RENDER_BYTES) { capped = true; break; }
        const addr = run.start + off + d.relBase;
        const hex = [];
        const ascii = [];
        for (let k = 0; k < 16 && off < run.bytes.length; k++, off++) {
          if (rendered >= MAX_HEX_RENDER_BYTES) { capped = true; break; }
          const b = run.bytes[off];
          const absPos = run.start + off;
          const isConflict = conflictPositions.has(absPos);
          hex.push((isConflict ? '<b class="c">' : '') + hex2(b) + (isConflict ? '</b>' : ''));
          ascii.push(b >= 32 && b < 127 ? escapeHtml(String.fromCharCode(b)) : '.');
          rendered++;
        }
        lines.push(
          '<span class="addr">' + addr.toString(16).padStart(8, '0') + '</span>' +
          hex.join(' ').padEnd(16 * 3 - 1) +
          '  <span class="sep">│</span>' + ascii.join('')
        );
      }
    }
    ui.hexView.innerHTML = lines.join('\n');
    ui.hexCapNote.textContent = capped
      ? '页面仅渲染前 ' + MAX_HEX_RENDER_BYTES.toLocaleString() + ' 字节，完整内容请使用导出。'
      : '共渲染 ' + rendered.toLocaleString() + ' 字节（含 ' + d.conflicts.length + ' 个冲突标注）。';
  }

  // ---- 未分类包 ----
  function renderUnclassified() {
    const model = session.model;
    ui.uncCount.textContent = model.unclassifiedCount;
    ui.uncBody.innerHTML = model.unclassified
      .map((p) => '<tr><td>' + (p.pktIndex + 1) + '</td>' +
        '<td>' + (model.baseTimestamp === null ? 0 : (p.timestamp - model.baseTimestamp).toFixed(6)) + '</td>' +
        '<td>' + p.inclLen + '</td>' +
        '<td class="wrap">' + escapeHtml(p.ignored ? p.ignored.layer + ' / ' + p.ignored.reason : '未知') + '</td></tr>')
      .join('');
  }

  // ---- 导出：引用当前冻结快照，不实时重算 ----
  function downloadBlob(blob, name) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 1000);
  }

  function exportJson() {
    if (!session || !session.snapshot) return;
    const blob = new Blob([JSON.stringify(session.snapshot, null, 2)], { type: 'application/json' });
    downloadBlob(blob, session.fileName.replace(/\.[^.]*$/, '') + '.frozen.json');
    setStatus('已导出冻结快照：' + session.snapshot.snapshotId + '（不随后续操作变化）。');
  }

  function exportText() {
    if (!session || !session.snapshot) return;
    // 严格引用当前冻结快照（不读取可能变化的实时 model）。
    const frozenConns = session.snapshot.model.connections;
    const conn = frozenConns[selectedConn];
    if (!conn) return;
    const d = selectedDir === 'AtoB' ? conn.directionAtoB : conn.directionBtoA;
    const header =
      '# 导出自冻结快照 ' + session.snapshot.snapshotId + '\n' +
      '# 文件: ' + session.fileName + '\n' +
      '# 连接: ' + conn.key + '\n' +
      '# 方向: ' + selectedDir + '\n' +
      '# 缺口已以 ␠[...] 显式标注，未做任何填充\n\n';
    const blob = new Blob([header + d.text], { type: 'text/plain;charset=utf-8' });
    downloadBlob(blob, session.fileName.replace(/\.[^.]*$/, '') + '.' + selectedDir + '.txt');
  }

  // ---- 事件绑定 ----
  ui.fileInput.addEventListener('change', (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) handleFile(f);
    ui.fileInput.value = '';
  });
  ui.cancelBtn.addEventListener('click', cancelSession);
  ui.exportBtn.addEventListener('click', exportJson);
  ui.exportTextBtn.addEventListener('click', exportText);

  ['dragover', 'dragenter'].forEach((evt) =>
    ui.dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      ui.dropZone.classList.add('drag');
    })
  );
  ['dragleave', 'drop'].forEach((evt) =>
    ui.dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      ui.dropZone.classList.remove('drag');
    })
  );
  ui.dropZone.addEventListener('drop', (e) => {
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) handleFile(f);
  });

  // 整个窗口拖入也支持（避免拖到非投放区时浏览器直接打开文件）。
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    if (e.target.closest('#dropZone')) return;
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) handleFile(f);
  });

  ui.dirAtoB.addEventListener('click', () => { selectedDir = 'AtoB'; renderConnection(); });
  ui.dirBtoA.addEventListener('click', () => { selectedDir = 'BtoA'; renderConnection(); });

  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      activeTab = btn.dataset.tab;
      document.querySelectorAll('.tab').forEach((b) => b.classList.toggle('active', b === btn));
      document.querySelectorAll('.panel').forEach((p) =>
        p.classList.toggle('active', p.dataset.panel === activeTab));
      renderActivePanel();
    });
  });

  ui.uncToggle.addEventListener('click', () => ui.uncPanel.classList.toggle('hidden'));
  ui.uncClose.addEventListener('click', () => ui.uncPanel.classList.add('hidden'));
})();
