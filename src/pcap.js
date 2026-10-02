/*
 * 纯本地小端经典 PCAP 解析器。
 * 只识别：
 *   - 经典 pcap（magic d4 c3 b2 a1，小端读写）
 *   - 链路层 LINKTYPE_ETHERNET (1)
 *   - Ethernet II -> IPv4 -> TCP
 * 解析在 Uint8Array 视图上做零拷贝偏移检查，不复制数据。
 *
 * 该文件可被 Worker（importScripts）与 Node 测试同时加载。
 */
(function (global, factory) {
  const api = factory();
  global.PcapLib = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  const PCAP_MAGIC = 0xa1b2c3d4; // 文件字节序 d4 c3 b2 a1（小端读出的值）
  const GLOBAL_HEADER_LEN = 24;
  const RECORD_HEADER_LEN = 16;
  const LINKTYPE_ETHERNET = 1;
  const ETHERTYPE_IPV4 = 0x0800;
  const IPPROTO_TCP = 6;
  const ETH_HEADER_LEN = 14;

  class PcapError extends Error {
    constructor(message) {
      super(message);
      this.name = 'PcapError';
      this.fatal = true; // 文件头/文件级错误：整份拒绝
    }
  }

  function u16le(view, off) {
    return view.getUint16(off, true);
  }

  function u32le(view, off) {
    return view.getUint32(off, true);
  }

  // 以太网 / IPv4 / TCP 协议头字段均为网络字节序（大端）。
  function u16be(view, off) {
    return view.getUint16(off, false);
  }

  function u32be(view, off) {
    return view.getUint32(off, false);
  }

  function ipToStr(buf, off) {
    return buf[off] + '.' + buf[off + 1] + '.' + buf[off + 2] + '.' + buf[off + 3];
  }

  /**
   * 解析整份文件。
   * @param {ArrayBuffer|Uint8Array} input
   * @param {{maxPackets?:number}} [opts]
   * @returns {{packets:Array, truncated:Object|null, stoppedReason:string|null, linkType:number, snapLen:number}}
   * @throws {PcapError} 文件头错误 / 非小端 / 不支持的链路层
   */
  function parse(input, opts) {
    const maxPackets = (opts && opts.maxPackets) || 2000;
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    if (bytes.byteLength < GLOBAL_HEADER_LEN) {
      throw new PcapError('文件不足 24 字节，缺少完整 pcap 全局文件头，整份拒绝。');
    }

    // 显式按字节读取，避免把大端/nanosec pcap 误当小端解析。
    const b0 = bytes[0], b1 = bytes[1], b2 = bytes[2], b3 = bytes[3];
    if (b0 === 0xd4 && b1 === 0xc3 && b2 === 0xb2 && b3 === 0xa1) {
      // 正确：小端经典 pcap
    } else if (b0 === 0xa1 && b1 === 0xb2 && b2 === 0xc3 && b3 === 0xd4) {
      throw new PcapError('这是大端（字节交换）pcap，本工具只接受小端 pcap，整份拒绝。');
    } else if (b0 === 0x4d && b1 === 0x3c && (b2 === 0xb2 || b2 === 0xa1)) {
      throw new PcapError('这是 pcapng 格式，本工具只接受经典小端 pcap，整份拒绝。');
    } else {
      throw new PcapError(
        '魔数不是 d4 c3 b2 a1（小端经典 pcap），实际为 ' +
          [b0, b1, b2, b3].map((x) => x.toString(16).padStart(2, '0')).join(' ') +
          '，整份拒绝。'
      );
    }

    const versionMajor = u16le(view, 4);
    const versionMinor = u16le(view, 6);
    const snapLen = u32le(view, 16);
    const linkType = u16le(view, 20) & 0xffff;
    if (linkType !== LINKTYPE_ETHERNET) {
      throw new PcapError(
        '链路层类型为 ' + linkType + '，本工具只解析以太网（LINKTYPE_ETHERNET=1），整份拒绝。'
      );
    }

    const packets = [];
    let offset = GLOBAL_HEADER_LEN;
    let truncated = null;
    let stoppedReason = null;
    let index = 0;

    while (offset < bytes.byteLength) {
      const recordFileOffset = offset;

      // 单个截断包：包头都放不下 —— 保留位置证据并停止。
      if (bytes.byteLength - offset < RECORD_HEADER_LEN) {
        truncated = {
          kind: 'record_header_truncated',
          packetIndex: index,
          fileOffset: recordFileOffset,
          availableBytes: bytes.byteLength - offset,
          neededBytes: RECORD_HEADER_LEN,
          message:
            '第 ' + (index + 1) + ' 个包的记录头在文件尾部被截断（只剩 ' +
            (bytes.byteLength - offset) + ' 字节，需要 16），保留位置证据并停止解析该包。'
        };
        stoppedReason = 'truncated_record_header';
        break;
      }

      if (index >= maxPackets) {
        truncated = {
          kind: 'packet_limit',
          packetIndex: index,
          fileOffset: recordFileOffset,
          message: '限定版最多处理 ' + maxPackets + ' 个包；第 ' + (index + 1) + ' 个包起不再解析。'
        };
        stoppedReason = 'packet_limit';
        break;
      }

      const tsSec = u32le(view, offset);
      const tsUsec = u32le(view, offset + 4);
      const inclLen = u32le(view, offset + 8); // 抓包中实际保存的长度
      const origLen = u32le(view, offset + 12); // 线上原始长度

      const dataOffset = offset + RECORD_HEADER_LEN;
      if (bytes.byteLength - dataOffset < inclLen) {
        // 单个截断包：声称的数据超出文件末尾 —— 保留证据并停止。
        truncated = {
          kind: 'record_data_truncated',
          packetIndex: index,
          fileOffset: recordFileOffset,
          dataOffset: dataOffset,
          inclLen: inclLen,
          origLen: origLen,
          availableBytes: Math.max(0, bytes.byteLength - dataOffset),
          message:
            '第 ' + (index + 1) + ' 个包声明保存 ' + inclLen + ' 字节，但文件中只剩 ' +
            Math.max(0, bytes.byteLength - dataOffset) + ' 字节；保留位置证据并停止解析该包。'
        };
        stoppedReason = 'truncated_record_data';
        break;
      }

      const pkt = parseRecord({
        index,
        bytes,
        view,
        dataOffset,
        inclLen,
        origLen,
        tsSec,
        tsUsec,
        fileOffset: recordFileOffset
      });
      packets.push(pkt);
      offset = dataOffset + inclLen;
      index++;
    }

    return {
      packets,
      truncated,
      stoppedReason,
      linkType,
      snapLen,
      version: versionMajor + '.' + versionMinor
    };
  }

  function parseRecord(ctx) {
    const { bytes, view, dataOffset, inclLen, origLen, tsSec, tsUsec, index, fileOffset } = ctx;
    const pkt = {
      index,
      fileOffset,
      tsSec,
      tsUsec,
      timestamp: tsSec + tsUsec / 1000000,
      inclLen,
      origLen,
      snapTruncated: origLen > inclLen, // 正常的 snaplen 截断（与文件截断区分）
      ignored: null, // {layer, reason}
      eth: null,
      ip: null,
      tcp: null
    };

    // ---- Ethernet ----（off 为文件绝对偏移）
    let off = dataOffset;
    const end = dataOffset + inclLen; // 当前帧抓包上界

    if (end - off < ETH_HEADER_LEN) {
      pkt.ignored = { layer: 'ethernet', reason: '以太网帧不足 14 字节' };
      return pkt;
    }
    const ethertype = u16be(view, off + 12);
    pkt.eth = { ethertype };
    off += ETH_HEADER_LEN;

    if (ethertype !== ETHERTYPE_IPV4) {
      pkt.ignored = {
        layer: 'ethernet',
        reason: 'EtherType 0x' + ethertype.toString(16) + ' 不是 IPv4 (0x0800)'
      };
      return pkt;
    }

    // ---- IPv4 ----
    if (end - off < 20) {
      pkt.ignored = { layer: 'ipv4', reason: 'IPv4 头不足 20 字节（可能被 snaplen 截断）' };
      return pkt;
    }
    const verIhl = bytes[off];
    const version = verIhl >> 4;
    const ihl = (verIhl & 0x0f) * 4;
    if (version !== 4) {
      pkt.ignored = { layer: 'ipv4', reason: 'IP 版本号不是 4' };
      return pkt;
    }
    if (ihl < 20) {
      pkt.ignored = { layer: 'ipv4', reason: 'IPv4 IHL 非法（小于 20）' };
      return pkt;
    }
    if (end - off < ihl) {
      pkt.ignored = { layer: 'ipv4', reason: 'IPv4 实际头长 ' + ihl + ' 字节未被完整捕获' };
      return pkt;
    }
    const totalLen = u16be(view, off + 2);
    const flagsFrag = u16be(view, off + 6);
    // u16 中：DF=0x4000(bit14)、MF=0x2000(bit13)，低 13 位为片偏移。
    const moreFragments = (flagsFrag & 0x2000) !== 0;
    const dontFragment = (flagsFrag & 0x4000) !== 0;
    const fragOffset = flagsFrag & 0x1fff;
    const protocol = bytes[off + 9];
    const srcIp = ipToStr(bytes, off + 12);
    const dstIp = ipToStr(bytes, off + 16);

    pkt.ip = {
      version,
      ihl,
      totalLen,
      dontFragment,
      moreFragments,
      fragOffset,
      protocol,
      srcIp,
      dstIp
    };

    // 分片（MF 或偏移非 0）无法当作完整 TCP 段，显式忽略。
    if (pkt.ip.moreFragments || fragOffset !== 0) {
      pkt.ignored = { layer: 'ipv4', reason: 'IP 分片，不参与 TCP 重组' };
      return pkt;
    }
    if (protocol !== IPPROTO_TCP) {
      pkt.ignored = {
        layer: 'ipv4',
        reason: 'IP 协议号 ' + protocol + ' 不是 TCP (6)'
      };
      return pkt;
    }

    // 依据 IP total length 限定 L4 可见范围；同时不能超过抓包上界。
    let l4End = end;
    if (totalLen >= ihl) {
      l4End = Math.min(end, off + totalLen);
    }
    off += ihl;

    // ---- TCP ----
    if (l4End - off < 20) {
      pkt.ignored = { layer: 'tcp', reason: 'TCP 头不足 20 字节（可能被 snaplen 截断）' };
      return pkt;
    }
    const srcPort = u16be(view, off);
    const dstPort = u16be(view, off + 2);
    const seq = u32be(view, off + 4);
    const ack = u32be(view, off + 8);
    const dataOffsetBytes = (bytes[off + 12] >> 4) * 4;
    const flagsByte = bytes[off + 13];
    const flagFin = (flagsByte & 0x01) !== 0;
    const flagSyn = (flagsByte & 0x02) !== 0;
    const flagRst = (flagsByte & 0x04) !== 0;
    const flagPsh = (flagsByte & 0x08) !== 0;
    const flagAck = (flagsByte & 0x10) !== 0;

    if (dataOffsetBytes < 20) {
      pkt.ignored = { layer: 'tcp', reason: 'TCP 数据偏移非法（头长小于 20）' };
      return pkt;
    }
    if (l4End - off < dataOffsetBytes) {
      pkt.ignored = {
        layer: 'tcp',
        reason: 'TCP 实际头长 ' + dataOffsetBytes + ' 字节未被完整捕获'
      };
      return pkt;
    }

    const payloadStart = off + dataOffsetBytes;
    const payloadEnd = l4End;
    const payloadLen = Math.max(0, payloadEnd - payloadStart);

    pkt.tcp = {
      srcPort,
      dstPort,
      seq,
      ack,
      flags: {
        fin: flagFin,
        syn: flagSyn,
        rst: flagRst,
        psh: flagPsh,
        ack: flagAck
      },
      payloadStart, // 指向原始文件 Uint8Array 的绝对偏移
      payloadLen
    };
    return pkt;
  }

  return {
    parse,
    PcapError,
    constants: {
      PCAP_MAGIC,
      GLOBAL_HEADER_LEN,
      RECORD_HEADER_LEN,
      LINKTYPE_ETHERNET,
      MAX_PACKETS_LIMITED: 2000
    }
  };
});
