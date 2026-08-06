#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "envoy/buffer/buffer.h"

#include "source/common/singleton/const_singleton.h"
#include "source/extensions/filters/network/thrift_proxy/metadata.h"
#include "source/extensions/filters/network/thrift_proxy/thrift.h"
#include "source/extensions/filters/network/thrift_proxy/transport.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ThriftProxy {

/**
 * TTHeader 是 CloudWeGo Kitex 的默认传输层协议。它与 Apache THeader 形似而实不同：
 * 除魔数不同（0x1000 vs 0x0FFF）外，头部所有变长整数（varint）在 TTHeader 中
 * 都是定宽整数。因此不能复用 HeaderTransportImpl，必须单独实现。
 *
 * 线格式（参见 cloudwego/gopkg protocol/ttheader/encode.go）：
 *
 *   +--------------------------------------------------------------+
 *   |                        LENGTH (uint32)                        |  不含自身
 *   +--------------------------------------------------------------+
 *   |     MAGIC (uint16 = 0x1000)    |      FLAGS (uint16)          |
 *   +--------------------------------------------------------------+
 *   |                    SEQUENCE NUMBER (int32)                    |
 *   +--------------------------------------------------------------+
 *   |  HEADER SIZE (uint16, 单位 4 字节)  | PROTOCOL ID (uint8) | ...
 *   +--------------------------------------------------------------+
 *   | NUM TRANSFORMS (uint8) | TRANSFORM IDs (uint8 each)          |
 *   +--------------------------------------------------------------+
 *   | INFO ID (uint8) | INFO DATA ...                              |
 *   +--------------------------------------------------------------+
 *   |                          PAYLOAD                              |
 *   +--------------------------------------------------------------+
 *
 * INFO ID 取值：
 *   0x00 PADDING       —— 填充字节，跳过
 *   0x01 KEY_VALUE     —— uint16 条数，然后 N 组 (uint16 len + bytes) × 2
 *   0x10 INT_KEY_VALUE —— uint16 条数，然后 N 组 (uint16 key + uint16 len + bytes)
 *   0x11 ACL_TOKEN     —— uint16 len + bytes（无条数字段）
 */
class TTHeaderTransportImpl : public Transport {
public:
  // Transport
  const std::string& name() const override { return TransportNames::get().TTHEADER; }
  TransportType type() const override { return TransportType::TTHeader; }
  bool decodeFrameStart(Buffer::Instance& buffer, MessageMetadata& metadata) override;
  bool decodeFrameEnd(Buffer::Instance& buffer) override;
  void encodeFrame(Buffer::Instance& buffer, const MessageMetadata& metadata,
                   Buffer::Instance& message) override;

  static bool isMagic(uint16_t word) { return word == Magic; }

  static constexpr uint16_t Magic = 0x1000;
  static constexpr int32_t MaxFrameSize = 0x3FFFFFFF;

  // 固定头部：MAGIC(2) + FLAGS(2) + SEQ(4) + HEADER SIZE(2)，不含 LENGTH 自身。
  static constexpr uint64_t MetaSizeNoLength = 10;
  // 起始可解码字节数：LENGTH(4) + 固定头部(10)。
  static constexpr uint64_t MinDecodeBytes = MetaSizeNoLength + 4;
  static constexpr int32_t MaxHeadersSize = 4 * 65535;

  // TTHeader 的 PROTOCOL ID 取值（gopkg protocol/ttheader/encode.go）。
  enum class TTProtocolId : uint8_t {
    ThriftBinary = 0x00,
    ThriftCompact = 0x02,
    ThriftCompactV2 = 0x03,
    KitexProtobuf = 0x04,
    ThriftStruct = 0x10,   // TTHeader Streaming
    ProtobufStruct = 0x11, // TTHeader Streaming
  };

  enum class InfoId : uint8_t {
    Padding = 0x00,
    KeyValue = 0x01,
    IntKeyValue = 0x10,
    AclToken = 0x11,
  };

  // Kitex 把 ACL token 解到 StrKV 的这个固定 key 下（metakey.go: GDPRToken =
  // metainfo.PrefixTransient + "gdpr-token"）。编码时需special-case回 0x11 块，
  // 否则往返不保真。
  static const std::string& aclTokenKey();

  // 未知 IntKV id 的 header 名前缀（冷路径 fallback）。
  static constexpr absl::string_view UnknownIntKeyPrefix = "x-ttheader-int-";

  // Kitex 用来识别载荷类型的魔数，取自 kitex pkg/remote/codec/default_codec.go:42-48。
  static constexpr uint32_t ThriftV1Magic = 0x80010000;
  static constexpr uint32_t ProtobufV1Magic = 0x90010000;
  static constexpr uint32_t MagicMask = 0xFFFF0000;

  // Kitex 的 transport.TTHeaderFramed（= TTHeader | Framed）会在 TTHeader 之后、
  // 载荷之前再插一个 4 字节长度前缀。这个前缀是冗余的（TTHeader 的 LENGTH 字段
  // 已经能推出载荷长度），但 Kitex 实际会发，且 TTHeaderFramed 是它的具名常量，
  // 说明这是常规配置而非边角情况，因此必须支持。
  //
  // 判定方式与 Kitex 自己一致（default_codec.go:380-397 checkPayload）：
  // 峰值载荷前 8 字节，看 thrift 魔数落在哪一段。
  //   bytes[0:4] 命中 → 无内层前缀
  //   bytes[4:8] 命中 → 有内层前缀，需跳过 4 字节
  //
  // 返回 true 表示存在内层 framed 前缀。数据不足 8 字节时返回 false（保守处理）。
  static bool payloadHasFramedPrefix(Buffer::Instance& buffer, uint32_t payload_len);

  // 记录「原始报文带内层 framed 前缀」的保留 header。
  //
  // 之所以要记而不是一律剥掉：代理应当透明，不该悄悄改变载荷分帧。
  // Kitex 的解码器两种形态都能自动识别（checkPayload 做同样的峰值探测），
  // 所以不还原也能跑通，但那样 Envoy 就成了会改写报文的中间人，
  // 往返不再保真，也让抓包比对失去意义。
  //
  // 该 header 仅存在于 Envoy 进程内，encodeFrame 会消费掉它，不会写到线上。
  static const Http::LowerCaseString& framedPayloadMarker();

private:
  static uint16_t drainUint16(Buffer::Instance& buffer, int32_t& remaining, const char* what);
  static uint8_t drainUint8(Buffer::Instance& buffer, int32_t& remaining, const char* what);
  static std::string drainString16(Buffer::Instance& buffer, int32_t& remaining, const char* what);
  static void writeString16(Buffer::Instance& buffer, absl::string_view str);
};

/**
 * TTHeader IntKV 的数字 key 到 Envoy header 名的静态映射表。
 *
 * 顺序与 kitex/pkg/remote/transmeta/metakey.go 的 iota 一致，不可调换。
 *
 * 之所以用编译期常量表而非运行时格式化（如 absl::StrCat("x-ttheader-int-", id)）：
 * 后者每条 IntKV 每请求都要做一次整数转字符串 + 至少三次堆分配
 * （StrCat 一次、LowerCaseString 构造一次、addCopy 再拷一次），
 * 而典型 Kitex 请求携带 5~8 条 IntKV。静态表配合 addReferenceKey 则是
 * 「数组下标取值 + key 按引用传递」，key 侧零分配零转换。
 */
class TTHeaderIntKeyNameValues {
public:
  TTHeaderIntKeyNameValues();

  // 按 IntKV 数字 key 取 header 名；未定义的 id 返回 nullptr，调用方走 fallback。
  const Http::LowerCaseString* fromId(uint16_t id) const {
    return id < by_id_.size() ? by_id_[id] : nullptr;
  }

  // 反向：header 名 → IntKV 数字 key。编码时用于把 header 还原回 IntKV 段。
  // 取 string_view 而非 LowerCaseString：header map 里存的 key 本就是小写，
  // 构造 LowerCaseString 只会白白多一次堆分配。未命中返回 false。
  bool toId(absl::string_view name, uint16_t& out) const;

  const Http::LowerCaseString MeshVersion{"x-tt-mesh-version"};
  const Http::LowerCaseString TransportType{"x-tt-transport-type"};
  const Http::LowerCaseString LogId{"x-tt-log-id"};
  const Http::LowerCaseString FromService{"x-tt-from-service"};
  const Http::LowerCaseString FromCluster{"x-tt-from-cluster"};
  const Http::LowerCaseString FromIdc{"x-tt-from-idc"};
  const Http::LowerCaseString ToService{"x-tt-to-service"};
  const Http::LowerCaseString ToCluster{"x-tt-to-cluster"};
  const Http::LowerCaseString ToIdc{"x-tt-to-idc"};
  const Http::LowerCaseString ToMethod{"x-tt-to-method"};
  const Http::LowerCaseString Env{"x-tt-env"};
  const Http::LowerCaseString DestAddress{"x-tt-dest-address"};
  const Http::LowerCaseString RpcTimeout{"x-tt-rpc-timeout"};
  const Http::LowerCaseString ReadTimeout{"x-tt-read-timeout"};
  const Http::LowerCaseString RingHashKey{"x-tt-ring-hash-key"};
  const Http::LowerCaseString DdpTag{"x-tt-ddp-tag"};
  const Http::LowerCaseString WithMeshHeader{"x-tt-with-mesh-header"};
  const Http::LowerCaseString ConnectTimeout{"x-tt-connect-timeout"};
  const Http::LowerCaseString SpanContext{"x-tt-span-context"};
  const Http::LowerCaseString ShortConnection{"x-tt-short-connection"};
  const Http::LowerCaseString FromMethod{"x-tt-from-method"};
  const Http::LowerCaseString StressTag{"x-tt-stress-tag"};
  const Http::LowerCaseString MsgType{"x-tt-msg-type"};
  const Http::LowerCaseString HttpContentType{"x-tt-http-content-type"};
  const Http::LowerCaseString RawRingHashKey{"x-tt-raw-ring-hash-key"};
  const Http::LowerCaseString LbType{"x-tt-lb-type"};

private:
  std::vector<const Http::LowerCaseString*> by_id_;
};

using TTHeaderIntKeyNames = ConstSingleton<TTHeaderIntKeyNameValues>;

} // namespace ThriftProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
