#include "source/extensions/filters/network/thrift_proxy/ttheader_transport_impl.h"

#include <limits>

#include "envoy/common/exception.h"
#include "envoy/http/header_formatter.h"

#include "source/common/buffer/buffer_impl.h"

#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_replace.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ThriftProxy {

namespace {

// header info 段的最小合法长度：PROTOCOL ID(1) + NUM TRANSFORMS(1)。
constexpr int32_t MinHeaderInfoSize = 2;

// LowerCaseString 不允许这三个字符。绝大多数 key 不含它们，因此先探测再替换，
// 避免无条件构造新串（现有 HeaderTransportImpl 就是无条件 StrReplaceAll，
// 每个 key 每请求都要多一次堆分配）。
constexpr absl::string_view IllegalHeaderChars("\0\n\r", 3);

std::string sanitizeKey(std::string key) {
  if (absl::string_view(key).find_first_of(IllegalHeaderChars) == absl::string_view::npos) {
    return key; // 热路径：无分配
  }
  return absl::StrReplaceAll(key, {{std::string(1, '\0'), ""}, {"\n", ""}, {"\r", ""}});
}

} // namespace

const std::string& TTHeaderTransportImpl::aclTokenKey() {
  // 与 kitex/pkg/remote/transmeta/metakey.go 的 GDPRToken 一致：
  // metainfo.PrefixTransient("RPC_TRANSIT_") + "gdpr-token"
  CONSTRUCT_ON_FIRST_USE(std::string, "RPC_TRANSIT_gdpr-token");
}

TTHeaderIntKeyNameValues::TTHeaderIntKeyNameValues() {
  // 顺序必须与 metakey.go 的 iota 严格一致。
  by_id_ = {
      &MeshVersion,      // 0
      &TransportType,    // 1
      &LogId,            // 2
      &FromService,      // 3
      &FromCluster,      // 4
      &FromIdc,          // 5
      &ToService,        // 6
      &ToCluster,        // 7
      &ToIdc,            // 8
      &ToMethod,         // 9
      &Env,              // 10
      &DestAddress,      // 11
      &RpcTimeout,       // 12
      &ReadTimeout,      // 13
      &RingHashKey,      // 14
      &DdpTag,           // 15
      &WithMeshHeader,   // 16
      &ConnectTimeout,   // 17
      &SpanContext,      // 18
      &ShortConnection,  // 19
      &FromMethod,       // 20
      &StressTag,        // 21
      &MsgType,          // 22
      &HttpContentType,  // 23
      &RawRingHashKey,   // 24
      &LbType,           // 25
  };
}

bool TTHeaderIntKeyNameValues::toId(const Http::LowerCaseString& name, uint16_t& out) const {
  for (uint16_t i = 0; i < by_id_.size(); i++) {
    if (*by_id_[i] == name) {
      out = i;
      return true;
    }
  }
  return false;
}

uint8_t TTHeaderTransportImpl::drainUint8(Buffer::Instance& buffer, int32_t& remaining,
                                          const char* what) {
  if (remaining < 1) {
    throw EnvoyException(fmt::format("ttheader: header too small reading {}", what));
  }
  const uint8_t v = buffer.peekBEInt<uint8_t>();
  buffer.drain(1);
  remaining -= 1;
  return v;
}

uint16_t TTHeaderTransportImpl::drainUint16(Buffer::Instance& buffer, int32_t& remaining,
                                            const char* what) {
  if (remaining < 2) {
    throw EnvoyException(fmt::format("ttheader: header too small reading {}", what));
  }
  const uint16_t v = buffer.peekBEInt<uint16_t>();
  buffer.drain(2);
  remaining -= 2;
  return v;
}

std::string TTHeaderTransportImpl::drainString16(Buffer::Instance& buffer, int32_t& remaining,
                                                 const char* what) {
  const uint16_t len = drainUint16(buffer, remaining, what);
  if (len == 0) {
    return {};
  }
  if (remaining < static_cast<int32_t>(len)) {
    throw EnvoyException(
        fmt::format("ttheader: header too small reading {} (need {}, have {})", what, len, remaining));
  }
  const std::string value(static_cast<char*>(buffer.linearize(len)), len);
  buffer.drain(len);
  remaining -= len;
  return value;
}

void TTHeaderTransportImpl::writeString16(Buffer::Instance& buffer, absl::string_view str) {
  if (str.size() > std::numeric_limits<uint16_t>::max()) {
    throw EnvoyException(absl::StrCat("ttheader: string too long: ", str.size()));
  }
  buffer.writeBEInt<uint16_t>(static_cast<uint16_t>(str.size()));
  if (!str.empty()) {
    buffer.add(str.data(), str.size());
  }
}

bool TTHeaderTransportImpl::decodeFrameStart(Buffer::Instance& buffer, MessageMetadata& metadata) {
  if (buffer.length() < MinDecodeBytes) {
    return false;
  }

  const int32_t frame_size = buffer.peekBEInt<int32_t>();
  if (frame_size < static_cast<int32_t>(MetaSizeNoLength) + MinHeaderInfoSize ||
      frame_size > MaxFrameSize) {
    throw EnvoyException(absl::StrCat("ttheader: invalid frame size ", frame_size));
  }

  const uint16_t magic = buffer.peekBEInt<uint16_t>(4);
  if (!isMagic(magic)) {
    throw EnvoyException(fmt::format("ttheader: invalid magic {:04x}", magic));
  }

  const uint16_t flags = buffer.peekBEInt<uint16_t>(6);
  const int32_t seq_id = buffer.peekBEInt<int32_t>(8);

  // HEADER SIZE 以 4 字节为单位。
  const uint16_t raw_header_size = buffer.peekBEInt<uint16_t>(12);
  const int32_t header_size = static_cast<int32_t>(raw_header_size) * 4;
  if (header_size < MinHeaderInfoSize || header_size > MaxHeadersSize) {
    throw EnvoyException(fmt::format("ttheader: invalid header size {} ({:04x})", header_size,
                                     raw_header_size));
  }
  if (header_size > frame_size - static_cast<int32_t>(MetaSizeNoLength)) {
    throw EnvoyException(fmt::format("ttheader: header size {} exceeds frame size {}", header_size,
                                     frame_size));
  }

  if (buffer.length() < static_cast<uint64_t>(header_size) + MinDecodeBytes) {
    return false; // 还需要更多 header 数据
  }

  buffer.drain(MinDecodeBytes);

  metadata.setFrameSize(static_cast<uint32_t>(frame_size - header_size - MetaSizeNoLength));
  metadata.setHeaderFlags(flags);
  metadata.setSequenceId(seq_id);

  int32_t remaining = header_size;

  // ---- PROTOCOL ID ----
  // 只放行 Envoy 有对应 Protocol 实现的取值；其余显式拒绝。
  // 若放任不管，Envoy 会拿 thrift binary 解析器去啃别的编码，解出的 method name
  // 与字段类型全是垃圾，表现为随机路由错误或崩溃，排查成本极高。
  const uint8_t proto_id = drainUint8(buffer, remaining, "protocol id");
  switch (static_cast<TTProtocolId>(proto_id)) {
  case TTProtocolId::ThriftBinary:
    metadata.setProtocol(ProtocolType::Binary);
    break;
  case TTProtocolId::ThriftCompact:
    metadata.setProtocol(ProtocolType::Compact);
    break;
  case TTProtocolId::KitexProtobuf:
    throw EnvoyException(
        "ttheader: unsupported protocol id 0x04 (KitexProtobuf): envoy has no matching "
        "thrift protocol implementation");
  case TTProtocolId::ThriftCompactV2:
    throw EnvoyException("ttheader: unsupported protocol id 0x03 (ThriftCompactV2)");
  case TTProtocolId::ThriftStruct:
  case TTProtocolId::ProtobufStruct:
    throw EnvoyException(fmt::format(
        "ttheader: unsupported protocol id 0x{:02x} (TTHeader streaming is out of scope)",
        proto_id));
  default:
    throw EnvoyException(fmt::format("ttheader: unknown protocol id 0x{:02x}", proto_id));
  }

  // ---- TRANSFORMS ----
  const uint8_t num_transforms = drainUint8(buffer, remaining, "transform count");
  if (num_transforms > 0) {
    // Kitex 目前不产生 transform（encode.go 里 transformIDs 恒为空）。
    // 收到即说明对端用了我们不支持的压缩，必须报错而非静默忽略 —— 否则 payload
    // 是压缩过的，后续协议层会解出乱码。
    throw EnvoyException(
        fmt::format("ttheader: transforms not supported (count={})", num_transforms));
  }

  // ---- INFO BLOCKS ----
  const bool is_request = metadata.isRequest();
  auto formatter =
      is_request ? metadata.requestHeaders().formatter() : metadata.responseHeaders().formatter();

  auto add_header = [&](const Http::LowerCaseString& key, absl::string_view value) {
    if (is_request) {
      metadata.requestHeaders().addReferenceKey(key, value);
    } else {
      metadata.responseHeaders().addReferenceKey(key, value);
    }
  };
  auto add_header_copy = [&](const Http::LowerCaseString& key, absl::string_view value) {
    if (is_request) {
      metadata.requestHeaders().addCopy(key, value);
    } else {
      metadata.responseHeaders().addCopy(key, value);
    }
  };

  while (remaining > 0) {
    const uint8_t info_id = drainUint8(buffer, remaining, "info id");
    switch (static_cast<InfoId>(info_id)) {
    case InfoId::Padding:
      continue; // 填充字节

    case InfoId::KeyValue: {
      const uint16_t count = drainUint16(buffer, remaining, "str kv count");
      for (uint16_t i = 0; i < count; i++) {
        std::string key = drainString16(buffer, remaining, "str kv key");
        // metainfo 的前缀是大写的（RPC_PERSIST_ / RPC_TRANSIT_ ...），而
        // LowerCaseString 会强制小写。必须让 formatter 记住原始大小写，
        // 否则回写时 Kitex 侧按大写前缀匹配会失败 —— 而且是静默失败。
        if (formatter) {
          formatter->processKey(key);
        }
        const std::string value = drainString16(buffer, remaining, "str kv value");
        add_header_copy(Http::LowerCaseString(sanitizeKey(std::move(key))), value);
      }
      break;
    }

    case InfoId::IntKeyValue: {
      const uint16_t count = drainUint16(buffer, remaining, "int kv count");
      for (uint16_t i = 0; i < count; i++) {
        const uint16_t key_id = drainUint16(buffer, remaining, "int kv key");
        const std::string value = drainString16(buffer, remaining, "int kv value");
        if (const auto* name = TTHeaderIntKeyNames::get().fromId(key_id); name != nullptr) {
          // 热路径：key 是进程启动时构造好的常量，按引用传递，零分配零转换。
          add_header(*name, value);
        } else {
          // 冷路径：未知 id，只能现场格式化。
          add_header_copy(Http::LowerCaseString(absl::StrCat(UnknownIntKeyPrefix, key_id)), value);
        }
      }
      break;
    }

    case InfoId::AclToken: {
      const std::string token = drainString16(buffer, remaining, "acl token");
      add_header_copy(Http::LowerCaseString(aclTokenKey()), token);
      break;
    }

    default:
      throw EnvoyException(fmt::format("ttheader: invalid info id 0x{:02x}", info_id));
    }
  }

  if (remaining > 0) {
    buffer.drain(remaining);
  }

  return true;
}

bool TTHeaderTransportImpl::decodeFrameEnd(Buffer::Instance&) { return true; }

void TTHeaderTransportImpl::encodeFrame(Buffer::Instance& buffer, const MessageMetadata& metadata,
                                        Buffer::Instance& message) {
  const uint64_t msg_size = message.length();
  if (msg_size == 0) {
    throw EnvoyException("ttheader: invalid message size 0");
  }
  if (!metadata.hasProtocol()) {
    throw EnvoyException("ttheader: missing protocol");
  }

  const bool is_request = metadata.isRequest();
  auto formatter =
      is_request ? metadata.requestHeaders().formatter() : metadata.responseHeaders().formatter();

  // 先把 header 按来源分成三类，才能按 Kitex 的写出顺序还原
  // （writeKVInfo: ACL token → StrKV → IntKV → padding）。
  // 分类依据是 header 名，而 x-tt-* 与 x-ttheader-int-* 是我们保留的前缀，
  // 与业务 StrKV 的命名空间不相交，所以往返是保真的。
  std::vector<std::pair<uint16_t, std::string>> int_kvs;
  std::vector<std::pair<std::string, std::string>> str_kvs;
  std::string acl_token;
  bool has_acl_token = false;

  const auto& int_names = TTHeaderIntKeyNames::get();
  const Http::LowerCaseString acl_key(aclTokenKey());

  auto classify = [&](const Http::HeaderEntry& header) -> Http::HeaderMap::Iterate {
    const absl::string_view raw_key = header.key().getStringView();
    const absl::string_view value = header.value().getStringView();
    const Http::LowerCaseString lc_key{std::string(raw_key)};

    uint16_t id = 0;
    if (int_names.toId(lc_key, id)) {
      int_kvs.emplace_back(id, std::string(value));
      return Http::HeaderMap::Iterate::Continue;
    }
    if (absl::StartsWith(raw_key, UnknownIntKeyPrefix)) {
      uint32_t parsed = 0;
      if (absl::SimpleAtoi(raw_key.substr(UnknownIntKeyPrefix.size()), &parsed) &&
          parsed <= std::numeric_limits<uint16_t>::max()) {
        int_kvs.emplace_back(static_cast<uint16_t>(parsed), std::string(value));
        return Http::HeaderMap::Iterate::Continue;
      }
    }
    if (lc_key == acl_key) {
      acl_token = std::string(value);
      has_acl_token = true;
      return Http::HeaderMap::Iterate::Continue;
    }
    // 普通 StrKV：用 formatter 还原原始大小写（§metainfo 大写前缀）。
    str_kvs.emplace_back(formatter ? std::string(formatter->format(raw_key)) : std::string(raw_key),
                         std::string(value));
    return Http::HeaderMap::Iterate::Continue;
  };

  if (is_request) {
    metadata.requestHeaders().iterate(classify);
  } else {
    metadata.responseHeaders().iterate(classify);
  }

  Buffer::OwnedImpl header_buffer;

  // PROTOCOL ID
  switch (metadata.protocol()) {
  case ProtocolType::Binary:
    header_buffer.writeByte(static_cast<uint8_t>(TTProtocolId::ThriftBinary));
    break;
  case ProtocolType::Compact:
    header_buffer.writeByte(static_cast<uint8_t>(TTProtocolId::ThriftCompact));
    break;
  default:
    throw EnvoyException(fmt::format("ttheader: cannot encode protocol {}",
                                     ProtocolNames::get().fromType(metadata.protocol())));
  }

  // NUM TRANSFORMS（Kitex 恒为 0）
  header_buffer.writeByte(0);

  if (has_acl_token) {
    header_buffer.writeByte(static_cast<uint8_t>(InfoId::AclToken));
    writeString16(header_buffer, acl_token);
  }

  if (!str_kvs.empty()) {
    header_buffer.writeByte(static_cast<uint8_t>(InfoId::KeyValue));
    header_buffer.writeBEInt<uint16_t>(static_cast<uint16_t>(str_kvs.size()));
    for (const auto& kv : str_kvs) {
      writeString16(header_buffer, kv.first);
      writeString16(header_buffer, kv.second);
    }
  }

  if (!int_kvs.empty()) {
    header_buffer.writeByte(static_cast<uint8_t>(InfoId::IntKeyValue));
    header_buffer.writeBEInt<uint16_t>(static_cast<uint16_t>(int_kvs.size()));
    for (const auto& kv : int_kvs) {
      header_buffer.writeBEInt<uint16_t>(kv.first);
      writeString16(header_buffer, kv.second);
    }
  }

  // padding —— 注意与 Apache THeader 的差别：
  // Apache 是 `4 - size % 4`（整除时补 4 字节），Kitex 是 `(4 - size % 4) % 4`
  // （整除时补 0 字节）。抄错会导致帧长偏移 4 字节，且只在 header 长度恰为
  // 4 的倍数时触发，表现为低频偶发解析失败。
  uint64_t header_size = header_buffer.length();
  const uint64_t padding = (4 - (header_size % 4)) % 4;
  if (padding > 0) {
    header_buffer.add("\0\0\0", padding);
    header_size += padding;
  }

  if (header_size > static_cast<uint64_t>(MaxHeadersSize)) {
    throw EnvoyException(absl::StrCat("ttheader: header too large ", header_size));
  }

  const uint64_t frame_size = header_size + msg_size + MetaSizeNoLength;
  if (frame_size > static_cast<uint64_t>(MaxFrameSize)) {
    throw EnvoyException(absl::StrCat("ttheader: frame too large ", frame_size));
  }

  buffer.writeBEInt<uint32_t>(static_cast<uint32_t>(frame_size));
  buffer.writeBEInt<uint16_t>(Magic);
  buffer.writeBEInt<uint16_t>(metadata.hasHeaderFlags() ? metadata.headerFlags() : 0);
  buffer.writeBEInt<int32_t>(metadata.hasSequenceId() ? metadata.sequenceId() : 0);
  buffer.writeBEInt<uint16_t>(static_cast<uint16_t>(header_size / 4));

  buffer.move(header_buffer);
  buffer.move(message);
}

class TTHeaderTransportConfigFactory : public TransportFactoryBase<TTHeaderTransportImpl> {
public:
  TTHeaderTransportConfigFactory() : TransportFactoryBase(TransportNames::get().TTHEADER) {}
};

/**
 * Static registration for the TTHeader transport. @see RegisterFactory.
 */
REGISTER_FACTORY(TTHeaderTransportConfigFactory, NamedTransportConfigFactory);

} // namespace ThriftProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
