#include "envoy/common/exception.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/network/thrift_proxy/ttheader_transport_impl.h"

#include "test/extensions/filters/network/thrift_proxy/ttheader_fixtures.h"
#include "test/test_common/printers.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace ThriftProxy {
namespace {

// 一帧「权威」的 Kitex TTHeader 字节，按 cloudwego/gopkg protocol/ttheader/encode.go
// 的逻辑逐字节推导得出。参数：SeqID=1, ProtocolID=0(ThriftBinary),
// IntInfo={6:"svc"}, StrInfo={}, payload=01 02 03 04 05
//
// 推导过程（保留在此，便于与 fixturegen 的输出交叉核对；若两者不一致，
// 说明我对协议的理解与 Kitex 实际行为有出入，那正是这个锚点存在的意义）：
//
//   header info 段：
//     00           PROTOCOL ID   = ThriftBinary
//     00           NUM TRANSFORMS= 0
//     10           INFO ID       = InfoIDIntKeyValue
//     00 01        条数          = 1
//     00 06        key           = 6 (ToService)
//     00 03        value 长度    = 3
//     73 76 63     "svc"
//   共 12 字节。writeSize=12，padding=(4-12%4)%4=0 —— 注意这里正是与 Apache
//   THeader 的分歧点：Apache 会补 4 字节，Kitex 补 0 字节。
//   headerInfoSize/4 = 3
//
//   总长 = 14(meta) + 12(header info) + 5(payload) = 31
//   LENGTH 字段 = 31 - 4 = 27 = 0x1B
constexpr uint8_t kKitexBasicFrame[] = {
    0x00, 0x00, 0x00, 0x1B,             // LENGTH = 27
    0x10, 0x00,                         // MAGIC = 0x1000
    0x00, 0x00,                         // FLAGS = 0
    0x00, 0x00, 0x00, 0x01,             // SEQ ID = 1
    0x00, 0x03,                         // HEADER SIZE = 3 (*4 = 12)
    0x00,                               // PROTOCOL ID = ThriftBinary
    0x00,                               // NUM TRANSFORMS = 0
    0x10,                               // INFO ID = IntKeyValue
    0x00, 0x01,                         // count = 1
    0x00, 0x06,                         // key = 6 (ToService)
    0x00, 0x03, 0x73, 0x76, 0x63,       // "svc"
    0x01, 0x02, 0x03, 0x04, 0x05,       // payload
};

void addBytes(Buffer::Instance& buffer, const uint8_t* data, size_t len) {
  buffer.add(data, len);
}

std::string hexOf(const Buffer::Instance& buffer) {
  std::string out;
  const uint64_t len = buffer.length();
  std::vector<uint8_t> tmp(len);
  buffer.copyOut(0, len, tmp.data());
  for (uint8_t b : tmp) {
    out += fmt::format("{:02x}", b);
  }
  return out;
}

class TTHeaderTransportTest : public testing::Test {
protected:
  TTHeaderTransportImpl transport_;
};

// ---------------------------------------------------------------------------
// 符合性：能否解开 Kitex 真正会发出的字节
// ---------------------------------------------------------------------------

TEST_F(TTHeaderTransportTest, DecodesAuthenticKitexFrame) {
  Buffer::OwnedImpl buffer;
  addBytes(buffer, kKitexBasicFrame, sizeof(kKitexBasicFrame));

  MessageMetadata metadata(true);
  EXPECT_TRUE(transport_.decodeFrameStart(buffer, metadata));

  EXPECT_EQ(1, metadata.sequenceId());
  EXPECT_EQ(0, metadata.headerFlags());
  EXPECT_EQ(ProtocolType::Binary, metadata.protocol());
  // frameSize 是「剩余 payload 长度」，不含 header
  EXPECT_EQ(5, metadata.frameSize());

  // IntKV key 6 应映射成语义化 header 名，而不是 x-ttheader-int-6
  const auto to_service = metadata.requestHeaders().get(TTHeaderIntKeyNames::get().ToService);
  ASSERT_FALSE(to_service.empty());
  EXPECT_EQ("svc", to_service[0]->value().getStringView());
  // 反面确认：不应同时出现数字形式
  EXPECT_TRUE(metadata.requestHeaders().get(Http::LowerCaseString("x-ttheader-int-6")).empty());

  // header 之后 buffer 里应只剩 payload
  EXPECT_EQ(5, buffer.length());
}

TEST_F(TTHeaderTransportTest, RejectsApacheTHeaderMagic) {
  // Apache THeader 的魔数 0x0FFF 必须被拒绝 —— 两者线格式不兼容，
  // 若误当作 TTHeader 解析会把 varint 当定宽整数读，解出垃圾。
  std::vector<uint8_t> frame(kKitexBasicFrame, kKitexBasicFrame + sizeof(kKitexBasicFrame));
  frame[4] = 0x0F;
  frame[5] = 0xFF;

  Buffer::OwnedImpl buffer;
  addBytes(buffer, frame.data(), frame.size());

  MessageMetadata metadata(true);
  EXPECT_THROW_WITH_REGEX(transport_.decodeFrameStart(buffer, metadata), EnvoyException,
                          "ttheader: invalid magic 0fff");
}

// ---------------------------------------------------------------------------
// §3.7 载荷协议支持边界：不支持的必须显式拒绝，不能静默错解
// ---------------------------------------------------------------------------

class TTHeaderProtocolIdTest : public TTHeaderTransportTest,
                               public testing::WithParamInterface<std::tuple<uint8_t, bool>> {};

TEST_P(TTHeaderProtocolIdTest, ProtocolIdWhitelist) {
  const uint8_t proto_id = std::get<0>(GetParam());
  const bool should_accept = std::get<1>(GetParam());

  std::vector<uint8_t> frame(kKitexBasicFrame, kKitexBasicFrame + sizeof(kKitexBasicFrame));
  frame[14] = proto_id; // PROTOCOL ID 位于固定头之后第一字节

  Buffer::OwnedImpl buffer;
  addBytes(buffer, frame.data(), frame.size());
  MessageMetadata metadata(true);

  if (should_accept) {
    EXPECT_TRUE(transport_.decodeFrameStart(buffer, metadata));
  } else {
    EXPECT_THROW(transport_.decodeFrameStart(buffer, metadata), EnvoyException);
  }
}

INSTANTIATE_TEST_SUITE_P(ProtocolIds, TTHeaderProtocolIdTest,
                         testing::Values(std::make_tuple(0x00, true),  // ThriftBinary
                                         std::make_tuple(0x02, true),  // ThriftCompact
                                         std::make_tuple(0x03, false), // ThriftCompactV2
                                         std::make_tuple(0x04, false), // KitexProtobuf
                                         std::make_tuple(0x10, false), // streaming
                                         std::make_tuple(0x11, false), // streaming
                                         std::make_tuple(0x7F, false))); // 未定义

TEST_F(TTHeaderTransportTest, RejectsTransforms) {
  // Kitex 目前不产生 transform。收到即说明 payload 被压缩过，
  // 静默忽略会让后续协议层解出乱码。
  std::vector<uint8_t> frame(kKitexBasicFrame, kKitexBasicFrame + sizeof(kKitexBasicFrame));
  frame[15] = 0x01; // NUM TRANSFORMS = 1

  Buffer::OwnedImpl buffer;
  addBytes(buffer, frame.data(), frame.size());
  MessageMetadata metadata(true);
  EXPECT_THROW_WITH_REGEX(transport_.decodeFrameStart(buffer, metadata), EnvoyException,
                          "transforms not supported");
}

// ---------------------------------------------------------------------------
// 往返保真
// ---------------------------------------------------------------------------

TEST_F(TTHeaderTransportTest, RoundTripIsByteIdentical) {
  Buffer::OwnedImpl original;
  addBytes(original, kKitexBasicFrame, sizeof(kKitexBasicFrame));
  const std::string expected = hexOf(original);

  Buffer::OwnedImpl buffer;
  addBytes(buffer, kKitexBasicFrame, sizeof(kKitexBasicFrame));

  MessageMetadata metadata(true);
  ASSERT_TRUE(transport_.decodeFrameStart(buffer, metadata));

  // decodeFrameStart 之后 buffer 里只剩 payload，直接当 message 重新编码
  Buffer::OwnedImpl reencoded;
  transport_.encodeFrame(reencoded, metadata, buffer);

  EXPECT_EQ(expected, hexOf(reencoded));
}

// §9.2 padding 陷阱：header 长度恰为 4 的倍数时，Kitex 补 0 字节而
// Apache 补 4 字节。抄错只在这种情况下触发，属于低频偶发故障。
TEST_F(TTHeaderTransportTest, PaddingIsZeroWhenHeaderIsMultipleOfFour) {
  MessageMetadata metadata(true);
  metadata.setProtocol(ProtocolType::Binary);
  metadata.setSequenceId(7);
  // 构造出 header info 恰为 4 的倍数的情况：
  // 2 (protoId+numTransforms) + 1 (infoId) + 2 (count) + 2+3 (key "abc") + 2+2 (value "xy") = 14
  // 14 % 4 = 2 → 会补 2 字节；换成 value 长度 4 则 16 % 4 == 0 → 补 0
  metadata.requestHeaders().addCopy(Http::LowerCaseString("abc"), "wxyz");

  Buffer::OwnedImpl message;
  message.add("\x01\x02\x03\x04", 4);

  Buffer::OwnedImpl out;
  transport_.encodeFrame(out, metadata, message);

  // HEADER SIZE 字段（偏移 12，uint16，单位 4 字节）
  const uint16_t header_units = out.peekBEInt<uint16_t>(12);
  const uint32_t header_size = static_cast<uint32_t>(header_units) * 4;
  EXPECT_EQ(16, header_size) << "header 恰为 16 字节时不应再补 4 字节 padding";

  // 且必须能被自己解回来
  MessageMetadata decoded(true);
  EXPECT_TRUE(transport_.decodeFrameStart(out, decoded));
  EXPECT_EQ(7, decoded.sequenceId());
}

// §9.1 metainfo 大小写：LowerCaseString 会强制小写，若不接 formatter，
// RPC_PERSIST_* 过一趟 Envoy 就变成 rpc_persist_*，Kitex 侧按大写前缀
// 匹配会静默失配。此测试锁住「解码后至少值不丢」，大小写还原由
// header_keys_preserve_case 配置 + formatter 保证（见 conn_manager 集成测试）。
TEST_F(TTHeaderTransportTest, MetainfoKeysSurviveDecode) {
  MessageMetadata metadata(true);
  metadata.setProtocol(ProtocolType::Binary);
  metadata.setSequenceId(11);
  metadata.requestHeaders().addCopy(Http::LowerCaseString("rpc_persist_tenant"), "tenant-a");

  Buffer::OwnedImpl message;
  message.add("\x01", 1);
  Buffer::OwnedImpl out;
  transport_.encodeFrame(out, metadata, message);

  MessageMetadata decoded(true);
  ASSERT_TRUE(transport_.decodeFrameStart(out, decoded));
  const auto res = decoded.requestHeaders().get(Http::LowerCaseString("rpc_persist_tenant"));
  ASSERT_FALSE(res.empty());
  EXPECT_EQ("tenant-a", res[0]->value().getStringView());
}

// 未知 IntKV id 走 fallback，不应丢数据
TEST_F(TTHeaderTransportTest, UnknownIntKeyFallsBackToNumericName) {
  MessageMetadata metadata(true);
  metadata.setProtocol(ProtocolType::Binary);
  metadata.setSequenceId(3);
  metadata.requestHeaders().addCopy(Http::LowerCaseString("x-ttheader-int-999"), "v");

  Buffer::OwnedImpl message;
  message.add("\x01", 1);
  Buffer::OwnedImpl out;
  transport_.encodeFrame(out, metadata, message);

  MessageMetadata decoded(true);
  ASSERT_TRUE(transport_.decodeFrameStart(out, decoded));
  const auto res = decoded.requestHeaders().get(Http::LowerCaseString("x-ttheader-int-999"));
  ASSERT_FALSE(res.empty());
  EXPECT_EQ("v", res[0]->value().getStringView());
}

// ACL token 走独立的 0x11 info block，编码时必须 special-case
TEST_F(TTHeaderTransportTest, AclTokenRoundTrip) {
  MessageMetadata metadata(true);
  metadata.setProtocol(ProtocolType::Binary);
  metadata.setSequenceId(5);
  metadata.requestHeaders().addCopy(Http::LowerCaseString(TTHeaderTransportImpl::aclTokenKey()),
                                    "tok-abc");

  Buffer::OwnedImpl message;
  message.add("\x01", 1);
  Buffer::OwnedImpl out;
  transport_.encodeFrame(out, metadata, message);

  // 确认写出的是 0x11 块而非普通 StrKV
  const std::string hex = hexOf(out);
  EXPECT_NE(std::string::npos, hex.find("11")) << "应包含 InfoIDACLToken";

  MessageMetadata decoded(true);
  ASSERT_TRUE(transport_.decodeFrameStart(out, decoded));
  const auto res =
      decoded.requestHeaders().get(Http::LowerCaseString(TTHeaderTransportImpl::aclTokenKey()));
  ASSERT_FALSE(res.empty());
  EXPECT_EQ("tok-abc", res[0]->value().getStringView());
}

// ---------------------------------------------------------------------------
// 增量数据：不足时必须返回 false 且不消耗 buffer
// ---------------------------------------------------------------------------

TEST_F(TTHeaderTransportTest, WaitsForMoreDataWithoutConsuming) {
  for (size_t prefix = 1; prefix < sizeof(kKitexBasicFrame) - 5; prefix++) {
    Buffer::OwnedImpl buffer;
    addBytes(buffer, kKitexBasicFrame, prefix);
    const uint64_t before = buffer.length();

    MessageMetadata metadata(true);
    bool done = false;
    EXPECT_NO_THROW(done = transport_.decodeFrameStart(buffer, metadata))
        << "前 " << prefix << " 字节不应抛异常";
    EXPECT_FALSE(done) << "前 " << prefix << " 字节不应认为解析完成";
    EXPECT_EQ(before, buffer.length()) << "未完成解析时不应消耗 buffer(prefix=" << prefix << ")";
  }
}

TEST_F(TTHeaderTransportTest, RejectsInsaneFrameSize) {
  std::vector<uint8_t> frame(kKitexBasicFrame, kKitexBasicFrame + sizeof(kKitexBasicFrame));
  frame[0] = 0x7F; // LENGTH 变成巨大值
  frame[1] = 0xFF;
  frame[2] = 0xFF;
  frame[3] = 0xFF;

  Buffer::OwnedImpl buffer;
  addBytes(buffer, frame.data(), frame.size());
  MessageMetadata metadata(true);
  EXPECT_THROW_WITH_REGEX(transport_.decodeFrameStart(buffer, metadata), EnvoyException,
                          "invalid frame size");
}

// ---------------------------------------------------------------------------
// 符合性:跑遍 Kitex 官方编码器生成的全部 fixture
//
// 与手工构造字节的区别:手工构造只能验证「实现符合我对协议的理解」，
// 而这些字节来自 Kitex 真正会发出的编码器，验证的是「实现符合 Kitex 实际行为」。
// ---------------------------------------------------------------------------

class TTHeaderFixtureTest : public testing::TestWithParam<size_t> {
protected:
  TTHeaderTransportImpl transport_;
};

TEST_P(TTHeaderFixtureTest, MatchesKitexEncoder) {
  const auto& f = TTHeaderFixtures::all()[GetParam()];
  SCOPED_TRACE(absl::StrCat(f.name, ": ", f.why));

  Buffer::OwnedImpl buffer;
  buffer.add(f.bytes.data(), f.bytes.size());

  MessageMetadata metadata(true);

  if (f.should_fail) {
    EXPECT_THROW(transport_.decodeFrameStart(buffer, metadata), EnvoyException)
        << f.name << " 应被拒绝";
    return;
  }

  ASSERT_TRUE(transport_.decodeFrameStart(buffer, metadata)) << f.name;
  EXPECT_EQ(f.seq_id, metadata.sequenceId());
  EXPECT_EQ(f.flags, metadata.headerFlags());
  EXPECT_EQ(f.payload_len, metadata.frameSize()) << "frameSize 应等于 payload 长度";
  EXPECT_EQ(f.payload_len, buffer.length()) << "解完 header 后 buffer 应只剩 payload";

  // IntKV 应落到语义化 header 名下
  for (const auto& [id, value] : f.int_info) {
    const auto* name = TTHeaderIntKeyNames::get().fromId(id);
    Http::LowerCaseString key =
        name != nullptr ? *name
                        : Http::LowerCaseString(absl::StrCat(
                              TTHeaderTransportImpl::UnknownIntKeyPrefix, id));
    const auto res = metadata.requestHeaders().get(key);
    ASSERT_FALSE(res.empty()) << "缺少 IntKV id=" << id << " (" << key.get() << ")";
    EXPECT_EQ(value, res[0]->value().getStringView()) << "IntKV id=" << id;
  }

  // StrKV 同样应完整还原。注意 header map 会把 key 小写化，
  // metainfo 的大写前缀靠 formatter 在编码时还原（见 §9.1）。
  for (const auto& [k, v] : f.str_info) {
    const auto res = metadata.requestHeaders().get(Http::LowerCaseString(k));
    ASSERT_FALSE(res.empty()) << "缺少 StrKV " << k;
    EXPECT_EQ(v, res[0]->value().getStringView()) << "StrKV " << k;
  }
}

// 每个 fixture 都必须能 decode → encode 回到逐字节相同的字节流。
//
// 注意 preserve_keys=true：Http::LowerCaseString 会强制小写，而 metainfo 的
// 前缀是大写的(RPC_PERSIST_ / RPC_TRANSIT_ ...)。只有装上 ThriftCaseHeaderFormatter
// (metadata.h:63，由配置项 header_keys_preserve_case 触发)才能还原原始大小写。
// 不加这个参数，MetainfoUppercase 这一例会往返失真 —— 见下面那个专门的反例测试。
TEST_P(TTHeaderFixtureTest, RoundTripsToIdenticalBytes) {
  const auto& f = TTHeaderFixtures::all()[GetParam()];
  if (f.should_fail) {
    return;
  }
  SCOPED_TRACE(f.name);

  Buffer::OwnedImpl original;
  original.add(f.bytes.data(), f.bytes.size());
  const std::string expected = hexOf(original);

  Buffer::OwnedImpl buffer;
  buffer.add(f.bytes.data(), f.bytes.size());
  MessageMetadata metadata(true, /*preserve_keys=*/true);
  ASSERT_TRUE(transport_.decodeFrameStart(buffer, metadata));

  Buffer::OwnedImpl reencoded;
  transport_.encodeFrame(reencoded, metadata, buffer);
  EXPECT_EQ(expected, hexOf(reencoded)) << f.name << " 往返不保真";
}

// 反例：不开 preserve_keys 时，metainfo 的大写前缀会被静默改成小写。
//
// 这条不是「已知缺陷」，而是把一个配置要求固化成可执行规格：
// Kitex 侧按大写前缀(RPC_PERSIST_ 等)做匹配，一旦被改成小写，
// metainfo 会静默消失 —— 不报错、不告警、不掉包，是最难查的那类故障。
// 因此 Envoy 配置必须开 header_keys_preserve_case。
TEST(TTHeaderMetainfoCaseTest, CaseIsLostWithoutPreserveKeys) {
  // 找到含大写 metainfo key 的那个 fixture
  const TTHeaderFixtures::Fixture* target = nullptr;
  for (const auto& f : TTHeaderFixtures::all()) {
    if (std::string(f.name) == "MetainfoUppercase") {
      target = &f;
      break;
    }
  }
  ASSERT_NE(nullptr, target) << "fixture MetainfoUppercase 缺失";

  TTHeaderTransportImpl transport;

  auto round_trip = [&](bool preserve_keys) {
    Buffer::OwnedImpl buffer;
    buffer.add(target->bytes.data(), target->bytes.size());
    MessageMetadata metadata(true, preserve_keys);
    EXPECT_TRUE(transport.decodeFrameStart(buffer, metadata));
    Buffer::OwnedImpl out;
    transport.encodeFrame(out, metadata, buffer);
    return hexOf(out);
  };

  Buffer::OwnedImpl original;
  original.add(target->bytes.data(), target->bytes.size());
  const std::string expected = hexOf(original);

  EXPECT_EQ(expected, round_trip(true)) << "开启 preserve_keys 后应逐字节保真";
  EXPECT_NE(expected, round_trip(false))
      << "未开 preserve_keys 却保真了？说明 header 大小写行为已变，"
         "§9.1 的结论和 header_keys_preserve_case 的必要性需要重新评估";
}

INSTANTIATE_TEST_SUITE_P(
    KitexFixtures, TTHeaderFixtureTest,
    testing::Range(size_t{0}, TTHeaderFixtures::all().size()),
    [](const testing::TestParamInfo<size_t>& info) {
      return std::string(TTHeaderFixtures::all()[info.param].name);
    });

// ---------------------------------------------------------------------------
// TTHeaderFramed:载荷前的内层 4 字节长度前缀
//
// Kitex 的 transport.TTHeaderFramed(= TTHeader | Framed)会在 TTHeader 之后、
// 载荷之前再插一个 4 字节长度前缀。这不是边角情况 —— 实测中 Kitex client
// 即使显式设 transport.TTHeader，最终生效的也是 TTHeader|Framed
// （SetTransportProtocol 内部是 |= 而非赋值，kitex rpcconfig.go:178）。
//
// 不处理的话，Protocol 层会从长度前缀开始读版本号，
// 报 "invalid binary protocol version 0x0000"。
// ---------------------------------------------------------------------------

// 构造一帧 TTHeaderFramed：在 kKitexBasicFrame 的载荷前插入 4 字节长度，
// 并相应调大 LENGTH 字段。
std::vector<uint8_t> makeFramedVariant() {
  const std::vector<uint8_t> base(kKitexBasicFrame, kKitexBasicFrame + sizeof(kKitexBasicFrame));
  // 原载荷是 5 字节的 01..05，替换成「4 字节长度 + 一条最小 thrift binary 消息」，
  // 否则魔数探测认不出来。
  const std::vector<uint8_t> msg = {0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
  std::vector<uint8_t> out(base.begin(), base.begin() + 26); // 头 14 + header info 12
  out.push_back(static_cast<uint8_t>(msg.size() >> 24));
  out.push_back(static_cast<uint8_t>(msg.size() >> 16));
  out.push_back(static_cast<uint8_t>(msg.size() >> 8));
  out.push_back(static_cast<uint8_t>(msg.size()));
  out.insert(out.end(), msg.begin(), msg.end());
  // 回填 LENGTH = 总长 - 4
  const uint32_t len = static_cast<uint32_t>(out.size() - 4);
  out[0] = static_cast<uint8_t>(len >> 24);
  out[1] = static_cast<uint8_t>(len >> 16);
  out[2] = static_cast<uint8_t>(len >> 8);
  out[3] = static_cast<uint8_t>(len);
  return out;
}

TEST_F(TTHeaderTransportTest, StripsInnerFramedPrefix) {
  const auto frame = makeFramedVariant();
  Buffer::OwnedImpl buffer;
  addBytes(buffer, frame.data(), frame.size());

  MessageMetadata metadata(true, /*preserve_keys=*/true);
  ASSERT_TRUE(transport_.decodeFrameStart(buffer, metadata));

  // 剥掉前缀后，buffer 应直接以 thrift 魔数开头，Protocol 层才认得
  ASSERT_GE(buffer.length(), 4);
  EXPECT_EQ(0x80010001u, buffer.peekBEInt<uint32_t>(0))
      << "剥掉内层前缀后应直接是 thrift binary 消息";
  EXPECT_EQ(buffer.length(), metadata.frameSize()) << "frameSize 应已扣除前缀";
}

TEST_F(TTHeaderTransportTest, RestoresInnerFramedPrefixOnEncode) {
  const auto frame = makeFramedVariant();
  Buffer::OwnedImpl original;
  addBytes(original, frame.data(), frame.size());
  const std::string expected = hexOf(original);

  Buffer::OwnedImpl buffer;
  addBytes(buffer, frame.data(), frame.size());
  MessageMetadata metadata(true, /*preserve_keys=*/true);
  ASSERT_TRUE(transport_.decodeFrameStart(buffer, metadata));

  Buffer::OwnedImpl reencoded;
  transport_.encodeFrame(reencoded, metadata, buffer);

  // 代理应当透明：带前缀进来就要带前缀出去，逐字节保真。
  // Kitex 两种形态都能自动识别，所以不还原也能跑通 —— 但那样 Envoy
  // 就成了会改写报文的中间人，抓包比对也失去意义。
  EXPECT_EQ(expected, hexOf(reencoded));
  // 内部标记不得泄漏到线上
  EXPECT_EQ(std::string::npos, hexOf(reencoded).find("782d74742d6672616d6564"))
      << "x-tt-framed-payload 标记不应出现在编码结果中";
}

TEST_F(TTHeaderTransportTest, LeavesUnframedPayloadAlone) {
  // 原始 fixture 的载荷不是 thrift 消息（就是 01 02 03 04 05），
  // 魔数探测两段都不命中，应保持原样不动。
  Buffer::OwnedImpl buffer;
  addBytes(buffer, kKitexBasicFrame, sizeof(kKitexBasicFrame));
  MessageMetadata metadata(true, /*preserve_keys=*/true);
  ASSERT_TRUE(transport_.decodeFrameStart(buffer, metadata));
  EXPECT_EQ(5, metadata.frameSize()) << "无内层前缀时 frameSize 不应被改动";
  EXPECT_TRUE(metadata.requestHeaders()
                  .get(TTHeaderTransportImpl::framedPayloadMarker())
                  .empty())
      << "无内层前缀时不应打标记";
}

// ---------------------------------------------------------------------------
// 静态映射表
// ---------------------------------------------------------------------------

TEST(TTHeaderIntKeyNamesTest, MatchesKitexMetakeyOrder) {
  const auto& names = TTHeaderIntKeyNames::get();
  // 顺序与 kitex/pkg/remote/transmeta/metakey.go 的 iota 一致
  EXPECT_EQ(&names.MeshVersion, names.fromId(0));
  EXPECT_EQ(&names.LogId, names.fromId(2));
  EXPECT_EQ(&names.FromService, names.fromId(3));
  EXPECT_EQ(&names.ToService, names.fromId(6));
  EXPECT_EQ(&names.ToMethod, names.fromId(9));
  EXPECT_EQ(&names.RpcTimeout, names.fromId(12));
  EXPECT_EQ(&names.LbType, names.fromId(25));
  EXPECT_EQ(nullptr, names.fromId(26));
  EXPECT_EQ(nullptr, names.fromId(999));
}

TEST(TTHeaderIntKeyNamesTest, ReverseLookupIsConsistent) {
  const auto& names = TTHeaderIntKeyNames::get();
  for (uint16_t id = 0; id <= 25; id++) {
    const auto* name = names.fromId(id);
    ASSERT_NE(nullptr, name) << "id=" << id;
    uint16_t back = 0xFFFF;
    EXPECT_TRUE(names.toId(*name, back)) << "id=" << id;
    EXPECT_EQ(id, back);
  }
  uint16_t unused = 0;
  EXPECT_FALSE(names.toId(Http::LowerCaseString("x-not-a-tt-key"), unused));
}

} // namespace
} // namespace ThriftProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
