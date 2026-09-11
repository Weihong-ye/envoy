#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/ub_socket_handle_impl.h"

#include "test/test_common/environment.h"

#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "gtest/gtest.h"

extern "C" void ubsocket_iobuf_deallocate(void* raw);

namespace Envoy {
namespace Network {
namespace {

struct FakeUbsocketState {
  std::vector<std::string> rx_chunks;
  absl::flat_hash_set<void*> allocations;
  std::string written;
  int read_error{0};
  int write_error{0};
  int alloc_calls{0};
  int dealloc_calls{0};
  int batch_alloc_calls{0};
  int batch_dealloc_calls{0};
  bool fail_alloc{false};
  int last_write_iovcnt{0};
  std::vector<void*> last_write_iov_bases;
  size_t block_size{Ubsocket::ReadBudgetBlockSize};
};

FakeUbsocketState* fake_ubsocket_state;

Ubsocket::Block* makeBlock(absl::string_view contents) {
  void* raw = ::operator new[](
      std::max(fake_ubsocket_state->block_size, contents.size() + sizeof(Ubsocket::Block)));
  fake_ubsocket_state->allocations.insert(raw);
  ++fake_ubsocket_state->alloc_calls;
  auto* block = static_cast<Ubsocket::Block*>(raw);
  block->nshared.store(1, std::memory_order_relaxed);
  block->flags = 0;
  block->abi_check = 0;
  block->size = static_cast<uint32_t>(contents.size());
  block->cap = static_cast<uint32_t>(contents.size());
  block->u.next = nullptr;
  block->data = static_cast<char*>(raw) + sizeof(Ubsocket::Block);
  std::memcpy(block->data, contents.data(), contents.size()); // NOLINT(safe-memcpy)
  return block;
}

class UbSocketHandleImplTest : public testing::Test {
protected:
  void SetUp() override {
    fake_ubsocket_state = &state_;
    for (const char* name : {"UBSOCKET_BLOCK_TYPE", "UBSOCKET_UB_TRANS_MODE"}) {
      const char* value = std::getenv(name);
      original_layout_env_.push_back(value == nullptr ? std::nullopt
                                                      : std::make_optional<std::string>(value));
    }
    TestEnvironment::setEnvVar("UBSOCKET_BLOCK_TYPE", "8k", true);
    TestEnvironment::setEnvVar("UBSOCKET_UB_TRANS_MODE", "RC_TP", true);
    Ubsocket::resetBlockLayoutForTest();
    Ubsocket::resetTransportModeCacheForTest();
    const char* transport_mode = std::getenv("UBSOCKET_TRANS_MODE");
    if (transport_mode != nullptr) {
      original_transport_mode_ = transport_mode;
    }
  }

  void TearDown() override {
    for (void* allocation : state_.allocations) {
      ::operator delete[](allocation);
    }
    fake_ubsocket_state = nullptr;
    size_t index = 0;
    for (const char* name : {"UBSOCKET_BLOCK_TYPE", "UBSOCKET_UB_TRANS_MODE"}) {
      const auto& value = original_layout_env_[index++];
      if (value.has_value()) {
        TestEnvironment::setEnvVar(name, *value, true);
      } else {
        TestEnvironment::unsetEnvVar(name);
      }
    }
    Ubsocket::resetBlockLayoutForTest();
    if (original_transport_mode_.has_value()) {
      TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", *original_transport_mode_, true);
    } else {
      TestEnvironment::unsetEnvVar("UBSOCKET_TRANS_MODE");
    }
    Ubsocket::resetTransportModeCacheForTest();
  }

  void useBlockSize(const char* setting, size_t size) {
    ASSERT_TRUE(state_.allocations.empty());
    TestEnvironment::setEnvVar("UBSOCKET_BLOCK_TYPE", setting, true);
    state_.block_size = size;
    Ubsocket::resetBlockLayoutForTest();
  }

  FakeUbsocketState state_;
  std::optional<std::string> original_transport_mode_;
  std::vector<std::optional<std::string>> original_layout_env_;
};

TEST_F(UbSocketHandleImplTest, RuntimeBlockAliasesMatchUbsocketAndAreCached) {
  for (const auto& setting :
       {std::pair<const char*, size_t>{"default", 16384}, {"8k", 8192}, {"16k", 16384}}) {
    useBlockSize(setting.first, setting.second);
    EXPECT_EQ(setting.second, Ubsocket::Api::instance().blockSize());
    EXPECT_EQ(setting.second - sizeof(Ubsocket::Block),
              Ubsocket::Api::instance().blockPayloadCapacity());
    TestEnvironment::setEnvVar("UBSOCKET_BLOCK_TYPE", "invalid", true);
    EXPECT_EQ(setting.second, Ubsocket::Api::instance().blockSize());
  }
}

TEST_F(UbSocketHandleImplTest, UnsupportedLayoutAndMismatchedLibraryFailClosed) {
  Buffer::OwnedImpl buffer;
  UbSocketHandleImpl handle(42, false, UbsocketAddressFamily);
  for (const char* invalid : {"4k", "32k", "64k", "large", "invalid", ""}) {
    useBlockSize(invalid, 8192);
    EXPECT_EQ(0, Ubsocket::Api::instance().blockPayloadCapacity());
    EXPECT_FALSE(handle.read(buffer, 1024).ok());
    EXPECT_EQ(0, state_.alloc_calls);
  }
  useBlockSize("16k", 8192); // Simulate an old/mismatched library exposing 8K blocks.
  EXPECT_FALSE(handle.read(buffer, 1024).ok());
  EXPECT_TRUE(state_.allocations.empty());
  TestEnvironment::setEnvVar("UBSOCKET_UB_TRANS_MODE", "RC_CTP", true);
  Ubsocket::resetBlockLayoutForTest();
  EXPECT_EQ(0, Ubsocket::Api::instance().blockPayloadCapacity());
  TestEnvironment::unsetEnvVar("UBSOCKET_UB_TRANS_MODE");
  Ubsocket::resetBlockLayoutForTest();
  EXPECT_EQ(0, Ubsocket::Api::instance().blockPayloadCapacity());
}

TEST_F(UbSocketHandleImplTest, RuntimeOutputBoundariesPreserveBytesAndOutstandingTxReference) {
  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "ub", true);
  for (const auto& setting : {std::pair<const char*, size_t>{"8k", 8192}, {"16k", 16384}}) {
    useBlockSize(setting.first, setting.second);
    const size_t capacity = Ubsocket::Api::instance().blockPayloadCapacity();
    for (const size_t length :
         {capacity - 1, capacity, capacity + 1, size_t{65536}, size_t{131072}, size_t{262144}}) {
      SCOPED_TRACE(testing::Message() << setting.first << " length=" << length);
      std::string payload(length, ' ');
      for (size_t i = 0; i < length; ++i) {
        payload[i] = static_cast<char>(i % 251);
      }
      Buffer::OwnedImpl buffer(Ubsocket::createOutputSliceFactory());
      buffer.add(payload);
      EXPECT_EQ(payload, buffer.toString());
      const auto slices = buffer.getRawSlices();
      ASSERT_EQ((length + capacity - 1) / capacity, slices.size());
      auto* block = reinterpret_cast<Ubsocket::Block*>(static_cast<char*>(slices[0].mem_) -
                                                       sizeof(Ubsocket::Block));
      block->nshared.fetch_add(1); // Outstanding asynchronous TX reference.
      buffer.drain(7);
      EXPECT_EQ(payload.substr(7), buffer.toString());
      buffer.drain(buffer.length());
      ASSERT_EQ(1, state_.allocations.size());
      ASSERT_EQ(1, block->nshared.fetch_sub(1));
      ::ubsocket_iobuf_deallocate(block);
      EXPECT_TRUE(state_.allocations.empty());
    }
  }
}

TEST_F(UbSocketHandleImplTest, RuntimeUnixReadsKeepBaselineByteBudgets) {
  for (const auto& setting : {std::pair<const char*, size_t>{"8k", 8192}, {"16k", 16384}}) {
    SCOPED_TRACE(setting.first);
    useBlockSize(setting.first, setting.second);
    const size_t capacity = Ubsocket::Api::instance().blockPayloadCapacity();
    int fds[2];
    ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
    const std::string data(65536, 'b');
    ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));
    {
      Buffer::OwnedImpl buffer;
      UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
      for (const size_t length : {size_t{8160}, size_t{40800}, size_t{16576}}) {
        const auto result = handle.read(buffer, std::nullopt);
        ASSERT_TRUE(result.ok());
        EXPECT_EQ(length, result.return_value_);
      }
      EXPECT_EQ(data, buffer.toString());
      EXPECT_TRUE(handle.read(buffer, std::nullopt).wouldBlock());
      buffer.drain(buffer.length());
      EXPECT_TRUE(state_.allocations.empty());
      ASSERT_EQ(1, ::write(fds[0], "x", 1));
      const int before = state_.alloc_calls;
      ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
      EXPECT_EQ((73440 + capacity - 1) / capacity, state_.alloc_calls - before);
      EXPECT_EQ("x", buffer.toString());
    }
    EXPECT_TRUE(state_.allocations.empty());
    EXPECT_EQ(0, ::close(fds[0]));
  }
}

TEST_F(UbSocketHandleImplTest, RuntimeRxChainsPassOriginalPayloadPointersToTx) {
  for (const auto& setting : {std::pair<const char*, size_t>{"8k", 8192}, {"16k", 16384}}) {
    useBlockSize(setting.first, setting.second);
    const size_t capacity = Ubsocket::Api::instance().blockPayloadCapacity();
    state_.rx_chunks = {std::string(capacity, 'r'), std::string(capacity, 's'), "tail"};
    state_.written.clear();
    Buffer::OwnedImpl buffer;
    UbSocketHandleImpl handle(42, false, UbsocketAddressFamily);
    const auto read_result = handle.read(buffer, std::nullopt);
    ASSERT_TRUE(read_result.ok());
    EXPECT_EQ(2 * capacity + 4, read_result.return_value_);
    const auto slices = buffer.getRawSlices();
    ASSERT_EQ(3, slices.size());
    const auto write_result = handle.write(buffer);
    ASSERT_TRUE(write_result.ok());
    EXPECT_EQ(state_.rx_chunks[0] + state_.rx_chunks[1] + "tail", state_.written);
    ASSERT_EQ(slices.size(), state_.last_write_iov_bases.size());
    for (size_t i = 0; i < slices.size(); ++i) {
      EXPECT_EQ(slices[i].mem_, state_.last_write_iov_bases[i]);
    }
    EXPECT_TRUE(state_.allocations.empty());
  }
}

TEST_F(UbSocketHandleImplTest, RuntimeUnixReadLimitAndShrinkPreserveByteBudgetLearning) {
  for (const auto& setting : {std::pair<const char*, size_t>{"8k", 8192}, {"16k", 16384}}) {
    SCOPED_TRACE(setting.first);
    useBlockSize(setting.first, setting.second);
    int fds[2];
    ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
    const std::string large(65536, 'l');
    {
      Buffer::OwnedImpl buffer;
      UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
      auto send_and_drain = [&](const std::string& payload, std::optional<uint64_t> limit) {
        ASSERT_EQ(static_cast<ssize_t>(payload.size()),
                  ::write(fds[0], payload.data(), payload.size()));
        size_t calls = 0;
        bool saw_again = false;
        while (calls++ < payload.size() + 1) {
          const auto result = handle.read(buffer, limit);
          if (result.wouldBlock()) {
            saw_again = true;
            break;
          }
          ASSERT_TRUE(result.ok());
          ASSERT_GT(result.return_value_, 0);
          if (limit.has_value()) {
            EXPECT_LE(result.return_value_, *limit);
          }
        }
        ASSERT_TRUE(saw_again);
        EXPECT_EQ(payload, buffer.toString());
        buffer.drain(buffer.length());
      };
      send_and_drain(large, std::nullopt);
      for (size_t i = 0; i < 8; ++i) {
        send_and_drain(std::string(1024, 's'), 512);
      }
      ASSERT_EQ(static_cast<ssize_t>(large.size()), ::write(fds[0], large.data(), large.size()));
      const auto still_large = handle.read(buffer, std::nullopt);
      ASSERT_TRUE(still_large.ok());
      EXPECT_EQ(large.size(), still_large.return_value_);
      EXPECT_TRUE(handle.read(buffer, std::nullopt).wouldBlock());
      buffer.drain(buffer.length());
      for (size_t i = 0; i < 8; ++i) {
        send_and_drain("s", std::nullopt);
      }
      ASSERT_EQ(static_cast<ssize_t>(large.size()), ::write(fds[0], large.data(), large.size()));
      const auto shrunk = handle.read(buffer, std::nullopt);
      ASSERT_TRUE(shrunk.ok());
      EXPECT_EQ(8160, shrunk.return_value_);
    }
    EXPECT_TRUE(state_.allocations.empty());
    EXPECT_EQ(0, ::close(fds[0]));
  }
}

TEST_F(UbSocketHandleImplTest, EnablesZeroCopyOnlyForExistingUbTransportMode) {
  TestEnvironment::unsetEnvVar("UBSOCKET_TRANS_MODE");
  Ubsocket::resetTransportModeCacheForTest();
  EXPECT_FALSE(Ubsocket::zeroCopyEnabled());

  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "tcp", true);
  Ubsocket::resetTransportModeCacheForTest();
  EXPECT_FALSE(Ubsocket::zeroCopyEnabled());

  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "ub", true);
  Ubsocket::resetTransportModeCacheForTest();
  EXPECT_TRUE(Ubsocket::zeroCopyEnabled());

  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "UB", true);
  Ubsocket::resetTransportModeCacheForTest();
  EXPECT_FALSE(Ubsocket::zeroCopyEnabled());
}

TEST_F(UbSocketHandleImplTest, OutputSliceFactoryIsEmptyOutsideUbMode) {
  TestEnvironment::unsetEnvVar("UBSOCKET_TRANS_MODE");
  Ubsocket::resetTransportModeCacheForTest();
  EXPECT_FALSE(Ubsocket::createOutputSliceFactory());

  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "tcp", true);
  Ubsocket::resetTransportModeCacheForTest();
  EXPECT_FALSE(Ubsocket::createOutputSliceFactory());
}

TEST_F(UbSocketHandleImplTest, OutputSliceFactoryFillsBlocksAndMovesWithoutCopying) {
  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "ub", true);
  Buffer::OwnedImpl buffer(Ubsocket::createOutputSliceFactory());
  const std::string first = "small thrift fields";
  const std::string payload(2 * Ubsocket::ReadBudgetPayloadCapacity, 'p');

  buffer.add(first);
  buffer.add(payload);

  EXPECT_EQ(first.size() + payload.size(), buffer.length());
  EXPECT_EQ(3, state_.alloc_calls);
  const Buffer::RawSliceVector before_move = buffer.getRawSlices();
  ASSERT_EQ(3, before_move.size());
  EXPECT_EQ(Ubsocket::ReadBudgetPayloadCapacity, before_move[0].len_);
  EXPECT_EQ(Ubsocket::ReadBudgetPayloadCapacity, before_move[1].len_);
  EXPECT_EQ(first.size(), before_move[2].len_);

  Buffer::OwnedImpl destination;
  destination.move(buffer);

  EXPECT_EQ(0, buffer.length());
  EXPECT_EQ(first + payload, destination.toString());
  const Buffer::RawSliceVector after_move = destination.getRawSlices();
  ASSERT_EQ(before_move.size(), after_move.size());
  for (size_t i = 0; i < before_move.size(); ++i) {
    EXPECT_EQ(before_move[i].mem_, after_move[i].mem_);
  }
  EXPECT_EQ(0, state_.dealloc_calls);

  destination.drain(destination.length());
  EXPECT_EQ(3, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, OutputSliceAllocationFailsClosed) {
  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "ub", true);
  state_.fail_alloc = true;
  Buffer::OwnedImpl buffer(Ubsocket::createOutputSliceFactory());

  EXPECT_DEATH(buffer.add("request"), "UBSocket output slice allocation failed");
  EXPECT_EQ(0, buffer.length());
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, LargeOutputUsesOneBatchAndOneReturn) {
  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "ub", true);
  Buffer::OwnedImpl buffer(Ubsocket::createOutputSliceFactory());
  const std::string payload(65536, 'b');
  buffer.add(payload);
  EXPECT_EQ(9, state_.alloc_calls);
  EXPECT_EQ(1, state_.batch_alloc_calls);
  EXPECT_EQ(payload, buffer.toString());
  buffer.drain(buffer.length());
  EXPECT_EQ(1, state_.batch_dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, MovingLargeOutputObjectDoesNotReleaseTransferredStorage) {
  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "ub", true);
  const std::string payload(65536, 'm');
  Buffer::OwnedImpl destination;
  {
    Buffer::OwnedImpl source(Ubsocket::createOutputSliceFactory());
    source.add(payload);
    Buffer::OwnedImpl intermediate(std::move(source));
    EXPECT_EQ(0, source.length());
    EXPECT_EQ(0, state_.dealloc_calls);
    destination = std::move(intermediate);
    EXPECT_EQ(0, intermediate.length());
  }
  EXPECT_EQ(0, state_.dealloc_calls);
  EXPECT_EQ(payload, destination.toString());
  destination.drain(destination.length());
  EXPECT_EQ(9, state_.dealloc_calls);
}

TEST_F(UbSocketHandleImplTest, BoundedOutputAddFragmentsAndLinearizePreserveBytes) {
  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "ub", true);
  Buffer::OwnedImpl buffer(Ubsocket::createOutputSliceFactory());
  const std::string a(17000, 'a');
  const std::string b(20000, 'b');
  const std::array<absl::string_view, 3> fragments{a, "", b};
  EXPECT_EQ(a.size() + b.size(), buffer.addFragments(fragments));
  EXPECT_EQ(a + b, buffer.toString());
  const auto* contiguous = static_cast<const char*>(buffer.linearize(buffer.length()));
  EXPECT_EQ(a + b, std::string(contiguous, buffer.length()));
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, DrainingDoesNotReturnBlockWithOutstandingTxReference) {
  TestEnvironment::setEnvVar("UBSOCKET_TRANS_MODE", "ub", true);
  Buffer::OwnedImpl buffer(Ubsocket::createOutputSliceFactory());
  buffer.add(std::string(16000, 't'));
  const auto slices = buffer.getRawSlices();
  auto* block = reinterpret_cast<Ubsocket::Block*>(static_cast<char*>(slices[0].mem_) -
                                                   sizeof(Ubsocket::Block));
  block->nshared.fetch_add(1, std::memory_order_relaxed); // Simulate successful asynchronous post.
  buffer.drain(buffer.length());
  EXPECT_EQ(1, block->nshared.load());
  EXPECT_EQ(1, state_.dealloc_calls);
  EXPECT_EQ(1, state_.allocations.size());
  ASSERT_EQ(1, block->nshared.fetch_sub(1));
  ::ubsocket_iobuf_deallocate(block); // Simulated completion.
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, AddsPr9BlocksAsFragmentsAndReleasesOnDrain) {
  state_.rx_chunks = {"hello", " world"};
  Buffer::OwnedImpl buffer;
  UbSocketHandleImpl handle(42, false, UbsocketAddressFamily);

  Api::IoCallUint64Result result = handle.read(buffer, 4);

  ASSERT_TRUE(result.ok());
  EXPECT_EQ(11, result.return_value_);
  EXPECT_EQ("hello world", buffer.toString());
  EXPECT_EQ(1, state_.dealloc_calls); // RX anchor only.

  buffer.drain(buffer.length());
  EXPECT_EQ(3, state_.dealloc_calls); // Anchor and two received blocks.
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, PropagatesFailClosedReadWithoutPosixFallback) {
  state_.read_error = EPROTONOSUPPORT;
  Buffer::OwnedImpl buffer;
  UbSocketHandleImpl handle(42, false, UbsocketAddressFamily);

  Api::IoCallUint64Result result = handle.read(buffer, 1024);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(EPROTONOSUPPORT, result.err_->getSystemErrorCode());
  EXPECT_EQ(1, state_.dealloc_calls);
  EXPECT_EQ(0, buffer.length());
}

TEST_F(UbSocketHandleImplTest, ReturnsAgainForTransientReadAndReleasesAnchor) {
  state_.read_error = EAGAIN;
  Buffer::OwnedImpl buffer;
  UbSocketHandleImpl handle(42, false, UbsocketAddressFamily);

  Api::IoCallUint64Result result = handle.read(buffer, 1024);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(Api::IoError::IoErrorCode::Again, result.err_->getErrorCode());
  EXPECT_EQ(EAGAIN, result.err_->getSystemErrorCode());
  EXPECT_EQ(1, state_.alloc_calls);
  EXPECT_EQ(1, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
  EXPECT_EQ(0, buffer.length());
}

TEST_F(UbSocketHandleImplTest, PassesSlicesToDirectWritevWithoutEnvoyStaging) {
  std::string first = "hello";
  std::string second = " world";
  Buffer::RawSlice slices[] = {{first.data(), first.size()}, {second.data(), second.size()}};
  UbSocketHandleImpl handle(42, false, UbsocketAddressFamily);

  Api::IoCallUint64Result result = handle.writev(slices, 2);

  ASSERT_TRUE(result.ok());
  EXPECT_EQ(11, result.return_value_);
  EXPECT_EQ("hello world", state_.written);
  ASSERT_EQ(2, state_.last_write_iovcnt);
  EXPECT_EQ(first.data(), state_.last_write_iov_bases[0]);
  EXPECT_EQ(second.data(), state_.last_write_iov_bases[1]);
  EXPECT_EQ(0, state_.alloc_calls);
  EXPECT_EQ(0, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, LeavesLargeSliceSplittingToUbsocket) {
  std::string data(16 * 1024, 'a');
  Buffer::RawSlice slice{data.data(), data.size()};
  UbSocketHandleImpl handle(42, false, UbsocketAddressFamily);

  Api::IoCallUint64Result result = handle.writev(&slice, 1);

  ASSERT_TRUE(result.ok());
  EXPECT_EQ(data.size(), result.return_value_);
  EXPECT_EQ(data, state_.written);
  EXPECT_EQ(1, state_.last_write_iovcnt);
  EXPECT_EQ(data.data(), state_.last_write_iov_bases[0]);
  EXPECT_EQ(0, state_.alloc_calls);
  EXPECT_EQ(0, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, PropagatesFailClosedWriteWithoutPosixFallback) {
  state_.write_error = EPROTONOSUPPORT;
  std::string data = "fallback must fail";
  Buffer::RawSlice slice{data.data(), data.size()};
  UbSocketHandleImpl handle(42, false, UbsocketAddressFamily);

  Api::IoCallUint64Result result = handle.writev(&slice, 1);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(EPROTONOSUPPORT, result.err_->getSystemErrorCode());
  EXPECT_EQ(0, state_.dealloc_calls);
  EXPECT_TRUE(state_.written.empty());
}

TEST_F(UbSocketHandleImplTest, ReturnsAgainForTransientDirectWrite) {
  state_.write_error = EAGAIN;
  std::string data = "retry on the next write event";
  Buffer::RawSlice slice{data.data(), data.size()};
  UbSocketHandleImpl handle(42, false, UbsocketAddressFamily);

  Api::IoCallUint64Result result = handle.writev(&slice, 1);

  ASSERT_FALSE(result.ok());
  EXPECT_EQ(Api::IoError::IoErrorCode::Again, result.err_->getErrorCode());
  EXPECT_EQ(EAGAIN, result.err_->getSystemErrorCode());
  EXPECT_EQ(0, state_.alloc_calls);
  EXPECT_EQ(0, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
  EXPECT_TRUE(state_.written.empty());
}

TEST_F(UbSocketHandleImplTest, ReadsUnixSocketDirectlyIntoUbsocketFragment) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  const std::string data = "kitex payload";
  ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));

  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    Api::IoCallUint64Result result = handle.read(buffer, data.size());

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(data.size(), result.return_value_);
    EXPECT_EQ(data, buffer.toString());
    EXPECT_EQ(1, state_.alloc_calls);
    EXPECT_EQ(0, state_.dealloc_calls);
  }
  EXPECT_EQ(0, ::close(fds[0]));

  buffer.drain(buffer.length());
  EXPECT_EQ(1, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, UnboundedUnixReadStartsWithOneBlock) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  const std::string data(1024, 'u');
  ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));

  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    Api::IoCallUint64Result result = handle.read(buffer, std::nullopt);

    ASSERT_TRUE(result.ok());
    EXPECT_EQ(data.size(), result.return_value_);
    EXPECT_EQ(data, buffer.toString());
    EXPECT_EQ(1, state_.alloc_calls);
    EXPECT_EQ(0, state_.dealloc_calls);
  }
  EXPECT_EQ(0, ::close(fds[0]));

  buffer.drain(buffer.length());
  EXPECT_EQ(1, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, AdaptiveReservationGrowsAndReturnsUnusedBlocks) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  const std::string data(20 * 1024, 'm');
  ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));

  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    Api::IoCallUint64Result first = handle.read(buffer, std::nullopt);
    Api::IoCallUint64Result second = handle.read(buffer, std::nullopt);

    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());
    EXPECT_EQ(Ubsocket::ReadBudgetPayloadCapacity, first.return_value_);
    EXPECT_EQ(data.size() - Ubsocket::ReadBudgetPayloadCapacity, second.return_value_);
    EXPECT_EQ(data, buffer.toString());
    EXPECT_EQ(6, state_.alloc_calls);
    EXPECT_EQ(3, state_.dealloc_calls);
  }
  EXPECT_EQ(0, ::close(fds[0]));

  buffer.drain(buffer.length());
  EXPECT_EQ(6, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, ShortReadUsesOneBlockForDrainToAgainProbe) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  const std::string data(20 * 1024, 'p');
  ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));

  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
    ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
    Api::IoCallUint64Result again = handle.read(buffer, std::nullopt);

    ASSERT_FALSE(again.ok());
    EXPECT_TRUE(again.wouldBlock());
    EXPECT_EQ(data, buffer.toString());
    // 1-block read + 5-block read + 1-block EAGAIN probe.
    EXPECT_EQ(7, state_.alloc_calls);
    EXPECT_EQ(4, state_.dealloc_calls);
  }
  EXPECT_EQ(0, ::close(fds[0]));

  buffer.drain(buffer.length());
  EXPECT_EQ(7, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, AdaptiveReservationReachesNineBlocksFor64KiB) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  const std::string data(64 * 1024, 'k');
  ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));

  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    Api::IoCallUint64Result first = handle.read(buffer, std::nullopt);
    Api::IoCallUint64Result second = handle.read(buffer, std::nullopt);
    Api::IoCallUint64Result third = handle.read(buffer, std::nullopt);

    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());
    ASSERT_TRUE(third.ok());
    EXPECT_EQ(Ubsocket::ReadBudgetPayloadCapacity, first.return_value_);
    EXPECT_EQ(5 * Ubsocket::ReadBudgetPayloadCapacity, second.return_value_);
    EXPECT_EQ(data.size() - 6 * Ubsocket::ReadBudgetPayloadCapacity, third.return_value_);
    EXPECT_EQ(data, buffer.toString());
    EXPECT_EQ(15, state_.alloc_calls);
    EXPECT_EQ(6, state_.dealloc_calls);
  }
  EXPECT_EQ(0, ::close(fds[0]));

  buffer.drain(buffer.length());
  EXPECT_EQ(15, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, AdaptiveReservationPreservesLargerStreamAcrossReads) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  constexpr size_t ReservationBytes = 9 * Ubsocket::ReadBudgetPayloadCapacity;
  const std::string data(ReservationBytes + 1024, 'l');
  ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));

  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    Api::IoCallUint64Result first = handle.read(buffer, std::nullopt);
    ASSERT_TRUE(first.ok());
    EXPECT_EQ(Ubsocket::ReadBudgetPayloadCapacity, first.return_value_);

    Api::IoCallUint64Result second = handle.read(buffer, std::nullopt);
    ASSERT_TRUE(second.ok());
    EXPECT_EQ(5 * Ubsocket::ReadBudgetPayloadCapacity, second.return_value_);

    Api::IoCallUint64Result third = handle.read(buffer, std::nullopt);
    ASSERT_TRUE(third.ok());
    EXPECT_EQ(data.size() - 6 * Ubsocket::ReadBudgetPayloadCapacity, third.return_value_);

    EXPECT_EQ(data, buffer.toString());
    EXPECT_EQ(15, state_.alloc_calls);
    EXPECT_EQ(5, state_.dealloc_calls);
  }
  EXPECT_EQ(0, ::close(fds[0]));

  buffer.drain(buffer.length());
  EXPECT_EQ(15, state_.dealloc_calls);
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, AdaptiveReservationShrinksAfterStableSmallReads) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  const std::string large(64 * 1024, 'l');
  ASSERT_EQ(static_cast<ssize_t>(large.size()), ::write(fds[0], large.data(), large.size()));

  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
    ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
    ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
    EXPECT_TRUE(handle.read(buffer, std::nullopt).wouldBlock());

    const std::string small(1024, 's');
    for (int i = 0; i < 8; ++i) {
      ASSERT_EQ(static_cast<ssize_t>(small.size()), ::write(fds[0], small.data(), small.size()));
      ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
      EXPECT_TRUE(handle.read(buffer, std::nullopt).wouldBlock());
    }

    const int allocations_before_shrunk_read = state_.alloc_calls;
    ASSERT_EQ(static_cast<ssize_t>(small.size()), ::write(fds[0], small.data(), small.size()));
    ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
    EXPECT_EQ(1, state_.alloc_calls - allocations_before_shrunk_read);
  }
  EXPECT_EQ(0, ::close(fds[0]));

  buffer.drain(buffer.length());
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, UnboundedUnixReadUsesOneBlockForInitialAgain) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));

  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    Api::IoCallUint64Result result = handle.read(buffer, std::nullopt);

    ASSERT_FALSE(result.ok());
    EXPECT_EQ(Api::IoError::IoErrorCode::Again, result.err_->getErrorCode());
    EXPECT_EQ(EAGAIN, result.err_->getSystemErrorCode());
    EXPECT_EQ(1, state_.alloc_calls);
    EXPECT_EQ(1, state_.dealloc_calls);
    EXPECT_TRUE(state_.allocations.empty());
  }
  EXPECT_EQ(0, ::close(fds[0]));
}

TEST_F(UbSocketHandleImplTest, LearnsTwoBlocksForEightKiBWithoutExtraDataRead) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    const std::string data(8192, 'e');
    for (int round = 0; round < 9; ++round) {
      ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));
      while (handle.read(buffer, std::nullopt).ok()) {
      }
      ASSERT_EQ(data, buffer.toString());
      buffer.drain(buffer.length());
    }
    const int before = state_.alloc_calls;
    const int batch_before = state_.batch_alloc_calls;
    ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));
    const auto result = handle.read(buffer, std::nullopt);
    ASSERT_TRUE(result.ok());
    EXPECT_EQ(data.size(), result.return_value_);
    EXPECT_EQ(2, state_.alloc_calls - before);
    EXPECT_EQ(1, state_.batch_alloc_calls - batch_before);
    EXPECT_EQ(data, buffer.toString());
    EXPECT_TRUE(handle.read(buffer, std::nullopt).wouldBlock());
  }
  EXPECT_EQ(0, ::close(fds[0]));
  buffer.drain(buffer.length());
  EXPECT_TRUE(state_.allocations.empty());
}

TEST_F(UbSocketHandleImplTest, ShrinkUsesLargestObservationInWindow) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    const std::string large(65536, 'w');
    ASSERT_EQ(static_cast<ssize_t>(large.size()), ::write(fds[0], large.data(), large.size()));
    while (handle.read(buffer, std::nullopt).ok()) {
    }
    buffer.drain(buffer.length());
    for (int round = 0; round < 8; ++round) {
      const std::string data(round % 2 == 0 ? 16384 : 8192, 'm');
      ASSERT_EQ(static_cast<ssize_t>(data.size()), ::write(fds[0], data.data(), data.size()));
      ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
      EXPECT_TRUE(handle.read(buffer, std::nullopt).wouldBlock());
      ASSERT_EQ(data, buffer.toString());
      buffer.drain(buffer.length());
    }
    const int before = state_.alloc_calls;
    ASSERT_EQ(1, ::write(fds[0], "x", 1));
    ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
    EXPECT_EQ(3, state_.alloc_calls - before); // Not two blocks from the final short round.
  }
  EXPECT_EQ(0, ::close(fds[0]));
}

TEST_F(UbSocketHandleImplTest, ReadLengthLimitDoesNotTrainSmallerReservation) {
  int fds[2];
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds));
  Buffer::OwnedImpl buffer;
  {
    UbUnixSocketHandleImpl handle(fds[1], false, AF_UNIX);
    const std::string large(65536, 'l');
    ASSERT_EQ(static_cast<ssize_t>(large.size()), ::write(fds[0], large.data(), large.size()));
    while (handle.read(buffer, std::nullopt).ok()) {
    }
    buffer.drain(buffer.length());
    const std::string small(1024, 's');
    for (int round = 0; round < 8; ++round) {
      ASSERT_EQ(static_cast<ssize_t>(small.size()), ::write(fds[0], small.data(), small.size()));
      while (handle.read(buffer, 512).ok()) {
      }
      ASSERT_EQ(small, buffer.toString());
      buffer.drain(buffer.length());
    }
    const int before = state_.alloc_calls;
    ASSERT_EQ(1, ::write(fds[0], "x", 1));
    ASSERT_TRUE(handle.read(buffer, std::nullopt).ok());
    EXPECT_EQ(9, state_.alloc_calls - before);
  }
  EXPECT_EQ(0, ::close(fds[0]));
}

} // namespace
} // namespace Network
} // namespace Envoy

extern "C" void* ubsocket_iobuf_allocate(size_t size, const void*) {
  auto& state = *Envoy::Network::fake_ubsocket_state;
  ++state.alloc_calls;
  if (state.fail_alloc) {
    errno = ENOMEM;
    return nullptr;
  }
  if (size != state.block_size) {
    errno = EINVAL;
    return nullptr;
  }
  void* raw = ::operator new[](size);
  state.allocations.insert(raw);
  return raw;
}

extern "C" void ubsocket_iobuf_deallocate(void* raw) {
  auto& state = *Envoy::Network::fake_ubsocket_state;
  if (state.allocations.erase(raw) == 1) {
    ++state.dealloc_calls;
    ::operator delete[](raw);
  }
}

extern "C" int ubsocket_iobuf_allocate_batch(size_t size, void** blocks, uint32_t count) {
  ++Envoy::Network::fake_ubsocket_state->batch_alloc_calls;
  for (uint32_t i = 0; i < count; ++i) {
    blocks[i] = ubsocket_iobuf_allocate(size, nullptr);
    if (blocks[i] == nullptr) {
      for (uint32_t j = 0; j < i; ++j) {
        ubsocket_iobuf_deallocate(blocks[j]);
      }
      return -1;
    }
  }
  return 0;
}

extern "C" void ubsocket_iobuf_deallocate_batch(void* const* blocks, uint32_t count) {
  ++Envoy::Network::fake_ubsocket_state->batch_dealloc_calls;
  for (uint32_t i = 0; i < count; ++i) {
    ubsocket_iobuf_deallocate(blocks[i]);
  }
}

extern "C" ssize_t ubsocket_readv(int, const struct iovec* iov, int iovcnt) {
  auto& state = *Envoy::Network::fake_ubsocket_state;
  if (state.read_error != 0) {
    errno = state.read_error;
    return -1;
  }
  if (iovcnt != 1) {
    errno = EINVAL;
    return -1;
  }

  using Envoy::Network::Ubsocket::Block;
  auto* anchor = reinterpret_cast<Block*>(static_cast<char*>(iov[0].iov_base) - sizeof(Block));
  Block* tail = anchor;
  ssize_t total = 0;
  for (const std::string& chunk : state.rx_chunks) {
    Block* block = Envoy::Network::makeBlock(chunk);
    tail->u.next = block;
    tail = block;
    total += static_cast<ssize_t>(chunk.size());
  }
  return total;
}

extern "C" ssize_t ubsocket_writev(int, const struct iovec* iov, int iovcnt) {
  auto& state = *Envoy::Network::fake_ubsocket_state;
  if (state.write_error != 0) {
    errno = state.write_error;
    return -1;
  }

  state.last_write_iovcnt = iovcnt;
  state.last_write_iov_bases.clear();
  ssize_t total = 0;
  for (int i = 0; i < iovcnt; ++i) {
    state.last_write_iov_bases.push_back(iov[i].iov_base);
    state.written.append(static_cast<const char*>(iov[i].iov_base), iov[i].iov_len);
    total += static_cast<ssize_t>(iov[i].iov_len);
  }
  return total;
}
