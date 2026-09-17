#include "source/common/network/ub_socket_handle_impl.h"

#include <dlfcn.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>

#include "envoy/network/connection.h"
#include "envoy/network/transport_socket.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/utility.h"
#include "source/common/kitex_probe/probe.h"
#include "source/common/network/io_socket_error_impl.h"

#include "absl/container/inlined_vector.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Network {
namespace {

constexpr size_t MaxUbsocketIov = 1024;
constexpr size_t MaxRxChainBlocks = 4096;
constexpr size_t MaxUdsReadBlocks = 9;
constexpr size_t MediumUdsReadBlocks = 5;
constexpr size_t MinUdsReadBlocks = 1;
constexpr uint8_t UdsReadShrinkThreshold = 8;
constexpr uint64_t MaxUdsReadReservation = MaxUdsReadBlocks * Ubsocket::ReadBudgetPayloadCapacity;
static_assert(MaxUdsReadReservation == 73440,
              "nine UBSocket payload blocks must expose 73440 bytes");

size_t configuredBlockSize() {
  const char* mode = std::getenv("UBSOCKET_UB_TRANS_MODE");
  // UBSocket defaults to a different transport when unset; do not guess its block layout.
  if (mode == nullptr || std::strcmp(mode, "RC_TP") != 0) {
    return 0;
  }
  const char* value = std::getenv("UBSOCKET_BLOCK_TYPE");
  if (value == nullptr || std::strcmp(value, "default") == 0 || std::strcmp(value, "16k") == 0) {
    return Ubsocket::DefaultBlockSize;
  }
  if (std::strcmp(value, "8k") == 0) {
    return Ubsocket::ReadBudgetBlockSize;
  }
  return 0;
}

size_t& blockSizeCache() {
  static size_t size = configuredBlockSize();
  return size;
}

size_t nextUdsReadTier(size_t current) {
  return current < MediumUdsReadBlocks ? MediumUdsReadBlocks : MaxUdsReadBlocks;
}

std::atomic<int>& transportModeCache() {
  static std::atomic<int> cache{-1};
  return cache;
}

bool transportModeIsUb() {
  int cached = transportModeCache().load(std::memory_order_acquire);
  if (cached >= 0) {
    return cached != 0;
  }
  const char* transport_mode = std::getenv("UBSOCKET_TRANS_MODE");
  cached = transport_mode != nullptr && std::strcmp(transport_mode, "ub") == 0 ? 1 : 0;
  transportModeCache().store(cached, std::memory_order_release);
  return cached != 0;
}

template <class Function> Function loadUbsocketSymbol(const char* name) {
  static_assert(sizeof(Function) == sizeof(void*));
  void* symbol = dlsym(RTLD_DEFAULT, name);
  Function function = nullptr;
  std::memcpy(&function, &symbol, sizeof(function)); // NOLINT(safe-memcpy)
  return function;
}

void releaseBlock(const Ubsocket::Api& api, Ubsocket::Block* block) {
  if (block->nshared.fetch_sub(1, std::memory_order_acq_rel) == 1) {
    Buffer::ExternalStorageReleaseBatch::release(block, api.iobuf_deallocate_batch_);
  }
}

void releaseChain(const Ubsocket::Api& api, Ubsocket::Block* block) {
  Buffer::ExternalStorageReleaseBatch batch;
  size_t count = 0;
  while (block != nullptr && count++ < MaxRxChainBlocks) {
    Ubsocket::Block* next = block->u.next;
    block->u.next = nullptr;
    releaseBlock(api, block);
    block = next;
  }
}

Ubsocket::Block* initializeBlock(void* raw, size_t data_size, size_t capacity) {
  auto* block = static_cast<Ubsocket::Block*>(raw);
  block->nshared.store(1, std::memory_order_relaxed);
  block->flags = Ubsocket::BlockFlagsUb;
  block->abi_check = 0;
  block->size = static_cast<uint32_t>(data_size);
  block->cap = static_cast<uint32_t>(capacity);
  block->u.next = nullptr;
  block->data = static_cast<char*>(raw) + sizeof(Ubsocket::Block);
  return block;
}

bool allocateBlocks(const Ubsocket::Api& api, Ubsocket::Block** blocks, size_t count) {
  ASSERT(count > 0 && count <= MaxUdsReadBlocks);
  void* raw[MaxUdsReadBlocks];
  if (api.iobuf_allocate_batch_(api.blockSize(), raw, count) != 0) {
    return false;
  }
  for (size_t i = 0; i < count; ++i) {
    blocks[i] = initializeBlock(raw[i], 0, api.blockPayloadCapacity());
  }
  return true;
}

Ubsocket::Block* allocateBlock(const Ubsocket::Api& api, size_t data_size) {
  Ubsocket::Block* block;
  if (!allocateBlocks(api, &block, 1)) {
    return nullptr;
  }
  block->size = data_size;
  return block;
}

void attachBlock(Buffer::Instance& buffer, const Ubsocket::Api& api, Ubsocket::Block* block) {
  static_cast<Buffer::OwnedImpl&>(buffer).addExternalSlice(
      Buffer::Slice(static_cast<const void*>(block->data), block->cap,
                    [&api, block]() { releaseBlock(api, block); }));
}

Api::IoCallUint64Result failClosedResult(int error, absl::string_view operation, os_fd_t fd) {
  ENVOY_LOG_MISC(error, "[UB_ZC_FAIL_CLOSED] {} rejected on fd {}: errno {} ({})", operation, fd,
                 error, errorDetails(error));
  return Api::IoCallUint64Result(/*rc=*/0, IoSocketError::create(error));
}

bool isAgainError(int error) { return error == EAGAIN || error == EWOULDBLOCK; }

Api::IoCallUint64Result againResult() {
  return Api::IoCallUint64Result(/*rc=*/0, IoSocketError::getIoSocketEagainError());
}

} // namespace

namespace Ubsocket {

const Api& Api::instance() {
  static const Api api;
  return api;
}

size_t Api::blockSize() const { return blockSizeCache(); }

size_t Api::blockPayloadCapacity() const {
  const size_t size = blockSize();
  return size == 0 ? 0 : size - sizeof(Block);
}

void resetBlockLayoutForTest() { blockSizeCache() = configuredBlockSize(); }

Api::Api()
    : readv_(loadUbsocketSymbol<ReadvFn>("ubsocket_readv")),
      writev_(loadUbsocketSymbol<WritevFn>("ubsocket_writev")),
      iobuf_allocate_batch_(
          loadUbsocketSymbol<IobufAllocateBatchFn>("ubsocket_iobuf_allocate_batch")),
      iobuf_deallocate_batch_(
          loadUbsocketSymbol<IobufDeallocateBatchFn>("ubsocket_iobuf_deallocate_batch")),
      available_(readv_ != nullptr && writev_ != nullptr && iobuf_allocate_batch_ != nullptr &&
                 iobuf_deallocate_batch_ != nullptr) {}

bool zeroCopyEnabled() { return Api::instance().available() && transportModeIsUb(); }

void resetTransportModeCacheForTest() { transportModeCache().store(-1, std::memory_order_release); }

Buffer::OwnedImpl::SliceFactory createOutputSliceFactory(bool ub_destination) {
  const Api& api = Api::instance();
  const bool enabled = ub_destination && api.available() && transportModeIsUb();
  if (!enabled) {
    return {};
  }
  RELEASE_ASSERT(api.blockPayloadCapacity() != 0,
                 "UB ZC requires RC_TP and UBSOCKET_BLOCK_TYPE=default/8k/16k");

  return [&api](uint64_t min_capacity, uint32_t max_slices, void* context,
                Buffer::OwnedImpl::SliceConsumer consume) {
    const size_t capacity = api.blockPayloadCapacity();
    const size_t count = std::min<uint64_t>(
        std::min<uint32_t>(max_slices, MaxUdsReadBlocks),
        std::max<uint64_t>(1, min_capacity / capacity + (min_capacity % capacity != 0)));
    Block* blocks[MaxUdsReadBlocks];
    if (!allocateBlocks(api, blocks, count)) {
      const int error = errno;
      ENVOY_LOG_MISC(error, "[UB_ZC_FAIL_CLOSED] UBSocket output slice allocation failed: {}",
                     errorDetails(error));
      RELEASE_ASSERT(false, "UBSocket output slice allocation failed");
    }
    for (size_t i = 0; i < count; ++i) {
      Block* block = blocks[i];
      consume(context, Buffer::Slice(reinterpret_cast<uint8_t*>(block->data), capacity,
                                     [&api, block]() { releaseBlock(api, block); }));
    }
  };
}

} // namespace Ubsocket

Api::IoCallUint64Result UbUnixSocketHandleImpl::read(Buffer::Instance& buffer,
                                                     std::optional<uint64_t> max_length_opt) {
  const uint64_t max_length = max_length_opt.value_or(std::numeric_limits<uint64_t>::max());
  if (max_length == 0) {
    return Api::ioCallUint64ResultNoError();
  }

  KitexProbe::ScopedIoDetailPhase prepare(KitexProbe::IoDetailPhase::Prepare);
  const Ubsocket::Api& api = Ubsocket::Api::instance();
  if (!api.available()) {
    return failClosedResult(ENOSYS, "UB UDS read symbols unavailable", fd_);
  }
  const size_t capacity = api.blockPayloadCapacity();
  if (capacity == 0) {
    return failClosedResult(EINVAL, "unsupported UB block layout or transport mode", fd_);
  }

  const bool one_block_probe = one_block_probe_;
  one_block_probe_ = false;
  const size_t selected_blocks = one_block_probe ? MinUdsReadBlocks : read_reservation_blocks_;
  const uint64_t selected_capacity = selected_blocks * Ubsocket::ReadBudgetPayloadCapacity;
  const uint64_t read_length = std::min(max_length, selected_capacity);
  const size_t block_count = static_cast<size_t>((read_length + capacity - 1) / capacity);

  std::array<Ubsocket::Block*, MaxUdsReadBlocks> blocks;
  std::array<struct iovec, MaxUdsReadBlocks> iov;
  uint64_t remaining_capacity = read_length;
  if (!allocateBlocks(api, blocks.data(), block_count)) {
    const int error = errno;
    return failClosedResult(error, "UB UDS block allocation (check block layout and library)", fd_);
  }
  for (size_t i = 0; i < block_count; ++i) {
    const size_t offered = static_cast<size_t>(std::min<uint64_t>(remaining_capacity, capacity));
    iov[i] = {blocks[i]->data, offered};
    remaining_capacity -= offered;
  }
  read_round_limited_ = read_round_limited_ || read_length < selected_capacity;
  prepare.finish();
  const Api::SysCallSizeResult syscall_result = [&]() {
    KitexProbe::ScopedIoDetailPhase syscall(KitexProbe::IoDetailPhase::Syscall);
    return block_count == 1
               ? Api::OsSysCallsSingleton::get().recv(fd_, iov[0].iov_base, iov[0].iov_len, 0)
               : Api::OsSysCallsSingleton::get().readv(fd_, iov.data(),
                                                       static_cast<int>(block_count));
  }();
  const uint64_t bytes =
      syscall_result.return_value_ > 0 ? static_cast<uint64_t>(syscall_result.return_value_) : 0;
  const uint64_t used_blocks = bytes == 0 ? 0 : (bytes + capacity - 1) / capacity;
  KitexProbe::recordIoCall(bytes, read_length, block_count, block_count - used_blocks,
                           syscall_result.return_value_ < 0 && isAgainError(syscall_result.errno_));
  KitexProbe::ScopedIoDetailPhase commit(KitexProbe::IoDetailPhase::Commit);
  if (syscall_result.return_value_ <= 0) {
    Buffer::ExternalStorageReleaseBatch release_batch;
    for (size_t i = 0; i < block_count; ++i) {
      releaseBlock(api, blocks[i]);
    }
    if (syscall_result.return_value_ == 0) {
      return Api::ioCallUint64ResultNoError();
    }
    if (isAgainError(syscall_result.errno_)) {
      if (read_round_bytes_ != 0) {
        const uint8_t observed =
            static_cast<uint8_t>((read_round_bytes_ + Ubsocket::ReadBudgetPayloadCapacity - 1) /
                                 Ubsocket::ReadBudgetPayloadCapacity);
        if (observed > read_reservation_blocks_) {
          read_reservation_blocks_ = observed;
          low_use_streak_ = 0;
          low_use_max_blocks_ = 0;
        } else if (!read_round_limited_ && observed < read_reservation_blocks_) {
          low_use_max_blocks_ = std::max(low_use_max_blocks_, observed);
          if (++low_use_streak_ >= UdsReadShrinkThreshold) {
            read_reservation_blocks_ = low_use_max_blocks_;
            low_use_streak_ = 0;
            low_use_max_blocks_ = 0;
          }
        } else {
          low_use_streak_ = 0;
          low_use_max_blocks_ = 0;
        }
      }
      read_round_bytes_ = 0;
      read_round_limited_ = false;
      return againResult();
    }
    return failClosedResult(syscall_result.errno_, "UB UDS readv", fd_);
  }

  uint64_t remaining = static_cast<uint64_t>(syscall_result.return_value_);
  Buffer::ExternalStorageReleaseBatch release_batch;
  for (size_t i = 0; i < block_count; ++i) {
    Ubsocket::Block* block = blocks[i];
    const size_t used = static_cast<size_t>(std::min<uint64_t>(remaining, iov[i].iov_len));
    if (used == 0) {
      releaseBlock(api, block);
      continue;
    }
    block->size = static_cast<uint32_t>(used);
    block->cap = static_cast<uint32_t>(used);
    attachBlock(buffer, api, block);
    remaining -= used;
  }

  // Learn from a complete drain round, never from an individual short read/RPC.
  read_round_bytes_ =
      std::min<uint64_t>(MaxUdsReadReservation, read_round_bytes_ + syscall_result.return_value_);
  const bool filled_reservation =
      static_cast<uint64_t>(syscall_result.return_value_) == read_length;
  const bool full_tier_was_offered = read_length == selected_capacity;
  if (!one_block_probe && full_tier_was_offered && filled_reservation &&
      read_reservation_blocks_ < MaxUdsReadBlocks) {
    read_reservation_blocks_ = static_cast<uint8_t>(nextUdsReadTier(read_reservation_blocks_));
  }
  // A short read is not EAGAIN. Use one block to probe; return to the learned
  // capacity if that probe unexpectedly fills.
  one_block_probe_ = full_tier_was_offered && !filled_reservation;

  ASSERT(remaining == 0);
  return Api::IoCallUint64Result(static_cast<uint64_t>(syscall_result.return_value_),
                                 Api::IoError::none());
}

Api::IoCallUint64Result UbSocketHandleImpl::read(Buffer::Instance& buffer,
                                                 std::optional<uint64_t> max_length_opt) {
  if (max_length_opt.value_or(std::numeric_limits<uint64_t>::max()) == 0) {
    return Api::ioCallUint64ResultNoError();
  }

  KitexProbe::ScopedIoDetailPhase prepare(KitexProbe::IoDetailPhase::Prepare);
  const Ubsocket::Api& api = Ubsocket::Api::instance();
  if (!api.available()) {
    return failClosedResult(ENOSYS, "ubsocket_readv symbols unavailable", fd_);
  }
  const size_t capacity = api.blockPayloadCapacity();
  if (capacity == 0) {
    return failClosedResult(EINVAL, "unsupported UB block layout or transport mode", fd_);
  }

  Ubsocket::Block* anchor = allocateBlock(api, 0);
  if (anchor == nullptr) {
    const int error = errno;
    return failClosedResult(error, "ubsocket RX anchor allocation (check block layout and library)",
                            fd_);
  }

  struct iovec iov = {anchor->data, capacity};
  prepare.finish();
  ssize_t rc;
  {
    KitexProbe::ScopedIoDetailPhase syscall(KitexProbe::IoDetailPhase::Syscall);
    rc = api.readv_(fd_, &iov, 1);
  }
  const int saved_errno = errno;
  if (rc <= 0) {
    KitexProbe::recordIoCall(0, capacity, 1, rc < 0 ? 1 : 0, rc < 0 && isAgainError(saved_errno));
    KitexProbe::ScopedIoDetailPhase commit(KitexProbe::IoDetailPhase::Commit);
    releaseBlock(api, anchor);
    if (rc == 0) {
      return Api::ioCallUint64ResultNoError();
    }
    if (isAgainError(saved_errno)) {
      return againResult();
    }
    return failClosedResult(saved_errno, "ubsocket_readv", fd_);
  }

  KitexProbe::ScopedIoDetailPhase commit(KitexProbe::IoDetailPhase::Commit);
  absl::InlinedVector<Ubsocket::Block*, 64> blocks;
  Ubsocket::Block* block = anchor->u.next;
  uint64_t received = 0;
  bool valid = block != nullptr;
  while (valid && block != nullptr && received < static_cast<uint64_t>(rc) &&
         blocks.size() < MaxRxChainBlocks) {
    const bool valid_block =
        block->data == reinterpret_cast<char*>(block) + sizeof(Ubsocket::Block) &&
        block->cap != 0 && block->cap <= capacity &&
        received + block->cap <= static_cast<uint64_t>(rc);
    if (!valid_block) {
      valid = false;
      break;
    }
    blocks.push_back(block);
    received += block->cap;
    block = block->u.next;
  }
  valid = valid && received == static_cast<uint64_t>(rc) && block == nullptr;
  KitexProbe::recordIoCall(static_cast<uint64_t>(rc), static_cast<uint64_t>(rc), blocks.size(), 0,
                           false);

  if (!valid) {
    Ubsocket::Block* chain = anchor->u.next;
    anchor->u.next = nullptr;
    releaseChain(api, chain);
    releaseBlock(api, anchor);
    return failClosedResult(EPROTO, "invalid ubsocket_readv block chain", fd_);
  }

  anchor->u.next = nullptr;
  releaseBlock(api, anchor);
  for (Ubsocket::Block* received_block : blocks) {
    received_block->u.next = nullptr;
    attachBlock(buffer, api, received_block);
  }
  return Api::IoCallUint64Result(static_cast<uint64_t>(rc), Api::IoError::none());
}

Api::IoCallUint64Result UbSocketHandleImpl::writev(const Buffer::RawSlice* slices,
                                                   uint64_t num_slice) {
  KitexProbe::ScopedIoDetailPhase prepare(KitexProbe::IoDetailPhase::Prepare);
  const Ubsocket::Api& api = Ubsocket::Api::instance();
  if (!api.available()) {
    return failClosedResult(ENOSYS, "ubsocket_writev symbols unavailable", fd_);
  }
  if (api.blockPayloadCapacity() == 0) {
    return failClosedResult(EINVAL, "unsupported UB block layout or transport mode", fd_);
  }

  absl::InlinedVector<struct iovec, 64> iov;
  uint64_t bytes_to_write = 0;
  iov.reserve(std::min<uint64_t>(num_slice, MaxUbsocketIov));
  for (uint64_t i = 0; i < num_slice; ++i) {
    if (slices[i].mem_ != nullptr && slices[i].len_ != 0) {
      if (iov.size() == MaxUbsocketIov) {
        return failClosedResult(E2BIG, "ubsocket_writev iovec limit", fd_);
      }
      iov.push_back({slices[i].mem_, slices[i].len_});
      bytes_to_write += slices[i].len_;
    }
  }
  if (iov.empty()) {
    return Api::ioCallUint64ResultNoError();
  }

  prepare.finish();
  ssize_t rc;
  {
    KitexProbe::ScopedIoDetailPhase syscall(KitexProbe::IoDetailPhase::Syscall);
    rc = api.writev_(fd_, iov.data(), static_cast<int>(iov.size()));
  }
  const int saved_errno = errno;
  KitexProbe::recordIoCall(rc > 0 ? static_cast<uint64_t>(rc) : 0, bytes_to_write, iov.size(), 0,
                           rc < 0 && isAgainError(saved_errno));
  if (rc < 0) {
    if (isAgainError(saved_errno)) {
      return againResult();
    }
    return failClosedResult(saved_errno, "ubsocket_writev", fd_);
  }

  return Api::IoCallUint64Result(static_cast<uint64_t>(rc), Api::IoError::none());
}

namespace Ubsocket {

bool ioHandleUsesUbTransport(const IoHandle& io_handle) {
  return dynamic_cast<const UbSocketHandleImpl*>(&io_handle) != nullptr;
}

bool ioHandleUsesUbUdsRead(const IoHandle& io_handle) {
  return dynamic_cast<const UbUnixSocketHandleImpl*>(&io_handle) != nullptr;
}

bool connectionUsesUbTransport(const Connection& connection) {
  const auto* callbacks = dynamic_cast<const TransportSocketCallbacks*>(&connection);
  return callbacks != nullptr && ioHandleUsesUbTransport(callbacks->ioHandle());
}

bool connectionUsesUbUdsRead(const Connection& connection) {
  const auto* callbacks = dynamic_cast<const TransportSocketCallbacks*>(&connection);
  return callbacks != nullptr && ioHandleUsesUbUdsRead(callbacks->ioHandle());
}

} // namespace Ubsocket

} // namespace Network
} // namespace Envoy
