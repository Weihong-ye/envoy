#pragma once

#include <sys/uio.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/io_socket_handle_impl.h"

namespace Envoy {
namespace Network {

class Connection;

// UBSocket intercepts AF_SMC (43) socket creation and keeps the POSIX control plane.
constexpr int UbsocketAddressFamily = 43;

namespace Ubsocket {

// TX allocation layout, checked against the provider's capability response. RX owners are opaque.
struct Block {
  std::atomic<int> nshared;
  uint16_t flags;
  uint16_t abi_check;
  uint32_t size;
  uint32_t cap;
  union {
    Block* next;
    uint64_t data_meta;
  } u;
  char* data;
};

static_assert(sizeof(Block) == 32, "UBSocket block ABI changed");
// Preserve the existing 8K-based UDS read budget while allowing the physical allocator block to
// be selected independently at process start.
constexpr size_t ReadBudgetBlockSize = 8 * 1024;
constexpr size_t ReadBudgetPayloadCapacity = ReadBudgetBlockSize - sizeof(Block);
constexpr size_t DefaultBlockSize = 64 * 1024;
constexpr uint16_t BlockFlagsUb = 1U << 2;
static_assert(ReadBudgetPayloadCapacity == 8160, "UBSocket UDS read budget changed");

struct Capabilities {
  uint32_t struct_size;
  uint32_t abi_version;
  uint32_t block_size;
  uint32_t block_header_size;
  uint32_t max_batch_size;
  uint32_t reserved;
  uint64_t feature_flags;
};

struct Segment {
  const void* data;
  size_t length;
  void* owner;
};

// Construct before dispatchers; destroy after all workers, sockets and external slices.
class Runtime {
public:
  Runtime();
  ~Runtime();
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

private:
  void (*uninit_)() = nullptr;
};

class Api {
public:
  using ReadvFn = ssize_t (*)(int, Segment*, uint32_t, size_t);
  using ReleaseFn = void (*)(void*);
  using WritevFn = ssize_t (*)(int, const struct iovec*, int);
  using IobufAllocateBatchFn = int (*)(size_t, void**, uint32_t);
  using IobufDeallocateBatchFn = void (*)(void* const*, uint32_t);

  static const Api& instance();

  bool available() const { return available_ && blockSize() != 0; }
  size_t blockSize() const;
  size_t blockPayloadCapacity() const;

  const ReadvFn readv_;
  const ReleaseFn release_;
  const WritevFn writev_;
  const IobufAllocateBatchFn iobuf_allocate_batch_;
  const IobufDeallocateBatchFn iobuf_deallocate_batch_;

private:
  Api();

  const bool available_;
};

// Reuse UBSocket's transport mode so the same binary keeps ordinary socket behavior in TCP mode.
bool zeroCopyEnabled();
bool transportEnabled();

// Process transport mode is cached after its first observation. Tests that mutate the environment
// use this hook between observations; production code must not change transport mode after startup.
void resetTransportModeCacheForTest();

// Reload the process-start block setting between isolated tests, never with live UB allocations.
void resetBlockLayoutForTest();

// Return an empty factory outside UB mode. In UB mode every new mutable slice is backed by one
// UBSocket block and retains the caller-owned block reference until the slice is drained.
Buffer::OwnedImpl::SliceFactory createOutputSliceFactory(bool ub_destination = true);

} // namespace Ubsocket

/**
 * Stream socket handle for the versioned UBSocket v2 segment ABI.
 *
 * RX attaches bounded segments with opaque owners. TX passes UB-backed Envoy slices
 * to the direct ubsocket_writev_zc entry point. The selected Thrift path must take over ordinary
 * memory before it reaches this handle. Any missing symbol or UBSocket TCP fallback is returned as
 * an error instead of silently using a POSIX path.
 */
class UbSocketHandleImpl final : public IoSocketHandleImpl {
public:
  explicit UbSocketHandleImpl(os_fd_t fd = INVALID_SOCKET, bool socket_v6only = false,
                              std::optional<int> domain = std::nullopt,
                              size_t address_cache_max_capacity = 0, int creation_error = 0)
      : IoSocketHandleImpl(fd, socket_v6only, domain, address_cache_max_capacity),
        creation_error_(creation_error) {}

  Api::SysCallIntResult bind(Address::InstanceConstSharedPtr address) override;
  Api::SysCallIntResult connect(Address::InstanceConstSharedPtr address) override;
  Api::SysCallIntResult listen(int backlog) override;
  IoHandlePtr duplicate() override;

  Api::IoCallUint64Result read(Buffer::Instance& buffer,
                               std::optional<uint64_t> max_length) override;
  Api::IoCallUint64Result writev(const Buffer::RawSlice* slices, uint64_t num_slice) override;

private:
  const int creation_error_;
};

/**
 * AF_UNIX handle that reads Kitex UDS payloads directly into UBSocket-owned blocks.
 */
class UbUnixSocketHandleImpl final : public IoSocketHandleImpl {
public:
  explicit UbUnixSocketHandleImpl(os_fd_t fd = INVALID_SOCKET, bool socket_v6only = false,
                                  std::optional<int> domain = std::nullopt,
                                  size_t address_cache_max_capacity = 0)
      : IoSocketHandleImpl(fd, socket_v6only, domain, address_cache_max_capacity) {}

  Api::IoCallUint64Result read(Buffer::Instance& buffer,
                               std::optional<uint64_t> max_length) override;

private:
  // Counts baseline 8160-byte budget units, not physical blocks. A short read probes one unit
  // without discarding the learned tier. Physical blocks follow the process-start UB layout.
  uint8_t read_reservation_blocks_{1};
  uint8_t low_use_streak_{0};
  uint8_t low_use_max_blocks_{0};
  uint64_t read_round_bytes_{0};
  bool read_round_limited_{false};
  bool one_block_probe_{false};
};

namespace Ubsocket {

/** Whether an established connection sends through the explicit UBSocket data path. */
bool ioHandleUsesUbTransport(const IoHandle& io_handle);

/** Whether a UDS connection receives directly into UBSocket-owned blocks. */
bool ioHandleUsesUbUdsRead(const IoHandle& io_handle);

/** Inspect a real Envoy connection without invoking Connection::getSocket() on test doubles. */
bool connectionUsesUbTransport(const Connection& connection);
bool connectionUsesUbUdsRead(const Connection& connection);

} // namespace Ubsocket

} // namespace Network
} // namespace Envoy
