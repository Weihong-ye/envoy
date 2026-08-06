#pragma once

// Kitex 端到端链路打点探针。
//
// 这是为「Kitex × Envoy 端到端时序归因」实验加的侵入式插桩，
// **不适合上游化**，故独立成库，插桩点保持一行式，便于 rebase 时定位与摘除。
//
// 为什么不用 ThriftFilter 而要改源码：
//   thrift_proxy 的 filter 只能观察到 transportBegin/messageBegin/messageEnd/
//   transportEnd 四个事件，看不到 listener accept、连接池 ready、upstream write、
//   响应首字节 —— 而这些正是双跳 sidecar 开销归因最需要的点。
//
// 三个设计约束：
//
//   1. 未采样请求必须近乎零开销。否则在压测下打点本身会主导测量结果
//      （100k QPS × 9 点全量记录 ≈ 每秒百万级事件）。
//   2. 请求路径上不做 IO、不加锁、不分配堆内存。
//      Envoy 是 per-worker 单线程事件循环，thread_local 天然无竞争。
//   3. E1（下游首字节）早于 TTHeader 解析，此刻 trace 未知。
//      必须先记后绑，否则永远拿不到「数据到达 Envoy」的时刻。

#include <cstdint>
#include <string>

#include "envoy/common/time.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace KitexProbe {

// 编译期总开关。关闭时所有宏展开为空，用于测量插桩自身的固定成本
// （设计文档 §8.6 的基线组）。
#ifndef KITEX_PROBE_ENABLED
#define KITEX_PROBE_ENABLED 1
#endif

/**
 * 记录一个连接级事件。此时尚不知道属于哪条 trace，也不知道是否采样，
 * 因此无条件记录，待 bindTrace 时决定去留。
 *
 * 只有 E1（下游首字节到达）用这个 —— 它是唯一早于 TTHeader 解析的点。
 */
void connEvent(uint64_t conn_id, absl::string_view point, MonotonicTime mono,
               SystemTime wall);

/**
 * 把某条连接上的待定事件绑定到具体 trace，并确定采样与否。
 *
 * traceparent 取自 TTHeader StrKV 里的 rpc_persist_traceparent。
 * 解析失败或 sampled 位未置时，该连接上的待定事件被丢弃，
 * 后续 rpcEvent 也会快速返回。
 */
void bindTrace(uint64_t conn_id, int32_t seq_id, absl::string_view traceparent,
               MonotonicTime mono, SystemTime wall);

/**
 * 记录一个 RPC 级事件。内部先查采样状态，未采样立即返回。
 */
void rpcEvent(uint64_t conn_id, absl::string_view point, MonotonicTime mono, SystemTime wall);

/**
 * RPC 结束，释放该连接上的绑定状态。
 */
void endRpc(uint64_t conn_id);

/**
 * 配置输出文件与节点名。未调用时探针不落盘（仅在内存中丢弃），
 * 这样单测和未启用打点的部署不会产生副作用。
 */
void configure(const std::string& path, const std::string& node);

/** 刷盘。进程退出前调用。 */
void flush();

/** 统计：总事件数、已落盘数、因缓冲区满而丢弃的数量。 */
struct Stats {
  uint64_t recorded;
  uint64_t written;
  uint64_t dropped;
};
Stats stats();

} // namespace KitexProbe
} // namespace Envoy

#if KITEX_PROBE_ENABLED

#define KITEX_PROBE_CONN(conn_id, point, time_source)                                              \
  ::Envoy::KitexProbe::connEvent((conn_id), (point), (time_source).monotonicTime(),                \
                                 (time_source).systemTime())

#define KITEX_PROBE_BIND(conn_id, seq_id, traceparent, time_source)                                \
  ::Envoy::KitexProbe::bindTrace((conn_id), (seq_id), (traceparent),                               \
                                 (time_source).monotonicTime(), (time_source).systemTime())

#define KITEX_PROBE(conn_id, point, time_source)                                                   \
  ::Envoy::KitexProbe::rpcEvent((conn_id), (point), (time_source).monotonicTime(),                 \
                                (time_source).systemTime())

#define KITEX_PROBE_END(conn_id) ::Envoy::KitexProbe::endRpc((conn_id))

#else

#define KITEX_PROBE_CONN(conn_id, point, time_source)                                              \
  do {                                                                                             \
  } while (0)
#define KITEX_PROBE_BIND(conn_id, seq_id, traceparent, time_source)                                \
  do {                                                                                             \
  } while (0)
#define KITEX_PROBE(conn_id, point, time_source)                                                   \
  do {                                                                                             \
  } while (0)
#define KITEX_PROBE_END(conn_id)                                                                   \
  do {                                                                                             \
  } while (0)

#endif
