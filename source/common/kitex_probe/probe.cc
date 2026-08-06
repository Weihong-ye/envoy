#include "source/common/kitex_probe/probe.h"

#include <atomic>
#include <memory>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/syscall.h>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_format.h"

namespace Envoy {
namespace KitexProbe {
namespace {

// W3C traceparent: 00-<32 hex trace-id>-<16 hex span-id>-<2 hex flags>
// flags 的 bit0 是 sampled。
constexpr size_t TraceparentLen = 55;
constexpr size_t TraceIdOffset = 3;
constexpr size_t TraceIdLen = 32;
constexpr size_t FlagsOffset = 53;

struct Parsed {
  bool valid{false};
  bool sampled{false};
  absl::string_view trace_id;
};

Parsed parseTraceparent(absl::string_view tp) {
  Parsed p;
  if (tp.size() != TraceparentLen || tp[2] != '-' || tp[35] != '-' || tp[52] != '-') {
    return p;
  }
  const char hi = tp[FlagsOffset];
  const char lo = tp[FlagsOffset + 1];
  auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    return -1;
  };
  const int h = hex(hi), l = hex(lo);
  if (h < 0 || l < 0) {
    return p;
  }
  p.valid = true;
  p.sampled = ((h << 4) | l) & 0x01;
  p.trace_id = tp.substr(TraceIdOffset, TraceIdLen);
  return p;
}

// Event 不再自带 trace 字符串。
//
// trace-id 是 32 字符，超过 SSO 阈值必然堆分配；而它在一次 RPC 内不变，
// 每个点都拷一份等于每请求多做 8 次 malloc。改成共享同一份：
// binding 持有 shared_ptr<const std::string>，事件只拷指针。
// point 是短名字（SSO 内，无分配），且都是字面量，直接存 string_view。
struct Event {
  std::shared_ptr<const std::string> trace;
  absl::string_view point; // 指向静态字面量，生命周期长于事件
  int64_t mono_ns;
  int64_t wall_ns;
  int32_t seq_id;
};

// 某条连接上「已解析出 trace、正在处理」的 RPC 状态。
struct Binding {
  std::shared_ptr<const std::string> trace;
  int32_t seq_id{0};
  bool sampled{false};
  // wall/mono 的对应基准点，用于由 mono 推算 wall，省去每点一次 CLOCK_REALTIME
  int64_t base_mono{0};
  int64_t base_wall{0};
};

// 每 worker 线程一份。Envoy 的 worker 是单线程事件循环，
// 所以这里既不需要锁，也不存在伪共享。
class ThreadState {
public:
  // E1 用：此刻还不知道 trace，先按连接暂存。
  // 一条连接上同时最多有少量待定事件（通常 1 个），用小 vector 足够。
  absl::flat_hash_map<uint64_t, std::vector<Event>> pending;
  absl::flat_hash_map<uint64_t, Binding> bindings;
  std::vector<Event> ready;
  int64_t last_flush_ns{0};
  // 每个 worker 线程写自己的文件。
  //
  // 曾经所有线程都 fopen(path,"a") 追加写同一个文件，结果 JSON 行被切碎重组
  // ——O_APPEND 只保证单次 write 的原子性，而批量刷盘会跨多次 write，
  // 于是不同线程的输出互相穿插。表现为 merge 出来的节点名是拼接乱码。
  // 每线程独立文件既解决了交错，也避免了在刷盘路径上加锁。
  std::string path;
  // 常开的文件句柄。每次 writeOut 都 fopen/fclose 的话，
  // 在高 QPS 下 open 系统调用本身就会成为可观的开销。
  FILE* fp{nullptr};
};

ThreadState& tls() {
  static thread_local ThreadState state;
  return state;
}

// 输出配置是进程级的，首次使用时从环境变量读取，之后只读。
//
// 用环境变量而不是扩展 bootstrap schema：探针是实验性的侵入式插桩，
// 不该污染 Envoy 的配置接口；而且这样同一个二进制既能带探针跑，
// 也能不设变量当普通 Envoy 用（§8.6 的对照组）。
//
//   KITEX_PROBE_PATH=/tmp/kitex-demo/trace-envoy-out.ndjson
//   KITEX_PROBE_NODE=envoy-out
struct Config {
  std::string path;
  std::string node;
  std::string host;
  bool enabled{false};
};

Config& config() {
  static Config c = [] {
    Config init;
    const char* path = std::getenv("KITEX_PROBE_PATH");
    const char* node = std::getenv("KITEX_PROBE_NODE");
    if (path != nullptr && *path != '\0') {
      init.path = path;
      init.node = (node != nullptr && *node != '\0') ? node : "envoy";
      // host 标识决定 merge 工具是否允许把两个事件的时间戳相减（§8.2），
      // 因此必须能真正区分机器。
      //
      // **不能只靠 gethostname**：本实验的两台机器 hostname 都是
      // localhost.localdomain，靠它判断会把跨机误判成同机，
      // 于是跨机相减这一最危险的操作反而畅通无阻。
      // 所以优先取显式配置的 KITEX_PROBE_HOST。
      const char* host = std::getenv("KITEX_PROBE_HOST");
      if (host != nullptr && *host != '\0') {
        init.host = host;
      } else {
        char hostname[256] = {0};
        init.host = (::gethostname(hostname, sizeof(hostname) - 1) == 0) ? hostname : "unknown";
      }
      init.enabled = true;
    }
    return init;
  }();
  return c;
}

std::atomic<uint64_t> g_recorded{0};
std::atomic<uint64_t> g_written{0};
std::atomic<uint64_t> g_dropped{0};

// ready 累积到这个数量就刷盘。
// 取值权衡：太小则频繁 IO 影响请求路径，太大则进程异常退出时丢失过多。
constexpr size_t FlushThreshold = 512;
// 单线程最多缓存多少事件。超过即丢弃并计数 —— 宁可丢数据也不能阻塞请求，
// 那会直接改变被测系统的行为。
constexpr size_t MaxBuffered = 1 << 16;

int64_t monoNs(MonotonicTime t) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(t.time_since_epoch()).count();
}
int64_t wallNs(SystemTime t) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(t.time_since_epoch()).count();
}

void writeOut(ThreadState& st, std::vector<Event>& events) {
  if (events.empty()) {
    return;
  }
  auto& cfg = config();
  if (!cfg.enabled) {
    events.clear();
    return;
  }
  if (st.fp == nullptr) {
    st.path = absl::StrFormat("%s.%d", cfg.path, static_cast<int>(::syscall(SYS_gettid)));
    st.fp = std::fopen(st.path.c_str(), "a");
  }
  FILE* f = st.fp;
  if (f == nullptr) {
    events.clear();
    return;
  }
  for (const auto& e : events) {
    // 字段与 Kitex 侧 probe 包保持一致，merge 工具才能统一处理。
    // wall 仅供粗排序，跨机相减由 merge 工具拒绝（设计文档 §8.2）。
    absl::FPrintF(f,
                  R"({"host":"%s","node":"%s","trace":"%s","point":"%s","wall_ns":%d,"mono_ns":%d,)"
                  R"("attrs":{"seq_id":"%d"}})"
                  "\n",
                  cfg.host, cfg.node, *e.trace, e.point, e.wall_ns, e.mono_ns, e.seq_id);
  }
  g_written.fetch_add(events.size(), std::memory_order_relaxed);
  events.clear();
}

// 距上次刷盘超过这个时间就刷一次，即使没攒够 FlushThreshold。
// 没有它的话，低速率场景（功能验证、低采样率压测）会一直攒在内存里不落盘，
// 表现为「明明跑通了却没有 trace 文件」。
constexpr int64_t FlushIntervalNs = 200 * 1000 * 1000; // 200ms

void push(ThreadState& st, Event&& e) {
  if (st.ready.size() >= MaxBuffered) {
    g_dropped.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  const int64_t now = e.mono_ns;
  st.ready.push_back(std::move(e));
  g_recorded.fetch_add(1, std::memory_order_relaxed);

  // 用事件自带的时间戳判断，避免为了刷盘再读一次时钟。
  if (st.last_flush_ns == 0) {
    st.last_flush_ns = now;
  }
  if (st.ready.size() >= FlushThreshold || (now - st.last_flush_ns) >= FlushIntervalNs) {
    writeOut(st, st.ready);
    st.last_flush_ns = now;
  }
}

} // namespace

void configure(const std::string& path, const std::string& node) {
  auto& c = config();
  c.path = path;
  c.node = node;
  c.enabled = !path.empty();
}

void connEvent(uint64_t conn_id, absl::string_view point, MonotonicTime mono, SystemTime wall) {
  if (!config().enabled) {
    return;
  }
  auto& st = tls();
  auto& vec = st.pending[conn_id];
  // 单条连接上待定事件不应堆积。若堆积说明 bindTrace 没被调用
  // （例如解码失败的连接），直接丢弃最早的，避免无界增长。
  if (vec.size() > 8) {
    vec.erase(vec.begin());
  }
  vec.push_back(Event{nullptr, point, monoNs(mono), wallNs(wall), 0});
}

void bindTrace(uint64_t conn_id, int32_t seq_id, absl::string_view traceparent, MonotonicTime mono,
               SystemTime wall) {
  if (!config().enabled) {
    return;
  }
  auto& st = tls();
  const Parsed p = parseTraceparent(traceparent);

  Binding b;
  b.seq_id = seq_id;
  b.base_mono = monoNs(mono);
  b.base_wall = wallNs(wall);
  if (p.valid) {
    // 整条 RPC 只在这里构造一次 trace 字符串
    b.trace = std::make_shared<const std::string>(p.trace_id);
    b.sampled = p.sampled;
  }
  st.bindings[conn_id] = b;

  auto it = st.pending.find(conn_id);
  if (it == st.pending.end()) {
    return;
  }
  if (b.sampled) {
    // 回填：把 E1 那批事件挂到刚解析出的 trace 上。
    // 不做这一步，「下游首字节到达」这个点就永远无法与其余点关联。
    for (auto& e : it->second) {
      e.trace = b.trace;
      e.seq_id = seq_id;
      push(st, std::move(e));
    }
    // bindTrace 自身也是一个点（E2：header 解析完成）
    push(st, Event{b.trace, absl::string_view("hdr_decoded"), monoNs(mono), wallNs(wall), seq_id});
  }
  it->second.clear();
}

void rpcEvent(uint64_t conn_id, absl::string_view point, MonotonicTime mono) {
  if (!config().enabled) {
    return;
  }
  auto& st = tls();
  auto it = st.bindings.find(conn_id);
  // 未采样时这里就返回 —— 一次哈希查找加一次布尔判断。
  if (it == st.bindings.end() || !it->second.sampled) {
    return;
  }
  const auto& b = it->second;
  const int64_t m = monoNs(mono);
  // wall 由基准点推算，不再读 CLOCK_REALTIME
  push(st, Event{b.trace, point, m, b.base_wall + (m - b.base_mono), b.seq_id});
}

void endRpc(uint64_t conn_id) {
  if (!config().enabled) {
    return;
  }
  auto& st = tls();
  st.bindings.erase(conn_id);
  st.pending.erase(conn_id);
  // 这里**不**落盘。
  //
  // 曾经每次 RPC 结束都 writeOut + fflush，那是为了解决「流量停止后
  // 最后一批事件永远留在内存」的问题 —— 但代价是每个采样请求一次
  // write 系统调用。收尾问题应该由进程退出时的 flush 解决，
  // 而不是让稳态路径为它买单（见 registerExitFlush）。
}

void flush() {
  auto& st = tls();
  writeOut(st, st.ready);
  if (st.fp != nullptr) {
    std::fflush(st.fp);
  }
}

namespace {
// 线程退出时把该线程剩余的事件落盘。
//
// 这才是「收尾」的正确位置：稳态路径完全不必为此付出代价，
// 而进程/线程结束时只做一次。
struct ThreadFlusher {
  ~ThreadFlusher() { flush(); }
};
thread_local ThreadFlusher g_thread_flusher;
} // namespace

Stats stats() {
  return Stats{g_recorded.load(std::memory_order_relaxed),
               g_written.load(std::memory_order_relaxed),
               g_dropped.load(std::memory_order_relaxed)};
}

} // namespace KitexProbe
} // namespace Envoy
