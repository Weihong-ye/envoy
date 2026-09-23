# UBSocket v2 功能联调

这是开发分支的功能验证入口，不是性能基准，也不代表生产验收。

## 当前接入方式

- 仅 Linux；两端使用本分支 Envoy 与统一 UBSocket 仓库的 `feat/envoy-ubsocket-v2`。
- 只加载 `libubsocket_preload.so`。不要同时加载 `libubsocket.so`，避免出现两份全局状态。
- Envoy 主入口在创建 dispatcher 前显式初始化，在 worker、socket 和外部 slice 销毁后退出 UBSocket。
- 数据面调用 `read_zc` / `release_zc` / `writev_zc`；不拦截普通 `read` / `write` / `readv` / `writev`。
- 能力信息启动时查询并缓存，要求 ABI 1、64 KiB 物理块、32 字节 TX 块头及完整分段能力。
- 明确选择 UB 的地址在能力或建链失败时返回错误，不能退回 TCP。

## 真机构建与手动配置

以用户提供的 v2 构建方式为准，显式打开 URMA dlopen 后端；该开关在当前源码中默认也是 ON。
以下源码目录必须包含本次 Envoy 适配改动，只有原始 v2 源码不一定会生成 `libubsocket_preload.so`。
构建命令不设置运行时环境变量，也不修改系统驱动或 SDK。

```bash
cmake -S /home/share/l30030098/ubs-comm-self \
  -B /home/share/l30030098/ubs-comm-self/build_1 \
  -DBUILD_UBSOCKET=ON \
  -DBUILD_URMA_DLOPEN_BACKEND=ON

cmake --build /home/share/l30030098/ubs-comm-self/build_1 --parallel 8
```

下面是跨机手动联调的**目标配置，不是已通过的 UB 启动方案**。
设备 `udmac0d1e2`、EID 索引 `1` 来自用户提供的示例，两端各自按实际环境核对。
Envoy 二进制路径是占位路径，必须替换为配套 v2 产物。绑核和 16 worker 沿用原有测试口径。
业务 YAML 只读复制到独立 v2 目录；并行运行时使用独立监听/admin 端口和 UDS 路径，不修改 v1 文件。
所有环境变量只传给这次命令及其子进程，不使用 `export`。

```bash
env \
  LD_PRELOAD=/home/share/l30030098/ubs-comm-self/build_1/src/ubsocket/csrc/libubsocket_preload.so \
  ENVOY_UB_EXTRA_IPS="141.61.17.206,141.61.17.208" \
  KITEX_PROBE_DISABLE=1 \
  UBSOCKET_TRANS_MODE=ub \
  UBSOCKET_DEGRADE_ENABLE=false \
  UBSOCKET_UB_HANDSHAKE_MODE=ub_sock_opt \
  UBSOCKET_UB_BUSY_POLLING=0 \
  UBSOCKET_UB_BOUNDING_DEV=0 \
  UBSOCKET_UB_DEV=udmac0d1e2 \
  UBSOCKET_UB_EID_IDX=1 \
  UBSOCKET_EPOLL_HANDLE_MODE=0 \
  UBSOCKET_MONITOR_ENABLE=false \
  UBSOCKET_SPLIT_TRACE_ENABLE=false \
  UBSOCKET_CLI_ENABLE=false \
  UBSOCKET_PROBE_ENABLE=false \
  taskset -c 96-111 \
    /path/to/v2/envoy-static \
    -c /absolute/path/to/v2/two-hop-in-remote-ub.yaml \
    --base-id 10 --disable-hot-restart --concurrency 16 --log-level warn
```

客户端使用 `two-hop-out-remote-ub.yaml`，并按客户端实际设备、EID 和文件路径调整。
SDK 库不在系统搜索路径时，将 `LD_LIBRARY_PATH=/actual/sdk/lib` 同样放到 `env` 的参数中，
不要全局 export，也不要把 v1 UBSocket 一起 preload。URMA 后端通过 `dlopen("liburma.so", ...)` 加载，
因此 `ldd libubsocket_preload.so` 没列出 URMA 并不意味着运行时不需要它。

参数解释及当前限制：

- `UBSOCKET_UB_BUSY_POLLING=0`：不选择独立 poller 的忙轮询配置；模式 1 本身不启动独立 poller 线程。
- `UBSOCKET_UB_BOUNDING_DEV=0`：影响未指定设备时的自动选择路径，也参与 RDMA READ 完成标志配置；保留用户指定值，不按无关参数删除。
- `UBSOCKET_EPOLL_HANDLE_MODE=0` 是库默认值，使用独立 URMA poller；`1` 由应用 epoll 线程内联驱动 JFC 处理，并在读取侧消费延迟事件。
- 当前运行基线固定 mode `0` + `ub_sock_opt`。此前 mode 0 + TFO 循环测试出现过间歇失败；本轮修复后的真机循环尚待验收。
- 模式 1 暂不作为当前 Envoy 多 dispatcher 部署的可用选项。各 epoll 共享全局 JFC，局部 poller 锁不能解决全部事件所有权和唤醒边界；即使 concurrency 1 也另有主 dispatcher，不能据此认定安全。
- 不把旧 UMQ 的 `RC_TP`、pool、jetty、flow-control 等参数当成 URMA 的等价设置；当前后端 RM/CTP、64KiB 块和 256MB 初始池仍是已知版本差异。

## 一机双进程演示

链路：测试客户端 → UDS → Envoy-out → **UB 或 TCP** → Envoy-in → UDS echo 服务。
脚本自行选择端口和短 UDS 路径；不停止已有服务、不修改驱动或系统网络参数。

```bash
python3 tools/ubsocket_v2_smoke.py \
  --envoy /absolute/path/to/envoy-static \
  --preload /absolute/path/to/libubsocket_preload.so \
  --mode ub --workers 1 \
  --out-device udmac0d1e2 --in-device udmac0d1e2 \
  --out-eid-index 1 --in-eid-index 1 \
  --handshake-mode ub_sock_opt --epoll-handle-mode 0 \
  --artifact-dir /absolute/path/to/results
```

设备必须支持所选 EID 的同机通信；如需不同设备，可以分别指定两端设备。
这不是跨机器验证。`--ub-ip` 默认使用 `127.0.0.2`，与 admin 的 `127.0.0.1` 分离。
脚本默认 EID 索引 `1`、握手 `ub_sock_opt`、线程模型 `0`，两端 EID 可分别通过参数指定。
脚本显式设置 `BUSY_POLLING=0`、`BOUNDING_DEV=0` 和诊断开关，不修改父 shell 环境。
如需改变 EID，应使用脚本参数，而不是在命令前设置会被子进程配置覆盖的 EID 环境变量。

覆盖三次新建连接，每次测试 1、127、4096、65503、65504、65535、65536、65537、131072、262144 字节。
逐字节比较回包，并保存 SHA-256、两端配置、日志、admin 统计和退出状态。
配置包含临时 UDS 路径，复现时请重新运行脚本，而不是直接重用旧 JSON。

使用 `--mode tcp` 可先验证普通 TCP/UDS/admin 与 preload 的未初始化透传路径。
**TCP 模式通过不等于 UB 模式通过，也不证明已初始化状态下的混合 epoll 已完成硬件验收。**

## UB 模式前提

- URMA 用户态库、provider 和匹配的内核驱动可用。
- `/dev/uburma/<device>` 存在且可访问；只有 `urma_admin show` 中的 ACTIVE 状态不够。
- 当前一机脚本与跨机手动配置均默认 `ub_sock_opt`。
- mode 1 的 mock UT 不能替代硬件验收；目标配置及缺口见上节。
- 脚本关闭旧 UMQ 监控与 split trace；这些诊断功能尚未完成 URMA 适配。

## 尚未完成的验收

主动建链仍沿用源分支的同步协商流程；不能把本轮功能入口视为非阻塞建链完成。
仍需验证慢握手、建链期间取消/关闭、多 worker、真实背压及未完成 DMA 的断连回收。
控制 TCP 的半关闭与在途 UB 数据完成之间还需要明确顺序保证。
最终 Kitex/Thrift 跨机验收与性能测试单独推进。

## 本轮实际结果（2026-09-15）

- 已构建 ARM64 Envoy 完整二进制及 UBSocket v2 preload；Envoy 适配器 33 个用例和地址选择器测试通过。
- TCP 模式双 Envoy、2 个 worker 的 30 组字节校验通过，包含三次连接、admin 访问和正常退出。
- 实际结果目录：开发机隔离工作区 `smoke-results/envoy-v2-lmu73_vc/`；不是模拟 UB 测试。
- UB 模式尚未通过：开发机未加载 `uburma`，缺少 `/dev/uburma`，URMA 初始化失败。
- 该失败还暴露了 UB listener 创建失败时的断言退出；本地已补错误传递和一个回归用例，但最新补丁尚未重新构建、运行，不能算作验证通过。
- 当时后续代码上传被安全审批阻止，以上为历史结果；2026-09-16 用户已授权独立临时目录上传与构建，但未授权加载驱动。
- UBSocket 全量 CTest 为 20 个 targets、14 个通过；6 个失败 targets 中的 15 个失败用例与 baseline 相同。新增控制面及 ACK 用例通过，不将全量结果写成全绿。

远端工作区：`/home/bot-ywh-950/ubsocket-v2-20260915.TKEUKZ`。
以上历史二进制不包含最后的 listener 错误处理修复；本次交付包的实际结果见独立 `VERIFICATION.md`，不复用历史通过结论。
文件描述符表在初始化时按当时的 `RLIMIT_NOFILE` 分配，后续上调进程限制的边界尚未验收；首轮功能验证不覆盖大连接数。

## 独立候选交付复验（2026-09-16）

- 配套 ARM64 Envoy 完整目标及用户指定两参数的 UBSocket `build_1` 均重新构建成功。
- Envoy 定向 4 targets、140 用例通过：UB handle 34、地址选择器 3、Thrift conn_manager 55、TTHeader 48。
- 最终交付库组合的 TCP 模式在 2 / 16 worker 下各通过 30 次回包校验，含重连、admin、UDS 和正常退出。
- 无 UB 设备的负向启动确认返回 `No such device`、Envoy exit 1，不再触发 listener 断言或静默回退 TCP。
- UBSocket 20 targets、439 用例；剩余 14 个失败都属于 baseline，原 dispatcher ACK 用例已转为通过。
- 真实 UB 模式仍未通过硬件联调；此处 TCP 与缺设备错误路径结果不能代替 UB 收发验证。
- 交付命令、依赖版本、未完成项与源码身份见独立 tar 内的 `README.md`、`VERIFICATION.md`、`MANIFEST.json`。
