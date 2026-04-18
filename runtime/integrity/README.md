# runtime/integrity

- 对应 plan：§16.1 / §16.3
- 当前状态：region-registry-ready

## 组件
- `ProtectedRegion`：受保护区域描述（`name/base/size/expected_sha256/flags`）
- `RegionRegistry`：线程安全注册表，支持 `register_region` / `unregister` / `all` / `verify_one` / `verify_all`
- 哈希算法：复用 subtask 6 的纯 C++ `SHA-256`

## 语义
- 首次 `register_region(...)` 时若 `expected_sha256` 为全 0，则以当前内存内容捕获初始摘要。
- 后续 `verify_one/verify_all` 对运行时内存重新做 `SHA-256` 比较。
- 发现不一致时：
  - 返回 `RegionVerifyStatus::mismatch`
  - 通过 `RuntimeState::observe(integrity_failed, region_name)` 上报
  - 触发统一状态机进入 `Degraded`（或在已降级状态下进入 `Terminating`）

## Loader 集成
- 各平台 loader 在初始化时注册自身代码片段与固定 salt 所在 rodata。
- loader 保留 `register_optional_rewriter_regions()` 入口，用于未来接入 `.vmpstrings` / `.vmpcode` 注册。

## 审计
- 运行时完整性失败会写 `integrity_failed` 审计事件。
- 状态切换另写 `state_transition`。
