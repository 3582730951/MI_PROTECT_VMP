# runtime/state

- 对应 plan：§7.5、§13、§14、§16
- 当前状态：state-machine-finalized

## 状态机

```text
Init --init_done--> Ready
Ready --env_anomaly|integrity_failed|detection_event--> Degraded
Ready --hw_breakpoint--> Terminating
Ready --shutdown_requested--> Terminating
Ready --hot_threshold_reached|audit_event|key_rotated--> Ready
Degraded --further_failure|timeout--> Terminating
Degraded --shutdown_requested--> Terminating
```

> Owner override（2026-04-18）：`hw_breakpoint` 不经过 `Degraded`，执行 `audit_then_delayed_exit`，即先审计、再延迟进入 `Terminating`。

## 统一事件
- `env_anomaly`
- `integrity_failed`
- `hot_threshold_reached`
- `audit_event`
- `key_rotated`
- `detection_event`
- `shutdown_requested`
- `hw_breakpoint`
- 内部事件：`init_done` / `further_failure` / `timeout`

## 进入动作
### Enter Degraded
- 使所有 JIT 缓存失效
- 全局 `plaintext_budget` 提升为 `none`（拒绝新的瞬时解密）
- HotScheduler 切到 `conservative`

### Enter Terminating
- 立刻写 `state_transition`
- 写 `terminating_grace_start`
- grace 到期后：
  - 失效 JIT
  - 擦除全部 `KeyContext` 派生子密钥槽
  - 执行已注册 wipe callback
  - 写 `terminating_done`
  - `exit(0)`（默认 `VMP_TERMINATE_GRACE_MS=500`，可配置）

## Snapshot / API
- `RuntimeState::init_once(audit*, config)`
- `RuntimeState::current_state()`
- `RuntimeState::observe(kind, payload)`
- `RuntimeState::on_transition(cb)`
- `RuntimeState::get_hot_scheduler()`
- `RuntimeState::snapshot()`

## 审计事件
- `integrity_failed`
- `state_transition`
- `jit_cache_integrity_failure`
- `terminating_grace_start`
- `terminating_done`
- 既有 profile / scheduler 事件仍保留

## CLI
- `vmp-state-probe --event integrity_failed:region_X|hw_breakpoint|env_anomaly|shutdown [--audit path] [--no-exit]`
