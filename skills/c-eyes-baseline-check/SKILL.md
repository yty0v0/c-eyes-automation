---
name: c-eyes-baseline-check
description: 直接执行 C-Eyes `baseline-check` workflow 的独立 skill。用于主机安全基线核查和配置偏差检查。
---

# C-Eyes Baseline Check

这个 skill 只执行固定的 `baseline-check` workflow。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

## 适用场景

- 需要做安全基线核查
- 需要看主机配置偏差
- 需要先拿基线结果再决定是否继续补时间线

## 运行入口

- Windows：`scripts/run-baseline-check-windows.ps1`
- Linux：`scripts/run-baseline-check-linux.sh`

## 需要的输入

- 必需：`workspace`
- 可选：`baseline-level`
- 可选：`dist-root`
- 可选：`dry-run`

详细输入见 [references/inputs.md](references/inputs.md)。

## 执行规则

1. 固定执行 `baseline-check`。
2. 只在用户明确要求时调整 `baseline-level`。
3. 不在这里自动串联事件时间线。
