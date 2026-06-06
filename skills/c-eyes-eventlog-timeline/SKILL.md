---
name: c-eyes-eventlog-timeline
description: 直接执行 C-Eyes `eventlog-timeline` workflow 的独立 skill。用于导出事件日志时间线和近期活动上下文。
---

# C-Eyes Eventlog Timeline

这个 skill 只执行固定的 `eventlog-timeline` workflow。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

## 适用场景

- 需要快速看近期事件日志
- 需要围绕主机活动补时间线
- 需要先拿近期上下文再决定下一步

## 运行入口

- Windows：`scripts/run-eventlog-timeline-windows.ps1`
- Linux：`scripts/run-eventlog-timeline-linux.sh`

## 需要的输入

- 必需：`workspace`
- 可选：`time-window`
- 可选：`dist-root`
- 可选：`dry-run`

详细输入见 [references/inputs.md](references/inputs.md)。

## 执行规则

1. 固定执行 `eventlog-timeline`。
2. 只在需要时才调整 `time-window`。
3. 不在这个 skill 内自动串联主机排查或文件扫描。
