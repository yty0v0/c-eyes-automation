---
name: c-eyes-host-triage
description: 直接执行 C-Eyes `host-triage` workflow 的独立 skill。用于主机整体排查、快速体检和主机侧风险初查。
---

# C-Eyes Host Triage

这个 skill 只做一件事：执行固定的 `host-triage` workflow。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

不要把它当成自动调查链。需要串行推进多步调查时，改用 `$c-eyes-auto-triage`。

## 适用场景

- 排查单台主机是否存在明显异常
- 先做一次主机侧快速体检
- 需要为后续调查拿到主机初始风险视图

## 运行入口

- Windows：`scripts/run-host-triage-windows.ps1`
- Linux：`scripts/run-host-triage-linux.sh`

## 需要的输入

- 必需：`workspace`
- 可选：`dist-root`
- 可选：`risk-mode`
- 可选：`dry-run`

详细输入见 [references/inputs.md](references/inputs.md)。

## 执行规则

1. 固定执行 `host-triage`。
2. 不要再额外传入 `workflow` 选择参数。
3. 执行后先读取 `report_result/summary.md` 或 `report_result/report.html`，需要下钻时再读 `summary.json` 和 `manifest.json`。
4. 如果需要时间线、文件或基线补充，不要在这个 skill 内临时串联别的 workflow。

## 示例

### Windows

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\c-eyes-automation\skills\c-eyes-host-triage\scripts\run-host-triage-windows.ps1 `
  -Workspace .\workspace\host-triage `
  -DryRun
```

### Linux

```bash
bash ./c-eyes-automation/skills/c-eyes-host-triage/scripts/run-host-triage-linux.sh \
  --workspace ./workspace/host-triage \
  --dry-run
```

底层执行约定见 `$c-eyes-orchestrator`。
