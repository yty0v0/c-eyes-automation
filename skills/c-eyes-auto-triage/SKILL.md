---
name: c-eyes-auto-triage
description: 基于调查目标自动选择并串行执行固定的 C-Eyes 调查链，输出决策、发现和下一步建议。用于主机排查、文件告警排查、内网资产排查和基线核查这类 EDR 自动化调查场景。调用时应通过现有的 $c-eyes-orchestrator 执行每个底层 workflow，而不是手写原始 C-Eyes CLI。
---

# C-Eyes Auto Triage

这个 skill 负责上层自动调查编排，不负责直接运行原始 `c-eyes` 二进制。它接收调查目标，选择一条固定调查链，逐步调用 `$c-eyes-orchestrator`，读取每一步的 `summary.json` 和 `manifest.json`，再决定是否继续推进，并在工作区根目录生成 `report_result/` 最终报告层。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

## 目录导航

- `SKILL.md`：主入口，说明 skill 边界、运行入口和快速流程
- `sub_agent.md`：给上层主代理或子代理使用的委托规则
- `agents/openai.yaml`：provider 侧默认提示
- `scripts/`：唯一的执行入口，包含 Python runner 和 Windows / Linux wrapper
- `references/goal-inputs.md`：调查目标和输入要求
- `references/investigation-chains.md`：固定调查链定义
- `references/stop-rules.md`：何时停止自动推进
- `references/output-contract.md`：顶层结果文件和证据下钻约定
- `report_renderers/investigation-summary.md`：如何把 workspace 结果整理成可读摘要

## 调查目标

优先把用户请求归到以下目标之一：

- `host-investigation`
- `file-alert-investigation`
- `network-investigation`
- `baseline-investigation`

目标解释和输入要求见 [references/goal-inputs.md](references/goal-inputs.md)。

如果用户目标不属于上述集合，直接返回阻塞，不要临时自由规划 workflow。

## 执行边界

1. 先选一个最贴近用户目标的固定调查链，不要默认并行执行多条链。
2. 每一步都必须通过 `$c-eyes-orchestrator` 执行对应 workflow。
3. 不要直接拼接 `c-eyes.exe`、`c-eyes` 或其他原始运行时命令。
4. 每完成一步，先读取该步的 `summary.json`，再读取 `manifest.json`。
5. 如果某一步被权限、运行时缺失或参数缺失阻塞，直接记录阻塞原因并停止链路推进。
6. 如果当前结果已经足以回答用户问题，就停止，不要为了“更全”而继续跑后续步骤。
7. 顶层结果完成后，先查看 `report_result/report.html`，再看 `report_result/summary.md` 和 `report_result/report.xlsx`，需要证据下钻时再回到 JSON 和 `steps/`。

固定链和停止条件分别见：

- [references/investigation-chains.md](references/investigation-chains.md)
- [references/stop-rules.md](references/stop-rules.md)

## 运行入口

- Windows：`scripts/run-auto-triage-windows.ps1`
- Linux：`scripts/run-auto-triage-linux.sh`
- Python：`scripts/auto_triage.py`

## 快速流程

当用户提出“帮我自动排查主机异常”“帮我看这个可疑目录”“帮我做基线检查”这类目标时：

1. 选择最匹配的调查目标
2. 确认目标所需输入是否齐全
3. 按固定链逐步调用 `$c-eyes-orchestrator`
4. 每一步读取结果后再决定是否继续
5. 产出 `decision.json`、`findings.json`、`next_actions.json` 和 `report_result/`
6. 如需汇总结果，再交给 `report_renderers/` 里的说明做整理

输出契约见 [references/output-contract.md](references/output-contract.md)。

### Windows

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\c-eyes-automation\skills\c-eyes-auto-triage\scripts\run-auto-triage-windows.ps1 `
  -Goal host-investigation `
  -Workspace .\workspace\ceyes-auto-host `
  -DryRun
```

### Linux

```bash
bash ./c-eyes-automation/skills/c-eyes-auto-triage/scripts/run-auto-triage-linux.sh \
  --goal file-alert-investigation \
  --workspace ./workspace/ceyes-auto-file \
  --target-path /srv/www \
  --dry-run
```

## 资源

- 子代理委托规则：见 [sub_agent.md](sub_agent.md)
- 目标与输入：见 [references/goal-inputs.md](references/goal-inputs.md)
- 链路定义：见 [references/investigation-chains.md](references/investigation-chains.md)
- 停止规则：见 [references/stop-rules.md](references/stop-rules.md)
- 输出契约：见 [references/output-contract.md](references/output-contract.md)
- 结果整理入口：见 [report_renderers/investigation-summary.md](report_renderers/investigation-summary.md)
- 底层 workflow 参数与执行约定：调用前读取 `$c-eyes-orchestrator` 的 `SKILL.md` 和所需 references
