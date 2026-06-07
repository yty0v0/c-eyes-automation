# C-Eyes Auto Triage Sub Agent

这个文档给上层主代理或后续多代理编排使用。它的目标不是解释所有细节，而是约束委托边界，避免子代理自由发挥成“临时拼 workflow”。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

## 适用场景

只在下面两类场景委托给 `c-eyes-auto-triage`：

1. 已经能明确归类为某个固定调查目标。
2. 需要基于既有 workspace 结果继续整理调查结论。

如果用户问题无法归入受支持目标，或者用户要求的是“自由组合多个 workflow”，不要委托给这个 skill。

## 允许的调查目标

- `host-investigation`
- `file-alert-investigation`
- `network-investigation`
- `baseline-investigation`

目标解释见 [references/goal-inputs.md](references/goal-inputs.md)。

## 委托前必须确认的输入

- `goal`
- `workspace`
- `platform`（Windows 或 Linux）

按目标可能还需要：

- `target-path`
- `time-window`
- `risk-mode`
- `baseline-level`
- `reachable-segments`

如果当前目标缺少必需输入，不要假设默认值足够覆盖业务语义。要么补齐输入，要么让调查以阻塞结束。

## 委托执行规则

1. 只允许选择一条固定调查链。
2. 只允许通过 `scripts/auto_triage.py` 或对应平台 wrapper 触发执行。
3. 不要直接调用原始 `c-eyes` CLI。
4. 不要跳过 `c-eyes-orchestrator` 自己拼底层 workflow 命令。
5. 每一步执行后，优先回读 `summary.json`，再回读 `manifest.json`。
6. 顶层结果生成后，优先读取 `report_result/report.html`，其次读取 `report_result/summary.md` 和 `report_result/report.xlsx`。
7. 结果已经足以回答问题时，可以停止，不需要把链上所有步骤强行跑完。

## 读取结果的顺序

先读顶层产物：

1. `report_result/report.html`
2. `report_result/summary.md`
3. `report_result/report.xlsx`
3. `decision.json`
4. `findings.json`
5. `next_actions.json`

只有在需要下钻证据时，再进入：

- `steps/<nn>-<workflow>/summary.json`
- `steps/<nn>-<workflow>/manifest.json`
- `steps/<nn>-<workflow>/outputs/*`

详细输出契约见 [references/output-contract.md](references/output-contract.md) 和 [report_renderers/investigation-summary.md](report_renderers/investigation-summary.md)。

## 必须停止并返回的情况

- 用户目标不在受支持集合内
- 缺少当前链必须输入，例如 `target-path`
- 某一步返回 `blocked`
- 某一步返回 `failed`
- 当前证据已经足以形成明确结论

详细停止条件见 [references/stop-rules.md](references/stop-rules.md)。
