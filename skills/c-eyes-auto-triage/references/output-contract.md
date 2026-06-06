# 输出契约

这个文档定义 `c-eyes-auto-triage` 的稳定结果入口。它不负责解释链选择规则。

## 最终报告目录

每次自动调查完成后，工作区根目录下还会生成：

- `report_result/report.json`
- `report_result/summary.md`
- `report_result/report.html`

这组文件是面向人工查看的最终报告层。

## 顶层结果文件

每次自动调查完成后，机器可读入口仍然优先读取工作区根目录下的三个文件：

1. `decision.json`
2. `findings.json`
3. `next_actions.json`

这三个文件是上层消费入口，后续的渲染器、跟进 agent 或人工复核都应先从这里进入，而不是先遍历 `steps/`。

## 文件职责

### `decision.json`

记录：

- 调查目标
- 选中的固定链
- 已执行步骤
- 当前状态
- 停止原因

### `findings.json`

记录：

- 是否存在实质发现
- 每条发现的类型、严重级别和来源 workflow
- 指向底层证据的路径

即便没有实质发现，也应显式保留 `no-material-findings` 一类状态，而不是省略文件。

### `next_actions.json`

记录：

- 下一步建议是继续自动动作还是人工复核
- 为什么给出这个建议
- 当前建议依赖的目标或阻塞原因

## 证据下钻路径

只有在需要进一步看底层证据时，才进入：

- `steps/<nn>-<workflow>/summary.json`
- `steps/<nn>-<workflow>/manifest.json`
- `steps/<nn>-<workflow>/outputs/*`

顶层文件应该指回这些路径，而不是复制一份原始证据。

## 读取顺序

建议固定使用下面的顺序：

1. `report_result/summary.md`
2. `report_result/report.html`
3. `decision.json`
4. `findings.json`
5. `next_actions.json`
6. 按需进入 `steps/` 目录查看对应 workflow 的明细

结果整理模板见 [../report_renderers/investigation-summary.md](../report_renderers/investigation-summary.md)。
