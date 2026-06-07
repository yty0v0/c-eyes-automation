# Investigation Summary Renderer

这个目录不负责执行扫描，只负责帮助后续 agent 或人工把 workspace 结果整理成可读摘要。

## 输入

一个已完成的 `c-eyes-auto-triage` workspace，至少包含：

- `report_result/report.json`
- `report_result/summary.md`
- `report_result/report.html`
- `report_result/report.xlsx`
- `decision.json`
- `findings.json`
- `next_actions.json`

按需再读取：

- `steps/<nn>-<workflow>/summary.json`
- `steps/<nn>-<workflow>/manifest.json`

## 推荐阅读顺序

1. `decision.json`
2. `findings.json`
3. `next_actions.json`
4. 只为关键发现回看对应 step 证据

如果只是人工查看，优先直接打开：

1. `report_result/report.html`
2. `report_result/summary.md`
3. `report_result/report.xlsx`
3. 必要时再回到上述 JSON 和 `steps/`

## 推荐输出结构

### 1. 调查结论

- 本次调查目标是什么
- 选择了哪条固定链
- 链路最终停在什么状态

### 2. 关键发现

- 哪些 workflow 产生了有效发现
- 每条发现的严重级别
- 对应证据路径是什么

如果没有实质发现，要明确写出“未发现实质异常”，不要留空。

### 3. 阻塞或失败信息

- 是否出现 `blocked`
- 是否出现 `failed`
- 缺失了什么输入或权限

### 4. 下一步建议

- 当前建议是继续自动化动作还是转人工复核
- 为什么给出这个建议

## 渲染约束

- 不要覆盖底层 `manifest.json` 或 `summary.json`
- 不要把所有原始证据全文复制到摘要里
- 用顶层结果文件做摘要，用 step 证据做引用
- 如果顶层文件和底层证据冲突，先标记冲突，再指出对应路径
- `report_result/` 是最终展示层，不替代原始 JSON 证据入口
