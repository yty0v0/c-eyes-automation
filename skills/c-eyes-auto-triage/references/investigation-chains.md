# 调查链定义

这个文档只描述固定调查链本身，不再承载目标映射、输出契约和完整停止规则。相关内容分别见：

- 目标与输入：[goal-inputs.md](goal-inputs.md)
- 停止规则：[stop-rules.md](stop-rules.md)
- 输出契约：[output-contract.md](output-contract.md)

## 固定调查链

### `host-investigation`

适用的固定步骤：

1. `host-triage`
2. `eventlog-timeline`
3. `filescan-risk`

步骤说明：

- `host-triage`：先拿主机层面的整体状态和初始风险线索
- `eventlog-timeline`：在需要补上下文时读取时间线
- `filescan-risk`：仅在已有可疑路径或确实需要继续下钻文件面时使用

### `file-alert-investigation`

适用的固定步骤：

1. `filescan-risk`
2. `sbom-inventory`

步骤说明：

- `filescan-risk`：围绕可疑文件或目录做风险扫描
- `sbom-inventory`：补充组件和依赖视角，帮助判断影响面

### `network-investigation`

适用的固定步骤：

1. `network-inventory`
2. `host-triage`

步骤说明：

- `network-inventory`：先看内网资产、可见段和扫描视角
- `host-triage`：只有在网络结果不足以回答问题时，再补主机侧排查

### `baseline-investigation`

适用的固定步骤：

1. `baseline-check`
2. `eventlog-timeline`

步骤说明：

- `baseline-check`：先输出基线偏差或配置风险
- `eventlog-timeline`：在需要结合近期事件确认影响时再补时间线

## 步骤推进顺序

每完成一步都遵守以下顺序：

1. 读取该步 `summary.json`
2. 读取该步 `manifest.json`
3. 记录该步状态、输出路径和阻塞条件
4. 再决定继续、停止或转人工复核

默认不并行执行多条调查链，也不并行启动多个无关 workflow。
