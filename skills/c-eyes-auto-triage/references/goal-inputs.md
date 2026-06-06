# 调查目标与输入

这个文档只负责“用户问题如何映射到目标，以及每个目标需要什么输入”，不描述完整步骤链和输出解释。

## 支持的调查目标

### `host-investigation`

适用场景：

- 用户要求排查整机异常
- 用户要求看主机最近是否有异常事件
- 用户要做主机侧快速体检

常用输入：

- 必需：`workspace`
- 可选：`time-window`
- 可选：`target-path`（只有链路走到 `filescan-risk` 时才会真正使用）

### `file-alert-investigation`

适用场景：

- 用户给出可疑文件路径
- 用户给出可疑目录落点
- 用户要围绕文件告警继续深挖

常用输入：

- 必需：`workspace`
- 必需：`target-path`
- 可选：`risk-mode`

### `network-investigation`

适用场景：

- 用户要看内网资产可见性
- 用户怀疑存在横向扩散面
- 用户要先看网络盘点，再决定是否做主机排查

常用输入：

- 必需：`workspace`
- 可选：`reachable-segments`
- 可选：`time-window`

### `baseline-investigation`

适用场景：

- 用户要做安全基线核查
- 用户要看主机配置偏差
- 用户要确认基线问题是否需要结合近期日志复核

常用输入：

- 必需：`workspace`
- 可选：`baseline-level`
- 可选：`time-window`

## 映射规则

1. 优先按用户目标选择一个固定调查目标。
2. 不要因为某个目标“也许有帮助”就并行选择多个目标。
3. 如果问题无法归到受支持目标，直接返回阻塞。
4. 如果目标本身成立，但缺少关键输入，记录阻塞原因而不是临时改链。

固定链定义见 [investigation-chains.md](investigation-chains.md)。
