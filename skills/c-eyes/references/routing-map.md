# 路由映射

这个文档定义顶层 `c-eyes` skill 的路由表。

## 1. 直接走单 workflow skill

### 主机快速体检

请求特征：

- “先看这台机器整体情况”
- “直接扫一下当前主机”
- “做一次主机 triage”

路由到：

- `c-eyes-host-triage`

### 文件或目录风险扫描

请求特征：

- “扫一下这个文件”
- “看这个目录有没有风险”
- “直接扫描这个落点”

路由到：

- `c-eyes-filescan-risk`

### 事件日志时间线

请求特征：

- “导出最近日志”
- “看最近 24 小时事件”
- “拉一份事件时间线”

路由到：

- `c-eyes-eventlog-timeline`

### 内网资产盘点

请求特征：

- “盘一下内网资产”
- “看网络可见性”
- “导出网络盘点结果”

路由到：

- `c-eyes-network-inventory`

### SBOM / 软件组成

请求特征：

- “看这个目录的软件组成”
- “导出 SBOM”
- “看依赖和制品清单”

路由到：

- `c-eyes-sbom-inventory`

### 基线核查

请求特征：

- “做一次基线检查”
- “核查配置偏差”
- “先看安全基线”

路由到：

- `c-eyes-baseline-check`

## 2. 走自动调查链

### 主机异常调查

请求特征：

- “排查这台机器的异常”
- “调查这台主机最近出了什么问题”
- “帮我分析主机告警”

路由到：

- `c-eyes-auto-triage`
- `goal = host-investigation`

### 文件告警调查

请求特征：

- “帮我调查这个可疑目录”
- “继续分析这个文件告警”
- “对这个落点做排查”

路由到：

- `c-eyes-auto-triage`
- `goal = file-alert-investigation`

### 网络调查

请求特征：

- “调查一下内网异常”
- “分析网络侧可见性问题”
- “排查横向范围”

路由到：

- `c-eyes-auto-triage`
- `goal = network-investigation`

### 基线问题调查

请求特征：

- “排查基线异常”
- “分析为什么基线不过”
- “结合上下文调查配置风险”

路由到：

- `c-eyes-auto-triage`
- `goal = baseline-investigation`

## 3. 默认原则

1. 用户明确要“直接做一次操作”时，优先 direct workflow skill。
2. 用户明确要“调查/排查/告警分析/深挖”时，优先 `c-eyes-auto-triage`。
3. 先选最小可执行动作，不要一开始就并行路由到多个 skills。
