---
name: c-eyes
description: C-Eyes 的统一入口 skill。用于先判断请求属于单次扫描操作还是多步骤 EDR 调查，再路由到合适的下层 skill。
---

# C-Eyes

这个 skill 是整个 C-Eyes 技能集的统一入口。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

它自己不直接运行 `c-eyes` 二进制，也不自己拼接底层命令。它的职责是先判断用户请求属于哪一类，再把请求交给正确的下层 skill。

## 先做哪一步

先判断用户请求属于下面哪一类：

1. 单次扫描或单次导出操作
2. 多步骤调查或告警排查

如果是单次操作，路由到 direct workflow skills。

如果是多步骤调查，路由到 `$c-eyes-auto-triage`。

## direct workflow skills

下面这些 skill 对应固定 workflow：

- `$c-eyes-host-triage`
- `$c-eyes-filescan-risk`
- `$c-eyes-eventlog-timeline`
- `$c-eyes-network-inventory`
- `$c-eyes-sbom-inventory`
- `$c-eyes-baseline-check`

## 调查链 skill

下面这个 skill 负责多步骤调查：

- `$c-eyes-auto-triage`

## 路由规则

- 用户说“帮我直接扫一下这个目录/文件”：优先去 `$c-eyes-filescan-risk`
- 用户说“帮我看这台机器有没有异常”：如果只是做一次快速体检，去 `$c-eyes-host-triage`；如果是明确的排查/调查，去 `$c-eyes-auto-triage`
- 用户说“帮我导出最近日志时间线”：去 `$c-eyes-eventlog-timeline`
- 用户说“帮我盘一下内网资产”：去 `$c-eyes-network-inventory`
- 用户说“帮我看这个目录的软件组成/SBOM”：去 `$c-eyes-sbom-inventory`
- 用户说“帮我做基线核查”：如果只是单次核查，去 `$c-eyes-baseline-check`；如果是带调查语义的持续排查，去 `$c-eyes-auto-triage`

完整映射见 [references/routing-map.md](references/routing-map.md)。

## 委托边界

1. 不要在这个 skill 里直接执行原始 `c-eyes` CLI。
2. 不要在这个 skill 里临时发明新的 workflow 链。
3. 不要把 direct workflow skill 和 auto-triage 混在一个请求里同时乱跑。
4. 如果用户目标不清楚，先按最小动作选择一个 direct workflow；只有明显需要链式排查时才进 `auto-triage`。

更严格的委托规则见 [sub_agent.md](sub_agent.md)。

## 常见用法

- “帮我直接扫描这个可疑目录” -> `$c-eyes-filescan-risk`
- “帮我排查这台主机最近的异常活动” -> `$c-eyes-auto-triage`
- “帮我先看这台主机整体情况” -> `$c-eyes-host-triage`
- “帮我导出最近 24 小时事件日志” -> `$c-eyes-eventlog-timeline`

## 结果读取

无论路由到哪种下层 skill，执行完成后都先查看对应任务工作目录下的 `report_result/`：

1. `report_result/summary.md`
2. `report_result/report.html`
3. 只有需要证据下钻时，再回到原始 JSON 和 `outputs/`

## 资源

- 路由映射：见 [references/routing-map.md](references/routing-map.md)
- 请求示例：见 [references/request-examples.md](references/request-examples.md)
- 多步骤调查：见 `$c-eyes-auto-triage`
- 单 workflow 执行：见对应 direct workflow skill
