# C-Eyes Root Sub Agent

这个文档约束顶层 `c-eyes` skill 如何把请求委托给下层 skills。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

## 允许委托到的 skills

### direct workflow skills

- `c-eyes-host-triage`
- `c-eyes-filescan-risk`
- `c-eyes-eventlog-timeline`
- `c-eyes-network-inventory`
- `c-eyes-sbom-inventory`
- `c-eyes-baseline-check`

### investigation skill

- `c-eyes-auto-triage`

## 路由判断

### 走 direct workflow skill

满足下面任一情况，优先走单 workflow skill：

- 用户明确要求“直接扫描/直接导出/直接核查”
- 用户已经明确给出操作对象，例如路径、目录、主机当前状态、最近日志
- 用户要的是一次性结果，不是持续排查链

### 走 `c-eyes-auto-triage`

满足下面任一情况，优先走自动调查链：

- 用户说的是“排查”“调查”“分析告警”“继续深挖”
- 用户目标本身需要多步推进
- 当前 direct workflow 结果不足以回答问题，且后续动作已经落在支持的调查目标内

## 不允许的行为

1. 不要在顶层 skill 里自己拼 `c-eyes` 原始命令。
2. 不要在顶层 skill 里自由组合新的 workflow 链。
3. 不要一次请求里默认并行启动多个 direct workflow skills。
4. 不要把 direct workflow 的单次扫描误说成完整自动调查。

## 推荐读取顺序

如果委托给 direct workflow skill：

1. 先读 `report_result/report.html`
2. 再读 `report_result/summary.md`
3. 需要筛选和导出时再读 `report_result/report.xlsx`
3. 需要下钻时再看 `summary.json`、`manifest.json` 和 `outputs/`

如果委托给 `c-eyes-auto-triage`：

1. 先读 `report_result/report.html`
2. 再读 `report_result/summary.md`
3. 需要筛选和导出时再读 `report_result/report.xlsx`
3. 需要结构化上下文时再读 `decision.json`、`findings.json`、`next_actions.json`
4. 需要证据时再下钻 `steps/`

## 阻塞条件

- 用户目标无法判断是单次操作还是调查链
- direct workflow 缺少关键输入，例如 `target-path`
- auto-triage 目标不在支持集合内

遇到这些情况，先收紧问题或选择最小可执行动作，不要即兴扩展。
