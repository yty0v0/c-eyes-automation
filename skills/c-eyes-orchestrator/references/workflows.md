# C-Eyes Orchestrator 工作流

## host-triage

- 用途：主机侧全量扫描，并结合风险分析
- 权限预期：通常需要提升权限
- 包装脚本输入：
  - `workspace`
  - 可选 `dist-root`
  - 可选 `risk-mode`，默认 `smart`
- 命令模板：
  - `c-eyes -o <workspace>/outputs/host-triage/host-triage.json -r --risk-mode <mode> hostscan --all`

## filescan-risk

- 用途：按路径扫描文件，并结合风险分析
- 权限预期：通常普通用户即可
- 包装脚本输入：
  - `workspace`
  - 可选 `dist-root`
  - `target-path`
  - 可选 `risk-mode`，默认 `smart`
- 命令模板：
  - `c-eyes -o <workspace>/outputs/filescan-risk/filescan-risk.json -r --risk-mode <mode> filescan --scan-mode path <target-path> --smart`

## eventlog-timeline

- 用途：导出最近事件日志，用于排查时间线
- 权限预期：取决于主机策略
- 包装脚本输入：
  - `workspace`
  - 可选 `dist-root`
  - 可选 `time-window`，默认 `24h`
- 命令模板：
  - `c-eyes -o <workspace>/outputs/eventlog-timeline/eventlog-timeline.json eventlog -last <time-window>`

## network-inventory

- 用途：扫描内网资产信息
- 权限预期：建议提升权限
- 包装脚本输入：
  - `workspace`
  - 可选 `dist-root`
  - 可选 `reachable-segments`
- 命令模板：
  - `c-eyes -o <workspace>/outputs/network-inventory/network-inventory.json netscan`
  - 需要时追加 `-reachableSegments`

## sbom-inventory

- 用途：采集目标路径的软件物料清单
- 权限预期：通常普通用户即可
- 包装脚本输入：
  - `workspace`
  - 可选 `dist-root`
  - `target-path`
- 命令模板：
  - `c-eyes -o <workspace>/outputs/sbom-inventory/sbom-inventory.json sbom --path <target-path>`

## baseline-check

- 用途：执行基线检查
- 权限预期：通常需要提升权限
- 包装脚本输入：
  - `workspace`
  - 可选 `dist-root`
  - 可选 `baseline-level`，默认 `1`
- 命令模板：
  - `c-eyes -o <workspace>/outputs/baseline-check/baseline-check.json benchmark --baseline-level <level>`

## 工作区输出

每个 workflow 都会写出：

- `run.json`：归一化后的请求参数
- `manifest.json`：选中的运行时目标、release 或本地来源细节、preflight、命令、日志和运行时状态文件
- `summary.json`：高层状态和输出指针
- `runtime/<platform-arch>/`：暂存后的公共运行时和运行时数据库文件
- `raw/`：stdout/stderr 日志
- `outputs/<workflow>/`：workflow 结果文件
