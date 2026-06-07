# c-eyes-automation

## c-eyes-automation 简介
`c-eyes-automation` 是 c-eyes 基于 AI Agent 架构搭建的自动化 EDR 扫描工具，采用多 Agent 协同执行方式，支持主机风险分析，文件风险分析，内网主机探测，sbom物理清单采集，日志信息获取，安全基线检查等多个功能，皆可通过 AI 直接执行。

c-eyes 地址：https://github.com/m-sec-org/c-eyes

## 说明
建议使用 AI 智能体加载本技能，并配合本技能包含的检测脚本使用，推荐编程类智能体：Qoder、Trae、Claude Code、Codex 等

注意：仅用于授权环境

## 安装和配置

先下载当前项目源码，然后通过 Agent 打开当前项目。第一次运行时，底层执行器会自动下载当前环境对应的 public runtime 到 `runtime/`。为了防止网络问题，也可以自己先手动下载；如果目标二进制已经存在，不会重复下载。

Windows 手动下载脚本:
```powershell
python .\skills\c-eyes-orchestrator\scripts\ceyes_runner.py --download-only
```
Linux 手动下载脚本:
```bash
python3 ./skills/c-eyes-orchestrator/scripts/ceyes_runner.py --download-only
```

如果需要走本地代理，可以先设置：

```powershell
$env:HTTP_PROXY = "http://127.0.0.1:7890"
$env:HTTPS_PROXY = "http://127.0.0.1:7890"
```

```bash
export HTTP_PROXY="http://127.0.0.1:7890"
export HTTPS_PROXY="http://127.0.0.1:7890"
```

默认下载到：

```text
c-eyes-automation/
  runtime/
    dist-windows-amd64-public/    # Windows 时下载
    dist-linux-amd64-public/      # Linux amd64 时下载
    dist-linux-arm64-public/      # Linux arm64 时下载
```

自建 workspace 文件夹存扫描结果，建议每次任务用独立目录，避免结果覆盖：

```text
workspace/
  host-triage/
    report_result/
  filescan-risk/
    report_result/
  auto-file-investigation/
    report_result/
```

所有结果都会写入你指定的 `workspace/<task>/` 目录。  
最终可读报告固定在：

```text
workspace/<task>/report_result/
```

其中至少包含：

- `report.json`
- `summary.md`
- `report.html`
- `report.xlsx`

## 使用说明

### 建议

建议所有提示词都以 `使用 c-eyes-automation 来...` 开头。

为了让 LLM 更稳定识别，提示词里尽量同时写清：

- 操作系统：`Windows` 或 `Linux`
- `workspace` 输出的结果路径
- `runtime` 脚本路径（首次运行时使用）
- `target-path`、`time-window` 或调查目标

提示词自拟就行，下面是常见的示例，也可以直接使用


### 主机快速排查

适合：快速看当前主机整体是否有明显异常。

```text
使用 c-eyes-automation 来执行主机快速排查。

要求：
- 操作系统：Windows 或 Linux
- workspace：当前目录下的 workspace/host-triage
- runtime：默认自动下载到 .\runtime
- 先做 dry-run，再正式执行
- 执行后优先读取 workspace/host-triage/report_result/report.html，其次再看 summary.md 和 report.xlsx
```

### 可疑文件或目录扫描

适合：已经知道可疑文件、目录或落点路径。

```text
使用 c-eyes-automation 来扫描可疑文件或目录。

要求：
- 操作系统：Windows 或 Linux
- target-path：xxxxx
- workspace：当前目录下的 workspace/filescan-risk
- runtime：默认自动下载到 .\runtime
- 执行后优先读取 workspace/filescan-risk/report_result/report.html，其次再看 summary.md 和 report.xlsx
```

### 事件日志时间线导出

适合：回看最近活动、补时间线。

```text
使用 c-eyes-automation 来导出最近事件日志时间线。

要求：
- 操作系统：Windows 或 Linux
- workspace：当前目录下的 workspace/eventlog-timeline
- runtime：默认自动下载到 .\runtime
- time-window：24h
- 执行后优先读取 workspace/eventlog-timeline/report_result/report.html，其次再看 summary.md 和 report.xlsx
```

### 内网资产盘点

适合：查看网络可见性和内网资产范围。

```text
使用 c-eyes-automation 来执行内网资产盘点。

要求：
- 操作系统：Windows 或 Linux
- workspace：当前目录下的 workspace/network-inventory
- runtime：默认自动下载到 .\runtime
- 只有在我明确要求时才使用 reachable-segments
- 执行后优先读取 workspace/network-inventory/report_result/report.html，其次再看 summary.md 和 report.xlsx
```

### SBOM / 软件组成清单采集

适合：看目录的软件组成、依赖和制品。

```text
使用 c-eyes-automation 来采集目标目录的 SBOM 信息。

要求：
- 操作系统：Windows 或 Linux
- target-path：xxxxx（web-path）
- workspace：当前目录下的 workspace/sbom-inventory
- runtime：默认自动下载到 .\runtime
- 执行后优先读取 workspace/sbom-inventory/report_result/report.html，其次再看 summary.md 和 report.xlsx
```

### 主机安全基线核查

适合：检查基线配置偏差。

```text
使用 c-eyes-automation 来执行主机安全基线核查。

要求：
- 操作系统：Windows 或 Linux
- workspace：当前目录下的 workspace/baseline-check
- runtime：默认自动下载到 .\runtime
- baseline-level：number (可选1/2/3/4 四个级别)
- 执行后优先读取 workspace/baseline-check/report_result/report.html，其次再看 summary.md 和 report.xlsx
```

### 文件告警自动调查

适合：不仅要扫目录，还要自动补 SBOM 和调查结论。

```text
使用 c-eyes-automation 来执行文件告警自动调查。

要求：
- 调查目标：file-alert-investigation
- 操作系统：Windows 或 Linux
- target-path：xxxxxx
- workspace：当前目录下的 workspace/auto-file-investigation
- runtime：默认自动下载到 .\runtime
- 最终优先读取 workspace/auto-file-investigation/report_result/report.html，其次再看 summary.md 和 report.xlsx
```

### 主机异常自动调查

适合：围绕主机异常做多步骤自动排查。

```text
使用 c-eyes-automation 来执行主机异常自动调查。

要求：
- 调查目标：host-investigation
- 操作系统：Windows 或 Linux
- workspace：当前目录下的 workspace/auto-host-investigation
- runtime：默认自动下载到 .\runtime
- 最终优先读取 workspace/auto-host-investigation/report_result/report.html，其次再看 summary.md 和 report.xlsx
```

### 基线异常自动调查

适合：先跑基线，再自动补近期事件上下文。

```text
使用 c-eyes-automation 来执行基线异常自动调查。

要求：
- 调查目标：baseline-investigation
- 操作系统：Windows 或 Linux
- workspace：当前目录下的 workspace/auto-baseline-investigation
- runtime：默认自动下载到 .\runtime
- 最终优先读取 workspace/auto-baseline-investigation/report_result/report.html，其次再看 summary.md 和 report.xlsx
```

## 看结果

所有任务执行完成后，先看对应任务目录下的：

- `report_result/report.html`
- `report_result/summary.md`
- `report_result/report.xlsx`
- `report_result/report.json`

如果还需要下钻，再看下面这些原始结构化文件。

### 单次扫描

单次扫描完成后，优先看：

- `summary.json`
- `manifest.json`
- `outputs/`

### 自动调查

自动调查完成后，优先看：

- `decision.json`
- `findings.json`
- `next_actions.json`
- 需要下钻时再看 `steps/`
