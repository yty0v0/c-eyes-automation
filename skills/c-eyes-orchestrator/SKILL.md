---
name: c-eyes-orchestrator
description: 通过隔离工作区和结构化清单编排 C-Eyes 公共运行时，支持主机、文件、事件日志、网络、SBOM 和基线工作流。适用于在 Windows 或 Linux 上让 Codex 调用 C-Eyes 扫描，而不是手写原始 CLI。
---

# C-Eyes Orchestrator

这个 skill 用来驱动打包后的 `c-eyes` 公共二进制，并通过一组固定工作流完成扫描。不要把 `c-eyes` 当成只靠提示词推理的能力；应优先使用 `scripts/` 下的包装脚本，这样平台选择、运行时下载、运行时暂存、工作区隔离和清单生成才是稳定的。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

## 工作流选择

先确定要跑哪个 workflow：

- `host-triage`：主机全量扫描，并结合风险分析
- `filescan-risk`：按路径做文件扫描，并结合风险分析
- `eventlog-timeline`：导出最近事件日志，便于排查
- `network-inventory`：执行网络资产盘点，可选可达网段信息
- `sbom-inventory`：采集目标路径的 SBOM 信息
- `baseline-check`：执行基线检查模块

需要精确输入约束或命令形态时，查看 [references/workflows.md](references/workflows.md)。

## 执行规则

1. 先判断任务意图，再映射到最合适的 workflow，不要一上来就尝试多个 workflow。
2. 运行时来源按下面顺序解析：
   - 显式传入 `--dist-root`，用于指定本地已有运行时目录，或指定自动下载的落地目录
   - 环境变量和 JSON 配置文件
   - 如果未显式传入，runner 会优先解析仓库默认 `runtime/` 目录作为当前平台运行时下载目录
   - 如果目标二进制缺失，runner 会自动从 GitHub Releases 下载当前平台对应的 `dist-*-public.zip`
3. 优先使用平台包装脚本：
   - Windows：`scripts/run-ceyes-windows.ps1`
   - Linux：`scripts/run-ceyes-linux.sh`
4. 每次运行都要提供独立的 `workspace`。包装脚本会先确保当前平台运行时已经就绪，再复制到 `workspace/runtime/` 后执行，避免把可变运行时文件写回原始包目录。
5. 执行后优先按这个顺序读取结果：
   - `report_result/summary.md`
   - `report_result/report.html`
   - 需要下钻时再读 `summary.json`、`manifest.json` 和 `workspace/outputs/` 下对应 workflow 的输出文件
6. 如果 preflight 报告权限不足、运行时缺失或目标不受支持，要直接返回这个阻塞条件，不要临时拼接替代命令。

## 快速开始

### Windows

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\c-eyes-automation\skills\c-eyes-orchestrator\scripts\run-ceyes-windows.ps1 `
  -Workflow filescan-risk `
  -Workspace .\workspace\ceyes-filescan `
  -TargetPath .\target\webroot
```

### Linux

```bash
bash ./c-eyes-automation/skills/c-eyes-orchestrator/scripts/run-ceyes-linux.sh \
  --workflow filescan-risk \
  --workspace ./workspace/ceyes-filescan \
  --target-path /srv/www
```

### 预下载当前平台 runtime

如果你只想先把当前环境需要的 runtime 下载好，不立刻发起扫描，可以直接运行：

```powershell
python .\c-eyes-automation\skills\c-eyes-orchestrator\scripts\ceyes_runner.py --download-only
```

```bash
python3 ./c-eyes-automation/skills/c-eyes-orchestrator/scripts/ceyes_runner.py --download-only
```

如果目标二进制已经存在，runner 不会重复下载。

如果网络需要经过本地代理，runner 会遵循标准 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量。

### 本地 dist 覆盖

如果你已经有本地 public runtime，仍然可以显式指向本地目录：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\c-eyes-automation\skills\c-eyes-orchestrator\scripts\run-ceyes-windows.ps1 `
  -Workflow host-triage `
  -Workspace .\workspace\ceyes-host `
  -DistRoot .\c-eyes-automation\runtime
```

## 常见调用范式

### 1. 先做主机排查

适合“先看整机是否有异常”的场景。优先选择 `host-triage`，结果出来后先读 `report_result/summary.md`，再按需下钻 `manifest.json` 和输出路径。

### 2. 已知目录，直接扫文件

适合用户已经给了路径，或者怀疑某个目录下有恶意文件的场景。优先选择 `filescan-risk`，并明确传入 `target-path`。

### 3. 用户要看时间线

适合需要回溯最近主机活动的场景。优先选择 `eventlog-timeline`，必要时再补 `time-window`，不要默认扩大时间范围。

### 4. 用户要看内网资产

适合资产盘点、横向可见性确认这类场景。优先选择 `network-inventory`；只有在用户明确需要可达网段信息时，再加 `reachable-segments`。

### 5. 用户要看软件组成

适合排查某个目录里有哪些组件、依赖或制品。优先选择 `sbom-inventory`，并明确传入 `target-path`。

### 6. 用户要做基线检查

适合安全基线核查。优先选择 `baseline-check`，仅在用户指定时调整 `baseline-level`。

### 7. 不确定先跑哪个 workflow

先根据用户目标选最贴近的一个 workflow，不要并行乱跑。只有当当前结果不足以回答问题时，再基于已有 `report_result/`、`summary.json` 和 `manifest.json` 决定下一步。

## 需要收集的参数

只收集当前 workflow 真正需要的参数：

- `workspace`：每次运行都必需
- `dist-root`：可选，本地运行时目录或自动下载落地目录
- `target-path`：`filescan-risk` 和 `sbom-inventory` 必需
- `time-window`：`eventlog-timeline` 可选，默认 `24h`
- `risk-mode`：带风险分析的 workflow 可选，默认 `smart`
- `baseline-level`：`baseline-check` 可选，默认 `1`
- `reachable-segments`：`network-inventory` 可选
- `dry-run`：适合做预检查，或在非 Linux 主机上验证 Linux 参数路径
- `download-only`：只下载当前平台 runtime，不执行 workflow

配置文件格式见 [references/configuration.md](references/configuration.md)。

## 预期输出

每次运行都会写出这些文件：

- `run.json`：归一化后的请求参数
- `report_result/`：最终人类可读报告目录，包含 `report.json`、`summary.md` 和 `report.html`
- `manifest.json`：preflight、运行时目标、执行命令、日志和状态
- `summary.json`：给后续推理优先消费的摘要
- `runtime/`：暂存后的公共运行时和运行时数据库文件
- `raw/`：每条命令的 stdout/stderr 日志
- `outputs/`：workflow 结果文件

需要配置模板时，使用 [assets/runtime-targets.example.json](assets/runtime-targets.example.json)。
