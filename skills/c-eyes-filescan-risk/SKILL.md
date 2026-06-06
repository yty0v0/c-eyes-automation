---
name: c-eyes-filescan-risk
description: 直接执行 C-Eyes `filescan-risk` workflow 的独立 skill。用于扫描可疑文件、目录和落点路径。
---

# C-Eyes FileScan Risk

这个 skill 只执行固定的 `filescan-risk` workflow。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

## 适用场景

- 用户已经给出可疑文件路径
- 用户已经给出可疑目录
- 需要围绕某个落点先做文件风险扫描

## 运行入口

- Windows：`scripts/run-filescan-risk-windows.ps1`
- Linux：`scripts/run-filescan-risk-linux.sh`

## 需要的输入

- 必需：`workspace`
- 必需：`target-path`
- 可选：`dist-root`
- 可选：`risk-mode`
- 可选：`dry-run`

详细输入见 [references/inputs.md](references/inputs.md)。

## 执行规则

1. 固定执行 `filescan-risk`。
2. 缺少 `target-path` 时直接视为输入不完整。
3. 不在这里自动补 SBOM 或别的 workflow。

## 示例

### Windows

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\c-eyes-automation\skills\c-eyes-filescan-risk\scripts\run-filescan-risk-windows.ps1 `
  -Workspace .\workspace\filescan-risk `
  -TargetPath .\target\webroot `
  -DryRun
```

### Linux

```bash
bash ./c-eyes-automation/skills/c-eyes-filescan-risk/scripts/run-filescan-risk-linux.sh \
  --workspace ./workspace/filescan-risk \
  --target-path /srv/www \
  --dry-run
```
