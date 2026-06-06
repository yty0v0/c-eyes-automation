---
name: c-eyes-sbom-inventory
description: 直接执行 C-Eyes `sbom-inventory` workflow 的独立 skill。用于目录组件、依赖和制品清单采集。
---

# C-Eyes SBOM Inventory

这个 skill 只执行固定的 `sbom-inventory` workflow。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

## 适用场景

- 需要看目标目录的软件组成
- 需要围绕样本落点补组件视图
- 需要生成依赖和制品清单

## 运行入口

- Windows：`scripts/run-sbom-inventory-windows.ps1`
- Linux：`scripts/run-sbom-inventory-linux.sh`

## 需要的输入

- 必需：`workspace`
- 必需：`target-path`
- 可选：`dist-root`
- 可选：`dry-run`

详细输入见 [references/inputs.md](references/inputs.md)。

## 执行规则

1. 固定执行 `sbom-inventory`。
2. 缺少 `target-path` 时不要假设默认路径。
3. 不在这个 skill 内自动补文件风险扫描。
