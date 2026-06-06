---
name: c-eyes-network-inventory
description: 直接执行 C-Eyes `network-inventory` workflow 的独立 skill。用于内网资产盘点和网络可见性检查。
---

# C-Eyes Network Inventory

这个 skill 只执行固定的 `network-inventory` workflow。

## 最高优先级安全约束

**必须严格保证不对扫描目标进行任何增删改查的操作。**

只允许执行只读安全扫描、证据采集、结果归档和本地结果分析；禁止登录目标业务系统、调用目标管理接口、写入目标文件、删除目标文件、修改目标配置或执行任何处置动作。

## 适用场景

- 查看内网资产范围
- 需要网络可见性盘点
- 需要确认是否还要继续做主机排查

## 运行入口

- Windows：`scripts/run-network-inventory-windows.ps1`
- Linux：`scripts/run-network-inventory-linux.sh`

## 需要的输入

- 必需：`workspace`
- 可选：`reachable-segments`
- 可选：`dist-root`
- 可选：`dry-run`

详细输入见 [references/inputs.md](references/inputs.md)。

## 执行规则

1. 固定执行 `network-inventory`。
2. 只有用户明确需要时才加 `reachable-segments`。
3. 不在这个 skill 内自动切换到主机调查链。
