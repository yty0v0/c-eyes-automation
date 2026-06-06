# 停止规则

这个文档只回答“什么时候停”，不重复完整链路定义。

## 通用停止规则

在任何目标下，出现以下情况都要停止自动推进：

1. 用户目标不在受支持集合内。
2. 当前步骤缺少必需输入。
3. 某一步返回 `blocked`。
4. 某一步返回 `failed`。
5. 当前结果已经足够回答用户问题。

## 按目标区分的停止规则

### `host-investigation`

- `host-triage` 已经给出足够明确的结论时可提前停止。
- 如果后续 `filescan-risk` 需要 `target-path` 但没有可用目标路径，记录阻塞原因后停止。

### `file-alert-investigation`

- 缺少 `target-path` 时直接阻塞。
- `filescan-risk` 没有发现可继续下钻的对象时可提前停止，不必强行进入后续富化。

### `network-investigation`

- 网络盘点步骤权限不足时直接阻塞。
- 如果 `network-inventory` 已经足够回答用户问题，可不继续进入 `host-triage`。

### `baseline-investigation`

- `baseline-check` 已经形成明确结论时可提前停止。
- 只有在需要近期事件上下文时才继续 `eventlog-timeline`。

## 不允许的推进方式

- 不要因为“可能还有别的发现”就把链上剩余步骤全部跑完。
- 不要把不受支持的用户目标硬塞进最接近的链里。
- 不要遇到阻塞后偷偷改成别的 workflow 继续跑。

固定链本身见 [investigation-chains.md](investigation-chains.md)。
