# 配置说明

runner 按下面顺序解析运行时来源：

1. 包装脚本参数，例如 `--dist-root`
2. 环境变量：
   - `C_EYES_DIST_ROOT`
3. JSON 配置文件字段
4. 仓库默认 `runtime/` 目录

如果你使用当前导出的 `c-eyes-automation/` 仓库，默认会把 `runtime/` 当成当前平台 runtime 的下载目录。缺少目标二进制时，runner 会自动下载对应的 `dist-*-public.zip` 并解压到这里。

如果你要显式覆盖运行时目标，可以通过 `--config` 传入下面这种 JSON：

```json
{
  "dist_root": ".\\c-eyes-automation\\runtime",
  "release_repo": "m-sec-org/c-eyes",
  "release_tag": "v1.6",
  "cache_dir": ".\\c-eyes-automation\\runtime\\_downloads",
  "runtime_targets": {
    "windows-amd64": {
      "bundle_dir": "dist-windows-amd64-public",
      "binary": "c-eyes.exe"
    },
    "linux-amd64": {
      "bundle_dir": "dist-linux-amd64-public",
      "binary": "c-eyes"
    },
    "linux-arm64": {
      "bundle_dir": "dist-linux-arm64-public",
      "binary": "c-eyes"
    }
  }
}
```

说明：

- `dist_root` 是本地运行时目录，也是默认自动下载落地目录
- `release_repo` 默认是 `m-sec-org/c-eyes`
- 不传 `release_tag` 时，默认取 latest release
- `cache_dir` 用于缓存下载到的 zip 包
- `bundle_dir` 在本地模式和自动下载模式下都相对 `dist_root`
- runner 会先把解析到的公共运行时暂存到工作区，再从工作区执行
- `dist_root` 下已下载或已存在的原始包目录按只读输入看待
- 下载阶段默认遵循标准 `HTTP_PROXY` / `HTTPS_PROXY` 环境变量
