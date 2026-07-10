# kphelper 新功能路线图

本路线图基于 2026 年 7 月完成的可靠性、QEMU 配置解析和报告模型重构。实施顺序优先考虑内核题环境中的稳定性、可诊断性和自动化能力。

## 已完成的基础重构

- Guest 上传流程统一使用随机 marker 命令协议，不再依赖每个上传步骤匹配固定提示符。
- initramfs 解包缓存加入源路径、文件大小和纳秒修改时间校验。
- 禁止覆盖没有 kphelper marker 的非空解包目录。
- initramfs 解包和打包启用管道失败传播。
- 新增集中式 QEMU 启动参数解析模型，避免把其他 shell 命令的参数误判为 QEMU 配置。
- 新增结构化 `Finding` 模型，运行时探测和报告渲染可逐步脱离松散字典。

## 第一阶段：快速收益

### `kphelper doctor`

统一检查运行环境和挑战目录，包括：

- Python、pwntools、QEMU、GDB、tmux。
- musl-gcc、gcc、nm、cpio 及常见压缩工具。
- `run.sh`、`vmlinux`、initramfs、`exp.c` 和 `exp`。
- Guest 串口配置、GDB 端口冲突和无法静态解析的 QEMU 参数。

支持普通文本和 JSON 输出，并给出可执行的修复建议。

### 统一 `--json`

为 `checksec`、运行时探测、doctor 和 pack 结果提供稳定 JSON schema。内部统一使用 `Finding`，包含 `status`、`value`、`detail` 和 `source`。

### `--dry-run`

优先覆盖具有副作用的命令：

- `pack`：展示解包、注入、输出和 `run.sh` 修改计划。
- `debug`：展示临时启动脚本和 GDB 命令。
- 上传：展示编码大小、目标路径和所需 Guest 工具。

### 上传能力协商

启动上传前探测 Guest 工具，依次选择：

1. gzip + base64。
2. base64。
3. xxd。
4. Python 或 Perl。
5. 纯 shell 小文件回退方案。

## 第二阶段：开发与调试增强

### 项目配置文件

支持 `.kphelper.toml`，保存常用配置：

- QEMU 启动脚本。
- vmlinux 和 initramfs 路径。
- exploit 源文件与输出文件。
- Guest 临时目录。
- GDB 地址和端口。
- 默认超时及符号列表。

命令行参数始终拥有最高优先级。

### 自动加载内核模块符号

读取 Guest 中模块的 `.text`、`.data` 和 `.bss` section 地址，自动构造 `add-symbol-file`，并支持模块延迟加载后的重试。

### GDB 初始化脚本

新增 GDB 配置生成能力，包含：

- 目标架构与远程连接。
- KASLR slide。
- 内核及模块符号。
- 常用断点和用户态返回辅助命令。
- 可选的 pwndbg、GEF 兼容设置。

### Rootfs 独立命令组

提供 `rootfs extract`、`rootfs list`、`rootfs inject` 和 `rootfs repack`，复用安全目录和缓存机制，不再把所有 rootfs 操作绑定到 `pack`。

## 第三阶段：分析能力扩展

### 可扩展检查规则

建立静态和运行时规则接口，规则声明唯一 ID、风险级别、证据来源和修复建议。内置规则覆盖：

- 内核启动安全参数。
- sysctl 泄漏面。
- 设备节点权限。
- setuid、capability 和可写启动脚本。
- 模块加载及模块 section 地址泄漏。

### Challenge snapshot

将一次挑战分析导出为 JSON 或 Markdown：

- QEMU、内核版本和 cmdline。
- rootfs、启动脚本、用户和设备节点。
- 安全特性及运行时验证结果。
- 内核符号、模块地址和 KASLR slide。
- 编译器及工具链版本。

### 攻击面辅助分析

结合 initramfs 静态扫描和 Guest 运行时信息，识别字符设备、ioctl 接口线索、模块、权限边界和常见利用条件。输出证据和建议检查项，不自动生成未经验证的完整 exploit。

## 第四阶段：工作区与生命周期管理

### 统一工作区

使用 `.kphelper/` 保存缓存、生成脚本、报告和日志，避免临时文件散落：

```text
.kphelper/
├── cache/
├── generated/
├── reports/
└── logs/
```

### QEMU 生命周期管理

提供 `start`、`status`、`stop`、`console` 和 `gdb`。实现前必须完成 PID 校验、端口管理、日志轮转、异常退出清理和多工作区隔离。

### 插件机制

内置命令使用显式注册；第三方命令和检查规则使用 Python entry points。单个可选插件加载失败时不影响基础 CLI 和帮助信息。

## 工程质量目标

- 将测试按 guest、upload、qemu、cpio、pack、checksec、symbols 和 CLI 拆分。
- 对 marker 协议、超时、EOF、管道失败和目录安全增加异常路径测试。
- 建立 Linux CI，覆盖项目声明支持的 Python 版本。
- 加入 Ruff、覆盖率阈值和构建安装验证。
- 在下一次大版本前评估将最低 Python 版本提升到 3.10 或 3.11。
