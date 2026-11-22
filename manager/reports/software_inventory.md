# 软件与文件清单

分析日期：2026-11-04。**已验证**表示本地文件、PE 解析或 Windows 签名检查的结果；文件名所暗示的用途另标为分类，不等于运行验证。样本仅本地保留，不提交第三方二进制。

## 官方获取与样本身份

| 项目 | 实际证据 |
|---|---|
| 官方入口 | [Accessport Manager](https://www.cobbtuning.com/products/accessport-manager/) 的 Windows 下载按钮 |
| 下载 URL | `https://s3.us-west-2.amazonaws.com/software.cobbtuning.com/Update/AccessportManager/3.2.0/APManagerSetup.exe` |
| 版本 | **已验证**：`APManager.exe` 的 PE 版本资源 `ProductVersion=3.2.0`、`FileVersion=3,2,0`；不是仅从 URL 推断 |
| 安装包 | `samples/downloads/APManagerSetup.exe`，**22,494,736 字节**；NSIS 包，PE I386/x86 |
| 安装包 SHA-256 | `33e5e1182d0ef770142af45380ec4d8202301d642c05f6a2289f2b0909aeaa19` |
| 主程序 | `samples/extracted/manager/APManager.exe`，**9,040,896 字节**；PE I386/x86 |
| 主程序 SHA-256 | `6c4361ed96f75951185a7dfb9d4376234a4a7d594bcc2f28a0f29fa6640c404f` |
| 对象修改时间 | HTTP `Last-Modified: Tue, 14 Jul 2026 14:31:33 GMT`；见 [installer_headers.json](../analysis/sources/installer_headers.json) |
| 发布日期 | **未知**：Last-Modified 是下载对象修改时间，不能当作官方发布日期；安装包 PE 时间戳 2018-12-15 也不能表示 Manager 3.2.0 发布时间 |
| 签名 | **已验证**：安装包 Authenticode `Valid`，签名主体 `COBB Tuning Products, LLC`，带 DigiCert 时间戳签名者；主程序内嵌签名检查 `NotSigned` |

已重新计算安装包与主程序哈希，与原始扫描记录一致。扫描记录生成于 `2026-11-03T18:03:58.481397+00:00`。归档保留 [样本清单](../samples_manifest.json) 和 [逐文件哈希表](inventory_generated.md)。

## 提取范围与结构

**已验证**：Bandizip 控制台 `bz 7.27(Beta,x64)` 识别外层及 `APDriverInstall.exe` 为 NSIS；外层列出 **10 个成员**，驱动包列出 **22 个成员**。见 [Manager 包列表](../analysis/sources/manager_archive_listing.txt) 和 [驱动包列表](../analysis/sources/driver_archive_listing.txt)。列表的 `Size=-1` 是该归档列举输出，不能用于实际文件大小；下表使用提取后扫描字节数。

样本树合计 **33 个文件路径**：1 个下载包 + 10 个 Manager 提取成员 + 22 个驱动包提取成员；其中 `APDriverInstall.exe` 本身仍保留，因此这是递归提取清单，不是系统安装后的文件布局。PE 解析共 **22 个**：19 个 x86、3 个 AMD64；另 11 个为 INF/CAT/INI/BMP/HTML 等非 PE。去掉下载包后，32 个提取文件中为 18 个 x86、3 个 AMD64、11 个非 PE。主应用为 x86，AMD64 文件是驱动安装/协同安装器，不能把整个产品说成 x64。

下表路径均相对 `samples/`；x86/x64 来自 PE machine 字段，`—` 表示无 PE 元数据。

| 路径 | 字节 | 架构 | 分类 |
|---|---:|---|---|
| downloads/APManagerSetup.exe | 22494736 | x86 | 官方外层安装包 |
| extracted/manager/APManager.exe | 9040896 | x86 | Manager 主应用 |
| extracted/manager/APDriverInstall.exe | 4953578 | x86 | 嵌套 NSIS 驱动安装包 |
| extracted/manager/VC_redist.x86.exe | 14327344 | x86 | Microsoft VC++ 运行库安装包 |
| extracted/manager/EULA_APM.htm | 21475 | — | 许可文本资源 |
| extracted/manager/uninst.exe | 52407 | x86 | NSIS 提取生成的卸载器候选，未运行 |
| extracted/manager/$PLUGINSDIR/InstallOptions.dll | 14848 | x86 | NSIS 安装 UI 插件 |
| extracted/manager/$PLUGINSDIR/System.dll | 11776 | x86 | NSIS 安装插件 |
| extracted/manager/$PLUGINSDIR/nsExec.dll | 6656 | x86 | NSIS 命令执行插件 |
| extracted/manager/$PLUGINSDIR/ioSpecial.ini | 211 | — | 安装 UI 配置 |
| extracted/manager/$PLUGINSDIR/modern-wizard.bmp | 26494 | — | 安装向导图片 |
| extracted/drivers/accessport.inf | 2471 | — | WinUSB 设备安装配置 |
| extracted/drivers/accessport64.cat | 8731 | — | 驱动目录签名文件 |
| extracted/drivers/accessportx86.cat | 8731 | — | 驱动目录签名文件 |
| extracted/drivers/AP_20.inf | 4021 | — | 旧 libusb 设备安装配置 |
| extracted/drivers/AP_20.cat | 165 | — | 目录候选，签名检查 UnknownError |
| extracted/drivers/AP_20_x64.cat | 165 | — | 目录候选，签名检查 UnknownError |
| extracted/drivers/Cobb_OBDFTDI.INF | 1844 | — | 旧 FTDI 设备安装配置 |
| extracted/drivers/driverinstaller.exe | 118784 | x86 | 驱动安装辅助程序 |
| extracted/drivers/driverinstaller64.exe | 414720 | x64 | 驱动安装辅助程序 |
| extracted/drivers/FTBUSUI.dll | 106496 | x86 | FTDI 驱动 UI 组件 |
| extracted/drivers/FTD2XX.dll | 176128 | x86 | FTDI 用户态库 |
| extracted/drivers/ftdibus.sys | 57536 | x86 | FTDI 内核驱动 |
| extracted/drivers/libusb0.dll | 41984 | x86 | libusb 用户态库 |
| extracted/drivers/libusb0.sys | 28160 | x86 | libusb 内核驱动 |
| extracted/drivers/i386/WdfCoInstaller01005.dll | 1419232 | x86 | WDF 协同安装器 |
| extracted/drivers/i386/WinUSBCoInstaller.dll | 581192 | x86 | WinUSB 协同安装器 |
| extracted/drivers/amd64/WdfCoInstaller01005.dll | 1919968 | x64 | WDF 协同安装器 |
| extracted/drivers/amd64/WinUSBCoInstaller.dll | 708168 | x64 | WinUSB 协同安装器 |
| extracted/drivers/uninst.exe | 49680 | x86 | NSIS 提取生成的卸载器候选，未运行 |
| extracted/drivers/$PLUGINSDIR/nsDialogs.dll | 9728 | x86 | NSIS 对话框插件 |
| extracted/drivers/$PLUGINSDIR/System.dll | 11264 | x86 | NSIS 安装插件 |
| extracted/drivers/$PLUGINSDIR/modern-wizard.bmp | 26494 | — | 安装向导图片 |

两个 `uninst.exe` 均被 pefile 成功解析为 PE，扫描无 warnings/errors；但这只证明提取产物可解析，不证明它等同实际安装时生成的卸载器或可用。特别是 Manager 的该产物包含 certificate table 数据，但 Windows 仍报告 NotSigned，不能复制外层签名结论到该产物。

## 签名与模块边界

**已验证**：[authenticode_all.json](../analysis/pe_metadata/authenticode_all.json) 检查 26 个 PE/CAT 文件：**9 个 Valid、15 个 NotSigned、2 个 UnknownError**。Valid 包括外层安装包、两个 accessport CAT、`ftdibus.sys`、四个 Microsoft WDF/WinUSB 协同安装器及 `VC_redist.x86.exe`。未签名的提取成员并不自动表示篡改，外层可信签名与内部成员内嵌签名是不同检查；本次未执行驱动目录对每个成员的覆盖验证。

`AP_20.cat` 与 `AP_20_x64.cat` 均为 165 字节且哈希相同，Windows 报「信任提供程序不认识或不支持指定格式」。**未知**：原因是旧格式、占位内容还是其他情况，不能把 UnknownError 改写为签名有效或恶意。`Cobb_OBDFTDI.INF` 引用 `ftdibus.cat`，该名称未出现在本轮 32 个提取成员中；这不是安装失败的实测结论。

**已验证（导入表）**：主程序链接 Windows 网络/加密、界面、SetupAPI 与 VC++ 运行库；FTDI、libusb 文件位于嵌套驱动包。本轮主程序静态导入表没有直接链接提取出的 `FTD2XX.dll`/`libusb0.dll`。**未知**：是否动态加载，以及针对哪个 AP 世代实际启用；必须结合调用与反编译证据。安装插件、VC 运行库安装包和驱动安装辅助程序不能算作 Manager 核心刷写模块。

本轮清单未包含单独 ECU/TCU 固件或 `.ptm`/`.ptp` 样本；这是当前已提取范围的观察，不证明应用或网络资源中没有相关内容。未运行安装器、卸载器或驱动，未验证系统安装、USB 连接或硬件兼容性。
