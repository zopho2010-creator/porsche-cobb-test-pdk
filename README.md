# Porsche 981 ECU / PDK TCU · Windows 刷写研究

## 项目是什么

这是一个面向 **2014 年 Porsche 981 3.4L** 的 Windows OBD 实验项目。核心目标是研究能否让 Windows 电脑通过 J2534 适配器直接与车辆通信，为 **发动机 ECU（SDI9）和 PDK 变速箱 TCU** 建立完整的刷写流程。

项目从识别车辆与控制器、确认软件版本做起，研究如何在写入前保存原车程序，写入后读回核对，以及出现中断时如何判断状态并尝试还原。这个仓库汇总了开发过程中留下的静态分析、离线工具和模拟验证结果。

## 开发过程中研究了哪些 COBB 功能

COBB Accessport 是本项目的研究参考。官方流程中，Windows 上的 **Accessport Manager** 通过 USB 与 **Accessport 手持设备**通信，负责管理文件和更新设备固件。面向车辆的 ECU 和 PDK 编程由手持设备通过 OBD-II 执行。

| 研究内容 | 已取得的结果 |
| --- | --- |
| Windows 端与 Accessport 的通信 | 使用 REA 和 Ghidra 分析官方 Accessport Manager 3.2.0，整理 USB 驱动、设备识别及相关调用。保留了官方安装包的来源、签名结果、文件清单和哈希。详见 [Manager 静态研究](manager/README.md)和 [USB 通信分析](manager/reports/communication_analysis.md)。 |
| Accessport 固件更新 | 研究版本识别、更新清单与镜像下载，取得 AP-POR-007 的公开设备更新镜像并核对校验值。这些镜像用于 Accessport 手持设备本身。详见 [POR-007 固件下载记录](manager/reports/firmware_download_path.md)。 |
| ECU／PDK 的安装、备份与恢复 | 对照 COBB 的车辆识别、Map 选择、保存原厂还原所需数据、写入及 Recovery Mode，整理 Windows 原型需要验证的环节。项目特别关注能否保存并还原这辆车安装前的原始程序。详见 [COBB 官方资料核对](manager/reports/official_documentation.md)和 [981 原型记录](porsche981/README.md)。 |
| Map 与车型兼容性 | 研究 Map 元数据和公开的车型、ROM 版本资料。官方 981 Map 的实际文件兼容性及 PDK 功能授权流程未验证。详见 [Map 格式研究](manager/reports/map_format_analysis.md)和 [公开 Map 调查](manager/reports/public_map_availability.md)。 |

## 对照 COBB 流程，Windows 原型目前实现了什么

| 功能 | 原型实现与验证状态 |
| --- | --- |
| 适配器检查、车辆识别 | 实现 Windows J2534 驱动枚举、连接自检、VIN 查询、ECU 和 PDK 软件标识读取。使用模拟驱动验证请求、响应和错误处理。 |
| 固件准备与刷前检查 | 实现离线 SDI 压缩编解码、ROM 校验与分段准备。原型对控制器身份、软件版本及备份匹配进行检查。 |
| PDK 原车程序备份 | 针对 Q033／Q061 实现双次读取和一致性检查，并将备份绑定到控制器身份及软件版本。已用合成数据跑通备份流程。 |
| PDK 实验写入、还原与中断处理 | 原型在模拟环境中验证了实验写入、写后读回比对及从匹配备份还原。也覆盖了无备份、备份损坏、身份不符和恢复中断等情况。 |
| ECU 刷写 | 已实现识别与部分离线准备。原型暂时限制新 ECU 写入，因为原车完整读取及原样还原仍缺少验证。 |

历史完整原型在 Windows x64 和 x86 上各通过 178 项模拟回归。这个公开仓库提供 Manager 离线分析器、J2534 适配器与识别代码、SDI 压缩编解码器、合成测试及研究报告。PDK 备份、写入和恢复以历史模拟结果记录。各目录的测试方法见 [Manager 工具说明](manager/README.md)和 [Porsche 981 原型说明](porsche981/README.md)。

## 哪些功能还没有测试过

- **实车和台架连接**。尚未用真实 J2534 适配器验证 981 的 VIN、控制器识别、通信时序与稳定性，普通 OBD 转 USB 线材的兼容性也未确认。
- **真实 ECU 和 PDK 写入及还原**。尚未在台架控制器或实车上验证完整读取、写入、点火循环后的读回，或写入中断后的救援。EEPROM、防盗数据和自适应数据未纳入备份与还原范围。
- **真实 Accessport 和官方 Map 交互**。尚未实测 Manager 与手持设备的 USB 会话、设备固件实际安装、授权 Map 的传输和 PDK 授权。

## 仅供测试

> **仅供测试 / For testing purposes only.** 本项目是独立的离线分析和模拟研究，请勿用于实车刷写或道路车辆操作。项目与 COBB Tuning、Porsche 无隶属关系，相关商标归各自权利人所有。
