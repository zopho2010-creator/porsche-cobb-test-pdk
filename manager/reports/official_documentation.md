# COBB 官方资料交叉核验

访问日期：2026-11-04。仅使用 COBB 官方网站及其公开 Atlassian 支持站；以下为摘要，不复制整篇资料。本文的「文档支持」是公开说明书支持，不能代替软件代码或设备测试。「已验证」仅指本次匿名读取页面或链接成功。未连接 Accessport 或车辆。

## PC 与车端职责

- **文档支持**：Manager 的公开职责是传输 calibration/map、datalog，以及更新 Accessport 固件。当前产品页要求 Windows 11（不支持 Windows ARM），需可传数据的 micro USB 线；不能据此推断 PE 是 64 位。来源：[Manager 产品页](https://www.cobbtuning.com/products/accessport-manager/)，未标发布日期。
- **已验证（网页链接）**：上述页面的 Windows 下载按钮指向 `https://s3.us-west-2.amazonaws.com/software.cobbtuning.com/Update/AccessportManager/3.2.0/APManagerSetup.exe`。`3.2.0` 在 URL 中；安装包内部版本、签名、大小及哈希应以本地样本分析为准。网页没有明确给出该版本发布日期。
- **文档支持**：Porsche 用户手册把车辆识别、原厂 ECU 数据保存、ECU 编程、恢复，以及 `Change PDK Map` 列为 Accessport 手持机的操作。Manager 用来在 PC 上管理文件和固件。来源：[Porsche V3 手册](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/45351128/V3+Accessport+Porsche+User+Manual)，页面更新 2020-08-27。
- **推测（职责架构）**：因此产品正常路径为「PC Manager ↔ USB ↔ Accessport ↔ OBD-II ↔ 车辆控制器」。这支持主要车辆刷写状态机在 AP 端的判断；不证明 Windows 二进制完全不含车辆相关解析或辅助代码，也不能证明 CAN、ISO-TP、UDS 的具体实现。

## Map 文件处理的直接研究价值

**文档支持**：[Manager Manual](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/28246235/Accessport+Manager+Manual) 描述本地 map 元数据索引、`.ptm` 单图、`.ptp` 多图容器，以及独立 `Unpack Map Pack` 功能。传输 `.ptp` 时会提取适合已安装 AP 的图；BMW/Porsche 是多 ROM revision 的示例。文档还列有 Ctrl+Shift+F11 固件强制更新快捷键。

该页面更新日期为 2020-04-01，正文标注 Manager 3.1.1、User Guide 04/02/2020，存在一天的日期差异，应视为历史文档。**推测**：本地元数据解析和合法 map pack 拆包是没有硬件时较可行的复用目标；字节布局、压缩格式、校验和、设备绑定规则必须另由样本及函数调用证实，手册不提供这些规格。强制更新不等于绕过认证。

## 固件更新流程及获取边界

**文档支持**：[官方更新教程](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/62357749/How+To+Update+Your+AP+s+Firmware)，更新 2020-04-09：安装 Manager/设备驱动，USB 接入 AP，Connect，Updates → Begin Firmware Update，完成后 Eject。Beta 通道需要在 Options 显式选用，官方建议仅按支持人员指引使用。

**文档支持**：[Updating Your Accessport](https://www.cobbtuning.com/updating-your-accessport/)，正文日期 2016-01-18：更新 AP 固件与更新车上 map 是不同步骤；某些更新需要随后重新给车辆加载 map。2025-08-12 官方回复还说明固件里的新 OTS 图可经 AP 的 Restore OTS Maps 放入用户分区，旧用户图不会因此自动删除。本文仅记录流程，不执行相关车辆操作。

**已验证（公开元数据）**：[Porsche 支持索引](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/27721971/Accessport+Support+for+Porsche)，更新 2025-04-01，公开链接到各型号 release notes；[AP3-POR-007 发布说明](https://static.cobbtuning.com/support/releasenotes/AP3-POR-007.html) 无需登录可读。页面本身未直接提供固件包链接。后续静态分析恢复 `AP-POR-007` 内部更新目录，已匿名下载版本 1.8.0.0-29445 的四个 AP 镜像和清单，详情见 [下载实录](firmware_download_path.md)。没有伪造设备、序列号、升级 key 或认证请求；匿名文件下载不证明 PDK 功能或绑定 Map 也无需设备授权。

## Porsche 981 兼容性与版本线索

| 结论 | 状态与官方来源 |
|---|---|
| AP3-POR-007 对应 981 Cayman/Boxster 及部分 991.1；ECU 文档支持 2014–2016 Cayman/S、2015–2016 GTS、2016 GT4/GT4 Clubsport，2013–2016 Boxster/S、2015–2016 GTS、2016 Spyder，具体 MT/PDK 依车型 | 文档支持：[981 NA Map Notes](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/939098141)，更新 2022-04-20；当时最低固件 1.7.4.2-19069，图版本 v400。该最低版本和图版本不是当前最新版本承诺。 |
| PDK 为额外能力，已有 AP 可购买升级并通过 Manager 应用固件更新 key；也有 AP3-POR-007-PDK 产品 | 文档支持：[PDK 发布公告](https://www.cobbtuning.com/accessport-tuning-for-porsche-pdk-transmissions/)，2017-08-16，历史公告；当前 [PDK 升级商品页](https://www.cobbtuning.com/products/accessport/accessport-for-porsche-981-cayman-boxster-991-1-carrera-upgrade-to-pdk-flashing) 仍列 AP3-POR-007 → AP3-POR-007-PDK。不能把付费能力当作免费公开固件研究入口。 |
| 2026-10-29 AP3-POR-007 固件 1.8.0.0-29445 新增 Accesslink 支持 | 已验证（当前公开发布说明元数据）：Windows HTTP 直接读取的页面顶部及本地 本地保存的原始 HTML 一致；这是当前公开文档最新条目，不是某台 AP 的实际可更新版本验证。搜索/抓取缓存曾漏掉此条，故以直接响应为准。 |
| 2026-09-03 AP3-POR-007 固件 1.7.6.0-29311 新增 PDK ROM `Q061_CQCD61DYC`；2025-01-15 的 1.7.5.0-26520 明确新增 981 Cayman/Boxster 2.7L PDK ROM `Q061_CQID61DYC` | 文档支持：上述 AP3-POR-007 release notes。第一个条目未指明 981，不能自行归到 981；两个条目均为历史版本记录。 |
| 2023-07-06 的 1.7.4.2-23340 修正部分 981 PDK Sequential Style 图行为，并把图升为 v401 | 文档支持：同一 release notes。直接说明 2021/2022 的旧 map notes 不能单独代表当前图版本。 |
| 2024-04-25 的 1.7.5.0-25089 在 AP 上保存 `.csv.gz`，Manager 3.1.10+ 导出时解压 | 文档支持：同一 release notes。是查找 Manager 压缩处理代码的有效线索，不能延伸为固件包也使用 gzip。 |

## 尚不能从这些文档获得的能力

- **未知**：981 ECU/PDK 的逐字节刷写协议、CAN ID、诊断会话、分块传输、擦写布局、校验算法、失败恢复条件，以及 ECU/TCU ROM 全部兼容矩阵。ROM 名称是兼容线索，不能直接推出控制器型号或协议。
- **文档支持（负面范围限制）**：[Unknown ROM 教程](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/64520299/How+to+Dump+an+Unknown+ROM+File) 的通用读取流程明确排除 Porsche 和 Ford，随后另述 Ford；不能把其 Save ECU Data/TCM 流程当成 981 可用的 ROM 获取方法。页面显示更新 Apr 07，浏览输出未给出年份，故不补写年份。
- **未知/未验证**：真实 USB 握手与错误恢复、AP 固件实际传输、PDK 升级授权、现场 ECU/TCU 读写。公开资料能建立产品职责、文件类型、版本和 ROM 标识；不能替代设备固件分析、硬件通信捕获及控制器测试。本项目没有执行车辆连接或刷写。

本次未获取受保护固件或升级 key；历史文档只作对应日期的证据，当前行为仍需结合 Manager 3.2.0 静态分析核对。
