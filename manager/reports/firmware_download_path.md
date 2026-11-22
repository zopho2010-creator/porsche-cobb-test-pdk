# POR-007 固件实际下载与 OBD 链路边界

研究日期：2026-11-04。**已验证：实际下载四个 AP 固件镜像及两份清单；服务器到本机链路成功。没有进行 USB、CAN 或车辆刷写。**

## 地址如何确定

**已验证（静态代码）**：Manager 默认根来自 `0x4E7BE0` 的 `http://www.accessecu.com/support/accessport/`。`0x482B90` 的 `APConnection::getInfo` 路径构造设备 profile，并把字符串写入设备对象 `+0x1F4`。COBB 默认 US profile 是 `AP-` + platform + `-` + 三位 product number；V3 代数通过版本文件名标志处理，没有插入这个目录前缀。Porsche 007 对应 **`AP-POR-007`**，不能直接拿商品 SKU `AP3-POR-007` 当目录。

`0x4E1E60` 取得根、追加 profile 和 `/`，在 `0x4E2656` 调用 `0x51FF50`。实际参数把 Windows 后缀标志设为 0，由设备类型决定 V3 标志。release 分支因此构造 `version_v3.txt`。原始汇编与反编译保存在 `analysis/ghidra/targeted_profile/`、`targeted_followup/0051ff50.*`。

**已验证（静态与真实响应相互印证）**：`0x50F441–0x50F47A` 将版本文本和 `/` 追加到下载根，`0x50F6FB` 将该 URL base 传给文件长度获取 helper `0x522A00`。`0xA6682C` 的原始字节为 `/\0`。`0x5236E0` 是后续文件下载 helper。独立 Ghidra 导出为 `targeted_download/00522a00.*`、`005236e0.*`，不伪造 REA evidence_id。

最终公开路径：

```text
http://www.accessecu.com/support/accessport/AP-POR-007/version_v3.txt
http://www.accessecu.com/support/accessport/AP-POR-007/1.8.0.0-29445/MD5SUMS
http://www.accessecu.com/support/accessport/AP-POR-007/1.8.0.0-29445/ap-app.img
http://www.accessecu.com/support/accessport/AP-POR-007/1.8.0.0-29445/ap-data.img
http://www.accessecu.com/support/accessport/AP-POR-007/1.8.0.0-29445/bootstream.img
http://www.accessecu.com/support/accessport/AP-POR-007/1.8.0.0-29445/rootfs.img
```

**已验证（匿名 GET）**：上述资源实际返回并完整下载，不提交序列号、key、凭据或认证数据。版本清单 241 字节，SHA-256 为 `267de9291ddb731e8c51730aabc0dea2401f59d6affbe3ab91c3dbd19e5d2005`。初次错误的商品 SKU 目录及未带版本号的 `MD5SUMS` 返回 404；这些失败响应不能证明需要授权。错误和正确探测均保存在 `analysis/sources/por007_*`。

## 实际文件与完整性

本地目录：`samples/firmware/AP-POR-007/1.8.0.0-29445/`。四个镜像合计 **58,374,168 字节**；原始 HTTP header、下载耗时、MD5、SHA-256 及 URL 在 `analysis/sources/por007_firmware_download.json`。这是实际文件传输记录，耗时包含本地写入和哈希，不能当作 OBD 刷写速度。

| 文件 | 实际字节数 | 版本清单中的下载 MD5（已匹配） |
|---|---:|---|
| MD5SUMS | 223 | `0954a2cd77d23fd0ceba46488fdadab4` |
| ap-app.img | 19,800,070 | `55442121d0c753e99cbeffbd9f05e55c` |
| ap-data.img | 29,544,454 | `e9a062eeb0bbcebbd1871986ad7597d6` |
| bootstream.img | 6,100,998 | `12027cb26ce682e256ffc4ea1b3df704` |
| rootfs.img | 2,928,646 | `059a2c1f515c8c61b4fd986b23d60937` |

**已验证（范围限制）**：MD5 一致证明本地内容符合这份版本清单。清单与文件均由匿名 HTTP 传输，清单没有在本轮获得独立签名验证；不能把这个一致性检查描述成供应商身份或防篡改的密码学证明。

可重复获取命令：

```powershell
.venv/Scripts/python.exe tools/acquire_por007_firmware.py
.venv/Scripts/python.exe tools/manager_analyzer/main.py scan samples/firmware --output analysis/firmware_samples
```

脚本固定版本清单 SHA-256 与五个文件名，下载先落 `.part`、验证后改名；已有正确文件只核对，不覆盖冲突。合成 HTTP 测试覆盖成功、重复执行、错误响应哈希和现有文件冲突，不使用商业镜像作为测试夹具。

## 镜像初步检查

**已验证（字节统计）**：四份下载数据整体熵约为 7.99994–7.99999 bit/byte；它们不是开头即可识别的 PE、ELF 或本工具支持的常见归档。`MD5SUMS` 中另列出的四份镜像尺寸分别为 19,800,064、29,544,448、6,100,672、2,928,640 字节，全部与下载镜像的 MD5 不同。ap-app、ap-data、rootfs 的下载大小比清单值多 6 字节；bootstream 多 326 字节。**不能据差值直接删除头部或宣布已经获得明文。**

`analysis/firmware_samples/image_inspection.json` 保存头尾、尺寸与熵。字段 `unpacked_*_claim` 只是指 `MD5SUMS` 的另一层数据声明，未验证其解包产物。扫描在 ap-data 偏移 21,620,792 偶遇 gzip magic；实际尝试读该候选会产生 deflate 错误，结果见 `gzip_candidate_check.json`，没有报告为成功解包。

**未知**：完整外层变换、内部文件系统、可执行架构、内部 981 ECU/PDK ROM 列表及实际车型协议。高熵或重复块只能支持继续研究外层编码的线索，不能单独证明加密算法。本轮没有提取商业密钥、解保护或修改镜像。

## 能否通过 OBD 刷写

**文档支持**：[COBB Porsche 用户手册](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/45351128/V3+Accessport+Porsche+User+Manual) 明确支持 Accessport 经 OBD-II 重编程 ECU，车辆操作由手持设备执行。981 的 POR-007 支持与 PDK 相关版本记录见 `official_documentation.md`。PDK 能力还取决于型号、ROM 支持和设备功能状态。

| 链路 | 当前结果 |
|---|---|
| 版本服务 → 本机版本清单、镜像 | **已验证**：实际匿名下载及哈希一致性通过 |
| Manager → Accessport USB | **已验证静态实现**：WinUSB/libusb、端点选择、分包和错误处理；没有设备会话 |
| Accessport 更新、重启、内部镜像运行 | **未知**：没有设备执行证据 |
| AP → 981 ECU/PDK 的 OBD 编程 | **文档支持产品路径**；本机未实测控制器识别、编程会话、数据传输、写后验证或恢复 |
| PC + 普通 OBD 适配器直接使用这些 `.img` | **未建立可用实现**：这些是 AP 更新资源，尚未取得、解析并验证匹配车辆的完整刷写载荷及协议 |

**结论**：已完成用户要求的实际固件下载，能够继续进行设备固件外层研究。它没有自动打通完整刷写链路；服务器下载成功也不能替代 USB 与车端验证。按当前证据，不能交付可直接用普通 OBD 适配器刷写 981 ECU/PDK 的工具。
