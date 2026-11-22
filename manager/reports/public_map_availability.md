# Porsche 981 公开 Map 与固件样本获取边界

调查日期：2026-11-04。结论：**仍未取得官方 981 `.ptm`/`.ptp` 文件；后续通过 Manager 静态代码恢复了公开更新地址，已经匿名下载 POR-007 的四个 AP 固件镜像及清单**。实际文件、URL 与哈希见 [固件下载实录](firmware_download_path.md)。以下网站 Map 检查不代表固件下载结论。

## 实际检查路径

| 来源/动作 | 实际结果与证据等级 |
|---|---|
| [981 NA Map Notes](https://cobbtuning.atlassian.net/wiki/spaces/PRS/pages/939098141) 的 `COBB Tuning Porsche Map Database` 链接 | **已验证**：当前匿名 HTTP 页面中的实际 `href` 是 `http://www.cobbtuning.com/`，链接标题虽称 Map Database，却不是直接 map 文件链接。 |
| 官网首页的 Maps 导航 | 网页读取工具给出的目标为 [https://www.cobbtuning.com/maps](https://www.cobbtuning.com/maps)。本轮没有从该入口发现经过确认的 981 二进制直接链接。 |
| [2014–2016 Cayman / 2013–2016 Boxster Stage 1 Map](https://www.cobbtuning.com/maps/2014-2016-porsche-cayman-981-2013-2016-porsche-boxster-981-stage-1-map) | **文档支持（工具缓存，抓取标注约两周前）**：页面明确 `Accessport Serial Number Required`，称其为 locked Map，要求正确的 10 位 AP 序列号，并显示 Add To Cart；版本 4.00。这不是匿名二进制下载入口。 |
| 上述 Stage 1 页面当前 Windows HTTP GET | **已验证（访问限制）**：返回 HTTP 403、5,836 字节 Cloudflare `Just a moment` 页面。因此不能把缓存商品页当成当前网络端到端验证，也不能判定服务器此刻仍完全采用相同下载规则。未尝试绕过。 |
| [2016 GT4 Clubsport Stage 0](https://www.cobbtuning.com/maps/2016-porsche-cayman-981-gt4-clubsport-stage-0-map)、[2016 Boxster Spyder Anti-Theft](https://www.cobbtuning.com/maps/2016-porsche-boxster-spyder-981-anti-theft-mode-map) | **文档支持（搜索索引）**：同样显示 AP 序列号必填与 locked Map，前者版本 2.03，后者 4.00；未获得匿名文件 URL，不提交表单。索引内容可能滞后。 |
| [2018 OEM+ PDK 公告](https://www.cobbtuning.com/new-pdk-maps-for-supported-991-1-981-vehicles/) | **文档支持（历史）**：2018-08-23 公告说用户可更新 AP 固件或从网站 maps 区取得图；它不提供今天可用、无设备授权的直接文件链接，不能把历史「可下载」表述当成当前匿名授权。 |

## 当前 AP3-POR-007 固件说明

**已验证（直接 HTTP）**：[官方发布说明](https://static.cobbtuning.com/support/releasenotes/AP3-POR-007.html) 返回 HTTP 200、45,999 字节，`Last-Modified: Thu, 29 Oct 2026 18:51:21 GMT`。与共享保存的 本地保存的原始 HTML 一致，顶部版本为 **1.8.0.0-29445，日期 2026-10-29**，新增 Accesslink 支持。搜索/抓取缓存仅显示下一条 2026-09-03 的 1.7.6.0-29311，因此当前版本元数据应以直接响应为准；仍不代表任何特定设备的实际可更新版本。

**已验证（页面链接检查）**：当前发布说明可见链接中未找到上述扩展名的二进制链接。后续代码分析找到的 `.img` 资源位于另一更新根，真实匿名下载已成功。没有枚举对象存储、构造设备身份或请求受保护下载；先前错误 profile / 非版本目录的 404 已保留，不能当成认证要求。

## 对复用研究的影响

- **已验证**：没有新增 `samples/public_maps` 样本；新增的 AP 固件及清单保存于 `samples/firmware/`，独立扫描结果为 `analysis/firmware_samples/`，原 Manager 快照保持原样。
- **未知**：官方 981 map 的实际头结构、完整校验、解包后的数据分布及绑定规则，不能用合成测试文件来宣称兼容真实商业样本。
- **可继续的合法路径**：继续静态分析 Manager 自带的元数据/容器处理代码；未来若获得具有合法使用权限的官方图样本，再验证解析与官方 Manager 的输出是否一致。PDK 升级授权和设备绑定不属于本轮可绕过的文件处理目标。

本次读取公开页面及公开更新文件，未登录、未提交或伪造 AP 序列号、未加入购物车、未执行样本，也未连接车辆。
