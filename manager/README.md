# Accessport Manager 静态研究

## 研究记录

- [软件清单](reports/software_inventory.md)、[逐文件哈希](samples_manifest.json)和[签名检查](analysis/pe_metadata/authenticode_all.json)覆盖官方 Windows Manager 3.2.0 安装包和解包产物。原始安装包的 Authenticode 检查通过。单独检查提取出的主程序时，Windows 报告其未单独签名。
- [USB 通信](reports/communication_analysis.md)和[架构图](reports/architecture.mmd)记录 Windows 端模块和调用关系。研究使用了 REA 6.8.0 与 Ghidra 12.1.4。曾出现自动分析漏块，关键路径以定向反汇编复核。
- [POR-007 下载记录](reports/firmware_download_path.md)保留公开入口、版本和文件校验。历史记录显示四个镜像与公布的 MD5 清单一致。HTTP 下载和清单一致性只验证了当时取得的文件。
- [Map 元数据](reports/map_format_analysis.md)、[公开 Map 调查](reports/public_map_availability.md)及[官方资料核对](reports/official_documentation.md)记录文件类型和授权范围。研究未取得授权的官方 981 Map 样本。
- [原始项目验证摘要](analysis/final_verification.json)记录历史检查覆盖了 33 个 Manager 样本文件、6 个固件及清单文件和 46 条 REA 记录。此处保留摘要、来源、哈希与报告。

## 本地复现

Python 3.12 及以上。在本目录执行以下命令。单元测试使用合成文件和模拟 HTTP 响应，不要求安装 Manager 或连接硬件。

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/manager_analyzer/main.py scan .\samples
python tools/manager_analyzer/main.py report .\analysis
```

扫描前可将合法取得的样本放在 `samples/`。官方 Manager 获取脚本 `tools/acquire_official.ps1` 固定版本和哈希，只在本地下载及解包，解包需要 Bandizip。公开设备更新下载脚本 `tools/acquire_por007_firmware.py` 固定 AP-POR-007 的版本，并验证清单和镜像。分析器生成 PE 元数据、字符串索引和依赖图，不执行样本。运行分析前可使用 `--output` 指向独立目录，保留归档中的历史记录。
