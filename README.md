# SafeGuard 安全卫士

> **真实杀毒，轻量守护。** Python (PyQt6) 界面 + C++ DLL (ClamAV/YARA 真实引擎) + Java JAR (VirusTotal 云端情报)。
> 本项目的病毒库由**用户自己制作和维护**，AI 只提供格式、加载代码与收集脚本；唯一预置的测试数据是 EICAR 官方测试串。

---

## 一、架构总览

```
┌─────────────────────────────────────────────────────────┐
│  Python 层（只做 3 件事，无杀毒逻辑）                      │
│  ├─ PyQt6 界面（无边框窗口/三语言/明暗×4主题色/QPainter图表）│
│  ├─ ctypes 调用 safeguard.dll                             │
│  └─ requests 调用 safeguard.jar (127.0.0.1:17890)        │
├─────────────────────────────────────────────────────────┤
│  C++ DLL  (safeguard.dll) - 真实杀毒核心                  │
│  ├─ libclamav：cl_engine_new/cl_load/cl_engine_compile/  │
│  │            cl_scanfile 真实病毒扫描                    │
│  ├─ libyara：加载 .yar 规则并扫描                         │
│  ├─ SHA-256 / MD5 真实哈希（纯 C++ 实现，FIPS 180-4/       │
│  │            RFC 1321）                                 │
│  ├─ 多线程目录扫描（可取消、进度回调）                      │
│  ├─ PE 解析 + 加壳识别（UPX/ASPack/PECompact/高熵）        │
│  ├─ 实时监控 ReadDirectoryChangesW / inotify             │
│  ├─ U盘监控 WM_DEVICECHANGE / 挂载点轮询                  │
│  ├─ 注册表 Run 键监控（RegNotifyChangeKeyValue）           │
│  ├─ 隔离区 AES-256-CBC（OpenSSL EVP，真实加密）            │
│  ├─ 进程阻断 + 白名单（系统目录/签名文件优先放行）           │
│  └─ 结果全部以 JSON 返回 Python                           │
├─────────────────────────────────────────────────────────┤
│  Java JAR (safeguard.jar) - 云端与规则服务                │
│  ├─ VirusTotal v3 API（okhttp，限速 4 次/分钟）            │
│  ├─ MalwareBazaar 病毒库更新（真实 HTTP 拉取）             │
│  ├─ YARA 规则在线更新 + 本地 yara CLI 辅助扫描             │
│  ├─ 威胁情报聚合 / HTML+PDF 报告 / 日志归档               │
│  ├─ 多语言文案服务                                        │
│  └─ 本地 HTTP 服务 127.0.0.1:17890                       │
└─────────────────────────────────────────────────────────┘
```

**铁律**：Python 不含任何杀毒核心逻辑；所有判定由 DLL/JAR 真实完成；禁止假哈希、假病毒名、随机数冒充结果。

---

## 二、目录结构

```
SafeGuard/
├── main.py / requirements.txt / build_py.bat / build_py.sh
├── config/        settings.json · paths.json · api_keys.json
├── lang/          zh_CN.json · zh_TW.json · en_US.json（运行时切换）
├── ui/            main_window + pages(6) + widgets(5) + charts(3) + themes(2 qss)
├── core/          bridge · dll_loader · jar_launcher · config_manager · i18n · theme_manager · event_bus
├── cpp_module/    CMakeLists.txt + include/safeguard_api.h + src/(15) + cmake/Find* + build.bat/sh
├── java_module/   pom.xml + src/main/java/com/safeguard/(10 类) + build.bat/sh
├── data/          virus_db/{signatures.json, rules.yar, behavior_rules.json} · clamav/ · yara_rules/ · white_list.json · stats.json
├── scripts/       collect_from_vt.py · collect_from_mb.py · update_clamav.py · update_yara.py · merge_db.py · validate_db.py · test_eicar.py · make_icon.py
├── video/         150 秒宣传片制作包（脚本/故事板/旁白/双语字幕/BGM/渲染指南）
├── quarantine/    隔离区（运行后自动生成）
├── logs/          日志
└── assets/icons/  app.ico（由 make_icon.py 生成）
```

---

## 三、构建步骤

### Windows

```bat
:: 1. 安装依赖库（vcpkg）
vcpkg install clamav:x64-windows yara:x64-windows openssl:x64-windows

:: 2. 更新 ClamAV 病毒库（CVD 文件会下载到 data/clamav）
python scripts\update_clamav.py

:: 3. 编译 C++ DLL
cd cpp_module && build.bat && cd ..

:: 4. 编译 Java JAR（需要 JDK 11+ 与 Maven）
cd java_module && build.bat && cd ..

:: 5. 安装 Python 依赖
pip install -r requirements.txt

:: 6. 验证真实杀毒链路（应检出 EICAR）
python scripts\test_eicar.py

:: 7. 运行
python main.py

:: 8. 打包 Python 层（生成 run_safeguard.bat）
build_py.bat
```

### Linux

```bash
# 1. 依赖
sudo apt install libclamav-dev libyara-dev libssl-dev python3-pyqt6 openjdk-17-jdk maven

# 2. ClamAV 病毒库
sudo freshclam
python3 scripts/update_clamav.py /usr/bin/freshclam

# 3. C++ 共享库
cd cpp_module && ./build.sh && cd ..

# 4. Java JAR
cd java_module && ./build.sh && cd ..

# 5. Python
pip install -r requirements.txt

# 6. 验证 + 运行
python3 scripts/test_eicar.py
python3 main.py
```

---

## 四、病毒库维护（用户自建，AI 不编造）

| 库 | 文件 | 维护方式 |
|---|---|---|
| 哈希库 | `data/virus_db/signatures.json` | `collect_from_vt.py`（VirusTotal，限速4次/分）或 `collect_from_mb.py`（MalwareBazaar）拉取 → `merge_db.py` 合并去重 → `validate_db.py` 校验 |
| YARA 规则 | `data/virus_db/rules.yar` + `data/yara_rules/` | `update_yara.py` 拉取官方仓库；自行挑选合并 |
| ClamAV CVD | `data/clamav/` | `update_clamav.py` 调用 freshclam |
| 行为规则 | `data/virus_db/behavior_rules.json` | 直接编辑（5 条内置模板已给出） |

> 初始库仅含 EICAR 官方测试串（真实哈希：`275a021b…`）。真实样本哈希请通过上述脚本从公开情报源获取，AI 不生成示例恶意哈希。

---

## 五、DLL 导出接口（ctypes 可调用）

```c
sg_init / sg_shutdown / sg_version
sg_scan_file(path) -> JSON
sg_scan_dir(dir, progress_cb) -> JSON   // 多线程、可取消
sg_start_realtime_monitor / sg_start_usb_monitor / sg_start_registry_monitor
sg_quarantine_add / restore / delete / list
sg_block_process / sg_allow_once
sg_clamav_version / sg_yara_version / sg_reload_virus_db
sg_free_string
```

`sg_scan_file` 返回示例：
```json
{"status":"infected","threat_name":"EICAR-Test-File","sha256":"275a021b…",
 "md5":"44d88612…","level":5,"engine":"hash","detail":"hash db match",
 "scan_time_ms":3}
```

## 六、JAR HTTP 接口（127.0.0.1:17890）

```
GET  /api/version            GET  /api/clamav/version
GET  /api/virusdb/status     POST /api/virusdb/update   {mode: all|mb|yara}
POST /api/vt/query           {sha256}
POST /api/mb/query           {sha256}
POST /api/yara/scan          {file}
POST /api/intel/query        {hash}
POST /api/i18n/load          {lang}
POST /api/report/generate    {scanned, infected_count, ...}
POST /api/log/archive        {tag}
```

## 七、安全防护原则

1. **绝不误杀**：系统目录默认白名单；用户文档目录低敏感；带有效 Authenticode 签名的文件优先放行（WinVerifyTrust）。
2. **隔离而非删除**：所有处置先入隔离区（AES-256 加密），可随时恢复。
3. **性能**：多线程扫描不卡 UI；支持取消与断点续扫（进度回调）。
4. **权限**：进程阻断需要管理员权限时提示；失败自动降级为「仅报警」。

## 八、安卓版

完整安卓工程见 `SafeGuard-Android/`（Kotlin + 真实哈希扫描 + VirusTotal + SAF + 隔离区），构建方式见该目录 `README_ANDROID.md`。

## 九、宣传片

`video/` 目录内含 150 秒产品宣传片完整制作包：双语分镜脚本、14 镜头故事板、中英旁白稿、精确到毫秒的双语 SRT 字幕、BGM 授权说明、FFmpeg/剪映合成指南、素材清单。

## 十、常见问题

| 问题 | 解决 |
|---|---|
| 启动提示 DLL 未加载 | 先执行 `cpp_module/build.bat` 或 `build.sh` 编译，输出到项目根目录 |
| JAR 服务不可用 | `java_module` 构建后根目录需存在 `safeguard.jar` |
| 扫描不报 EICAR | 检查 `data/clamav` 是否有 CVD 库、`rules.yar` 是否含 EICAR 规则、`signatures.json` 是否完整 |
| 云端查询 no_api_key | 在 `config/api_keys.json` 填入 VirusTotal API Key（免费注册） |
