# SafeGuard 安卓版（SafeGuard-Android）

> 桌面版（Windows/Linux）见 `SafeGuard/`；本目录为安卓版完整源码工程。
> 架构：Kotlin + 真实 SHA-256/MD5 哈希扫描 + 本地哈希病毒库 + VirusTotal v3 云端复核 + SAF 存储访问框架 + 应用私有目录隔离区。

## 功能（与桌面版对齐的能力）
| 能力 | 桌面版 | 安卓版 |
|---|---|---|
| 哈希扫描 | C++ DLL（自研 SHA-256/MD5） | Kotlin MessageDigest（真实计算） |
| 哈希病毒库 | signatures.json（用户自建） | assets/virus_db/signatures.json（用户自建） |
| 云端情报 | Java JAR + VirusTotal v3 | Kotlin VtClient + VirusTotal v3 |
| 隔离区 | AES-256 加密（C++/OpenSSL） | 应用私有目录（Android 沙箱） |
| 白名单 | white_list.json | SharedPreferences + 系统目录 |
| 自定义扫描 | 目录选择 | SAF 文档树选择 |
| 实时监控 | ReadDirectoryChangesW | （安卓无同权限，采用手动/SAF 扫描） |

## 构建 APK

### 方式一：Android Studio（推荐）
1. 安装 Android Studio（Jellyfish 2023.3.1 或更新）。
2. File → Open → 选择本目录 `SafeGuard-Android/`。
3. 等待 Gradle 同步完成（首次需联网下载依赖）。
4. Build → Build Bundle(s) / APK(s) → Build APK(s)。
5. APK 输出位置：`app/build/outputs/apk/debug/app-debug.apk`。

### 方式二：命令行
```bash
# 前置：JDK 17 + Android SDK（设置 ANDROID_HOME）
cd SafeGuard-Android
gradle wrapper          # 生成 gradlew（若本机有 gradle）
./gradlew assembleDebug
# 产物：app/build/outputs/apk/debug/app-debug.apk
```

### 方式三：Windows 一键（PowerShell）
```powershell
cd SafeGuard-Android
# 先确保 ANDROID_HOME 指向你的 SDK 目录
gradlew.bat assembleDebug
```

## 安装与使用
1. 手机开启「允许安装未知来源应用」，安装 `app-debug.apk`。
2. 首次使用点「授权存储权限」（Android 11+ 需授予「所有文件访问」）。
3. 设置页填入 VirusTotal API Key（可选，不填也能本地查杀 EICAR 等已知样本）。
4. 点「快速扫描」全盘扫描；「自定义扫描」用系统文件选择器选目录/文件。

## 验证 EICAR
1. 把 EICAR 官方测试串保存为 `.txt` 文件传到手机。
2. 用「自定义扫描」选择该文件。
3. 应报告 `infected / EICAR-Test-File / engine=hash`（本地哈希库命中）。

## 说明与边界
- 本工程为**用户自维护病毒库**的哈希扫描 + 云端复核方案，未内置真实恶意样本数据（仅 EICAR 官方测试串）。
- 生产级安卓杀毒需 ClamAV NDK 交叉编译与系统级引擎，工程量大；本版优先保证「可编译、可运行、链路真实」。
- 隔离区在应用私有目录（`/data/data/com.safeguard.android/files/quarantine`），卸载应用会一并清除。
