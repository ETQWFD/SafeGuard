# SafeGuard 宣传片 · 画面素材清单

> 本目录存放宣传片所需全部素材。原则：**演示画面必须来自真实运行的 SafeGuard**（软件自己截图/录屏），辅助画面可用免费图库，图标规格见文末。

---

## 一、必须自己录制的素材（软件真实画面）

| # | 素材 | 用途（对应镜头） | 获取方式 |
|---|---|---|---|
| 1 | 主界面截图 ×2（明亮/暗黑） | 产品亮相 Shot 06–07 | 运行 `python main.py`，分别切明亮/暗黑截图（1920×1080） |
| 2 | 全盘扫描录屏 | 真实扫描 Shot 08 | 运行 SafeGuard → 首页点「全盘扫描」，OBS 录制 30s（含进度条与结果表） |
| 3 | EICAR 检出录屏 | 真实扫描 Shot 08 | 先运行 `python scripts/test_eicar.py` 生成 EICAR 文件，再扫描并录制检出弹窗 |
| 4 | U盘插入自动扫描录屏 | U盘防护 Shot 10 | 插入 U盘，录制 SafeGuard 弹出的「检测到U盘插入」通知与自动扫描 |
| 5 | 拦截弹窗截图/录屏 | U盘防护 Shot 10–11 | 在 U盘放入 autorun.inf 后插入，录制红色拦截弹窗 |
| 6 | 主题色/语言/明暗切换录屏 | 个性化 Shot 12 | 设置页依次切换 4 主题色、3 语言、明暗模式，各录 5s |
| 7 | 统计图表截图 ×3 | 个性化 Shot 12 | 首页三张图表（环形/柱状/饼）各截图一张 |

> 录制规范：1920×1080，先切「明亮模式 + 浅蓝主题」再录；鼠标使用高亮光标；关闭无关窗口。

## 二、可免费获取的辅助素材

| # | 素材 | 用途 | 免费图库链接 |
|---|---|---|---|
| 1 | 勒索弹窗示意 | 痛点 Shot 03 | https://unsplash.com / https://pixabay.com （搜索 ransomware） |
| 2 | U盘特写 | 痛点/U盘 Shot 04、10 | https://pixabay.com （搜索 usb flash drive） |
| 3 | 数据泄露新闻截图 | 痛点 Shot 05 | 自行截图公开报道（注意打码个人信息） |
| 4 | 家庭/办公室/学生/老人剪影 ×4 | 价值升华 Shot 14 | https://pixabay.com （搜索 silhouette family / office / student / elderly） |
| 5 | 科技感背景（暗色网格/光点） | 技术亮点 Shot 13 | https://pixabay.com （搜索 technology abstract） |
| 6 | 键盘敲击/警报音效 | 开场/拦截 | https://pixabay.com/sound-effects/ |

## 三、Logo 与图标规格

| 项 | 规格要求 |
|---|---|
| 主 Logo | 256×256 PNG，透明底；盾牌 + 对勾造型；主色 #4A90E2，暗底可用白色变体 |
| 片尾 Logo | 512×512 PNG（4K 缩放安全），带 10% 安全边距 |
| 应用图标 | assets/icons/app.ico 已由脚本生成（256×256 内含 PNG），可直接导出 |
| 水印 | 全片右下角 8% 不透明度「SafeGuard」文字水印（可选） |

## 四、获取建议
1. **先录屏再找图**：先完成 SafeGuard 构建与演示，保证功能镜头真实。
2. **图库检索词**：优先英文关键词（`ransomware`、`silhouette family`、`technology abstract`）命中率高。
3. **授权提醒**：Pixabay/Unsplash 素材免费商用无需署名；第三方新闻截图仅作演示，发布前确认合理使用。
