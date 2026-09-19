# SafeGuard 宣传片 · 渲染与合成指南

> 目标：1920×1080 / 30fps / 150 秒 / 中文旁白 + 中英双语字幕。
> 方案 A：FFmpeg 全命令行合成（免费、可复现）；方案 B：剪映/CapCut 图形化合成。

---

## 0. 素材准备清单（详见 video/assets/README.md）

| 素材 | 数量 | 来源 |
|---|---|---|
| 录屏片段（扫描/U盘/设置） | 5–8 段 | 运行 SafeGuard 后 OBS 录制 |
| 开场代码/警告/架构图动画 | 4 段 | FFmpeg 滤镜生成（见下）或 AE/Motion Graphics |
| 人物剪影 | 4 张 | 免费图库（见 assets/README） |
| Logo | 1 张 | assets/icons/app.ico 导出 PNG（256×256 透明底） |
| 旁白 | 1 段 | Edge TTS / 讯飞 / Azure TTS |
| BGM | 3 段 | 见 bgm_license.md |

---

## 1. 配音工具推荐

### 1.1 Edge TTS（免费，推荐先用这个）
```bash
# 安装：pip install edge-tts
edge-tts --voice zh-CN-YunxiNeural --rate=-8% --file video/narration_zh.md -w video/assets/narration_zh.mp3
edge-tts --voice en-US-ChristopherNeural --rate=-5% --file video/narration_en.md -w video/assets/narration_en.mp3
```
- 中文建议男声 `zh-CN-YunxiNeural` 或 `zh-CN-YunjianNeural`（沉稳）；英文 `en-US-ChristopherNeural`。
- 语速 -8% 更沉稳。

### 1.2 讯飞语音合成（TTS 在线）
- 控制台选择「在线语音合成」，音色选「擎苍/云健」类沉稳男声，语速 0.9。
- 导出 MP3 后导入剪辑软件即可。

### 1.3 微软 Azure TTS
- 更接近真人。音色 `zh-CN-YunxiNeural` / `en-US-ChristopherNeural`，SSML 控制停顿：
```xml
<speak><prosody rate="-8%">每一次点击、每一个U盘，都可能藏着看不见的威胁。</prosody></speak>
```

---

## 2. 录屏工具推荐

| 工具 | 平台 | 用途 |
|---|---|---|
| OBS Studio | Win/Mac/Linux | 主力录屏（1080p 60fps，鼠标轨迹高亮插件） |
| ScreenToGif | Windows | 小片段/GIF 演示 |
| ShareX | Windows | 快速区域录屏 |

录屏建议：分辨率 1920×1080，先运行 SafeGuard 并切到「明亮模式 + 浅蓝主题」再录功能段。

---

## 3. 方案 A：FFmpeg 合成（全程命令行）

### 3.1 生成开场代码动画（0:00–0:10）
```bash
# 黑色底 + 绿色代码滚动 + 红色警告三角（drawtext + geq 简单合成）
ffmpeg -y -f lavfi -i color=c=black:s=1920x1080:d=10:r=30 \
  -vf "drawtext=text='scan(file)->threat:found':fontcolor=0x22C55E:fontsize=48:x=w-mod(t*400\,w+1200):y=h*0.72, \
       drawtext=text='!':fontcolor=0xEF4444:fontsize=420:x=(w-text_w)/2:y=(h-text_h)/2:enable='gte(t,6)':alpha='if(lt(t,6),0,min(1,(t-6)*2))'" \
  -c:v libx264 -pix_fmt yuv420p video/assets/shot01.mp4
```

### 3.2 三段主内容拼接（先各自渲染成 1920×1080 片段）
```bash
# 假设已剪辑好：part1.mp4 / part2.mp4 / part3.mp4 ...
# 拼接所有片段
ffmpeg -y -f concat -safe 0 -i video/assets/list.txt -c copy video/assets/_joined.mp4
```
其中 `video/assets/list.txt` 内容：
```
file 'part1.mp4'
file 'part2.mp4'
...
```

### 3.3 烧录中英双语字幕（双行）
```bash
ffmpeg -y -i video/assets/_joined.mp4 -i video/assets/narration_zh.mp3 -i video/assets/bgm.mp3 \
  -filter_complex "
    [1:a]adelay=1000|1000,volume=1.0[narr];
    [2:a]volume=0.18,afade=t=in:d=1.5,afade=t=out:st=147:d=3[bgm];
    [narr][bgm]amix=inputs=2:duration=longest[aout];
    [0:v]subtitles=video/subtitle_zh.srt:force_style='FontName=Microsoft YaHei,FontSize=22,PrimaryColour=&H00FFFFFF,OutlineColour=&H00101010,Outline=2,MarginV=48',
         subtitles=video/subtitle_en.srt:force_style='FontName=Arial,FontSize=18,PrimaryColour=&H00E6E6E6,OutlineColour=&H00101010,Outline=1.5,MarginV=88'
    [vout]"
  -map "[vout]" -map "[aout]" \
  -c:v libx264 -preset slow -crf 18 -r 30 -c:a aac -b:a 192k \
  -t 150 -movflags +faststart SafeGuard_promo.mp4
```

### 3.4 只烧英文字幕
```bash
ffmpeg -y -i video/assets/_joined.mp4 -vf "subtitles=video/subtitle_en.srt:force_style='FontName=Arial,FontSize=20,Outline=2,MarginV=60'" \
  -c:v libx264 -crf 18 SafeGuard_promo_en.mp4
```

### 3.5 导出竖版（9:16，用于抖音/视频号）
```bash
ffmpeg -y -i SafeGuard_promo.mp4 -vf "crop=1080:1920:(iw-1080)/2:0,scale=1080:1920" \
  -c:v libx264 -crf 20 SafeGuard_promo_vertical.mp4
```

---

## 4. 方案 B：剪映 / CapCut 图形化合成

### 4.1 项目设置
1. 新建项目 → 比例选「16:9 横屏」→ 分辨率 1080p，帧率 30fps。
2. 项目名称：SafeGuard_promo_150s。

### 4.2 时间线排布（9 段）
| 段 | 时间 | 素材 |
|---|---|---|
| 开场钩子 | 0:00–0:10 | shot01.mp4（代码+警告） |
| 痛点呈现 | 0:10–0:25 | 3 个素材快速切换（勒索/U盘/新闻） |
| 产品亮相 | 0:25–0:40 | 录屏：主界面 + 明暗切换 |
| 真实扫描 | 0:40–1:05 | 录屏：全盘扫描 + EICAR 检出 |
| U盘与实时 | 1:05–1:25 | 录屏：U盘插入 + 拦截弹窗 |
| 个性化 | 1:25–1:45 | 录屏：四色切换 + 语言切换 + 图表 |
| 技术亮点 | 1:45–2:10 | 架构图动画 + 关键词 |
| 价值升华 | 2:10–2:25 | 人物剪影 + 光晕 |
| 结尾 | 2:25–2:30 | Logo + Slogan |

### 4.3 操作步骤
1. 拖入各段素材，按上表对齐时间轴。
2. 「文本」→ 新建文本 → 打开「字幕」面板 → 导入 `video/subtitle_zh.srt`，样式选白字黑边、字号 22、位置 78% 高度。
3. 再导入 `video/subtitle_en.srt`，字号 18，位置 88% 高度（英文字幕居下）。
4. 「音频」→ 导入旁白 MP3，对齐到 1.0s 起点。
5. 「音频」→ 导入 BGM，音量调至 18%，开头结尾加「淡入淡出」。
6. 转场：段与段之间用「叠化」0.5s；0:06 处用「闪白」。
7. 导出 → 分辨率 1080p、帧率 30fps、码率 10–16Mbps。

---

## 5. 最终检查清单
- [ ] 总时长 147–153 秒
- [ ] 分辨率 1920×1080，帧率 30fps
- [ ] 中文字幕与旁白逐句对齐（偏差 < 0.3s）
- [ ] 英文字幕无语法错误
- [ ] BGM 音量不盖旁白（旁白 -6LUFS 左右）
- [ ] 所有演示画面均来自真实运行的 SafeGuard
- [ ] 无「全球第一」「最安全」等广告法违禁词
