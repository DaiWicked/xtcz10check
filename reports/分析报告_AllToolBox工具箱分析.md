# AllToolBox1.4.6 工具箱分析报告

> 分析时间：2026-10-09
> 分析对象：H:\xtcz10check\AllToolBox1.4.6

---

## 一、switch.db 的作用

### 1.1 基本信息

| 项目 | 内容 |
|---|---|
| 文件路径（设备上） | `/data/data/com.xtc.i3launcher/databases/switch.db` |
| 所属应用 | `com.xtc.i3launcher`（小天才桌面启动器） |
| 数据库类型 | SQLite |
| 核心表 | `module_switch`（434 条记录） |
| 字段 | `display`(0/1)、`extra`(JSON配置)、`id`、`module`、`serverId`、`tips` |

### 1.2 核心功能

**switch.db 是小天才系统的「功能模块开关数据库」**，控制 434 个系统功能模块的启用/禁用和配置参数。

- `display=1` → 功能模块启用/可见
- `display=0` → 功能模块禁用/隐藏
- `extra` → JSON 格式的详细配置

### 1.3 在工具箱中的使用方式（z10openinst.bat）

```batch
:: 1. 推送 switch.db 到设备
adb push .\switch.db /sdcard/

:: 2. 获取 root
adb root

:: 3. 设置 prop 启用 adb 安装
adb shell setprop persist.sys.xtc.adb_port 1
adb shell setprop persist.sys.adb.install 1

:: 4. 替换 i3launcher 的 switch.db
adb shell cp -R /sdcard/switch.db /data/data/com.xtc.i3launcher/databases/switch.db

:: 5. 重启 zygote 使配置生效
adb shell setprop ctl.restart zygote

:: 6. 安装第三方应用
adb install -r -t -d .\apks\z10apk.Apk
```

### 1.4 switch.db 控制的关键功能

| 模块 ID | display | extra 配置 | 功能说明 |
|---|---|---|---|
| 55137 | 0 | `{"userdebug":"false"}` | userdebug 模式开关 |
| 55153 | 1 | `{"filterModel":[...],"friendType":[1,16,256,4096]}` | **加好友型号/类型限制** |
| 55155 | 1 | `{"filterModel":[...],"friendType":[1,16,256,4096]}` | 加好友限制（更多型号） |
| 55159 | 1 | `{"filterModel":[...],"friendType":[1,16,256,4096]}` | 加好友限制 |
| 55188 | 1 | `{"filterModel":[...],"friendType":[1,16,256,4096]}` | 加好友限制 |
| 55285 | 0 | `{"filterModel":[...],"friendType":[1,16]}` | 加好友限制（旧型号） |
| 55368 | 0 | `{"domainList":[okii.com, ximalaya.com, ...]}` | 域名白名单 |
| 55499 | 0 | `{"supportModel":["IB","I13",...,"ND03",...]}` | 支持的型号列表 |
| 55126 | 1 | `{"supportingVideo":1,"supportingGif":1,...,"nsfwWeights":{...}}` | 内容审核/NSFW 检测 |
| 55145 | 1 | `{"deadLineTime":4320,"dropCount":90,"trace":{...}}` | 防沉迷/使用时长限制 |
| 55492 | 0 | `{"winterVacationStart":0,...,"limit":0.17559,...}` | 假期模式/使用限制 |

### 1.5 绕过应用安装限制的原理

小天才系统默认禁止安装第三方应用，限制来自两个层面：

1. **系统属性层**：`persist.sys.adb.install` 控制 adb 安装是否允许
2. **数据库层**：switch.db 中的模块开关控制安装器行为

工具箱通过：
- `setprop persist.sys.adb.install 1` → 打开 adb 安装开关
- 替换 switch.db → 将安装相关模块设为 `display=1`
- 重启 zygote → 使配置生效

**注意**：这就是你之前提到的「switch.db 绕过有时间限制」的原因——系统可能会定期从服务器同步 switch.db，覆盖本地修改。

---

## 二、强制加好友功能分析

### 2.1 工具箱中是否有「强制加好友」代码？

**结论：没有找到独立的「强制加好友」脚本或代码。**

搜索结果：
- `friendType` / `filterModel` → 只在 switch.db 的 extra 配置中出现
- `bleaddfriend` → 只在 root-SDK30.bat 的 LSPosed 作用域列表中出现
- `加好友` → 无匹配
- `好友数` → 只在 rtos.py 的账号信息展示页面中出现

### 2.2 加好友相关的系统组件

| 组件 | 包名 | 说明 |
|---|---|---|
| 蓝牙加好友应用 | `com.xtc.bleaddfriend` | 小天才官方蓝牙加好友系统应用 |
| SystemPlus 模块 | `com.zcg.systemplus` | LSPosed 模块，hook 了 bleaddfriend |

### 2.3 「强制加好友」可能的实现方式

工具箱中没有直接的强制加好友代码，但可能通过以下方式间接实现：

#### 方式 A：修改 switch.db 放宽加好友限制

switch.db 中有 5 条加好友相关配置：
```json
{"filterModel":["I16","I17","DI01",...], "friendType":[1,16,256,4096]}
```
- `filterModel` → 控制哪些型号之间可以互相加好友
- `friendType` → 控制允许的好友类型（1=普通, 16=?, 256=?, 4096=?）

通过修改这些配置，可以**放宽加好友的型号限制和类型限制**。

#### 方式 B：SystemPlus (LSPosed) 模块 hook

在 root-SDK30.bat 中，SystemPlus 模块的作用域包含：
```
com.xtc.bleaddfriend  ← 蓝牙加好友应用
com.xtc.i3launcher    ← 桌面启动器
com.xtc.keystore      ← 密钥库
com.xtc.datacenter    ← 数据中心
...（共 40+ 个系统应用）
```

SystemPlus 模块可能通过 hook `com.xtc.bleaddfriend` 的加好友验证逻辑，实现：
- 跳过型号检查
- 跳过好友数量限制
- 跳过家长验证

#### 方式 C：rtos.py 账号管理

rtos.py 是一个账号管理工具（基于 RTOS 协议），其中有「好友数」展示，但这只是**读取账号信息**，不是强制加好友。

### 2.4 结论

「强制加好友」功能**不在工具箱的脚本层面**，而可能在：
1. **SystemPlus APK** 中（LSPosed 模块，需要反编译 APK 确认）
2. **switch.db 配置**中（放宽加好友限制）
3. **Z10_SystemPlus.apk** 或 **appsettings-ND03.apk** 中

如果需要确认具体实现，需要反编译 `Z10_SystemPlus.apk` 或 `com.zcg.systemplus` 模块。

---

## 三、工具箱整体架构

### 3.1 核心组件

| 组件 | 说明 |
|---|---|
| `双击运行.exe` / `AllToolBox.exe` | 主程序（菜单界面） |
| `menu.exe` | 菜单渲染 |
| `bin\*.bat` | 功能脚本（root、安装、备份、EDL 等） |
| `bin\*.sh` | 设备端执行脚本（Magisk 模块安装等） |
| `bin\rtos.py` / `rtos.exe` | RTOS 协议账号管理工具 |
| `bin\apks\` | 预装 APK（SystemPlus、应用商店、微信等） |
| `bin\EDL\` | EDL 模式工具（firehose、XML 配置、misc 镜像） |
| `bin\ND03.zip` | ND03 固件包（3GB） |

### 3.2 主要功能模块

| 脚本 | 功能 |
|---|---|
| `root.bat` / `root-SDK30.bat` | Root 流程（Magisk + LSPosed + SystemPlus） |
| `z10openinst.bat` | 绕过安装限制（switch.db + prop） |
| `instapp.bat` / `userinstapp.bat` | 安装应用 |
| `backup.bat` | 备份/恢复 |
| `rebootpro.bat` | 重启到各种模式（QMMI/EDL/recovery） |
| `magiskpatch.bat` | Magisk patch boot |
| `cloud.bat` | 云服务/账号管理 |
| `scrcpy-ui.bat` | 屏幕投射 |
| `xtcpatch.bat` | XTC 系统补丁 |

### 3.3 Root 流程（root-SDK30.bat 关键步骤）

1. 刷入 Magisk patch 后的 boot
2. 安装 Magisk APK
3. 安装 LSPosed (riru_lsposed)
4. 安装 SystemPlus 模块 (`com.zcg.systemplus`)
5. 激活 SystemPlus 模块，作用域覆盖 40+ 系统应用
6. 安装各种工具 APK

---

## 四、与我们项目的关联

### 4.1 对我们的启发

1. **switch.db 是系统功能控制的核心** — 我们之前只关注了 BL 解锁，但系统层的功能限制（安装、加好友等）是通过 switch.db 控制的
2. **SystemPlus 模块是关键** — 作者通过 LSPosed hook 系统应用来绕过各种限制，这比修改系统分区更灵活
3. **QMMI 模式 + adb root 是基础** — 工具箱的很多功能依赖 QMMI 模式的 adb root

### 4.2 后续可以研究的方向

1. **反编译 SystemPlus APK** — 看看它具体 hook 了哪些方法，如何绕过安装限制和加好友限制
2. **分析 switch.db 的完整结构** — 434 个模块的具体含义，哪些控制安装、哪些控制加好友
3. **研究 RTOS 协议** — rtos.py 实现了账号管理，可能包含加好友的协议实现
4. **对比作者的 switch.db 和原版** — 看看作者修改了哪些模块的 display 值

---

*报告完成*
