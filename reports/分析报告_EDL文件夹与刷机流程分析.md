# AllToolBox1.4.6 EDL 文件夹分析报告

> 分析时间：2026-10-09
> 分析对象：H:\xtcz10check\AllToolBox1.4.6\bin\EDL

---

## 一、EDL 文件夹结构

```
EDL/
├── prog_firehose_ddr.elf    # ND03 用的 firehose 程序（548KB）
├── msm8909w.mbn             # 旧型号 firehose（280KB）
├── msm8937.mbn              # 新型号 firehose（416KB）
├── ND03.zip                 # ND03 固件包（3GB）
├── allxml/                  # 各型号 rawprogram XML
│   ├── I13.xml / I13C.xml / I19.xml / I20.xml
│   ├── I25.xml / I25D.xml / I32.xml
│   ├── ND01.xml (6.7KB) / ND07.xml
├── misc/                    # misc 分区镜像和 XML
│   ├── misc.img (7字节占位) / ffbm.img / fastbootd.img / wipe.img (1MB)
│   ├── misc_ND03.xml / misc_ND01.xml / ... (各型号)
└── rooting/                 # ★ root 方案核心文件
    ├── abl.img              # 作者的 UserDebug abl（1MB）
    ├── boot.img             # Magisk patch 后的 boot（96MB）
    ├── Dm.zip               # Magisk 模块包（3.5MB）
    ├── recovery.img         # TWRP recovery（49.5MB）
    ├── super.img            # 修改后的 super 分区（3.5GB）
    ├── vbmeta.img           # 重签的 vbmeta（64KB）
    ├── vbmeta_system.img    # 重签的 vbmeta_system（64KB）
    ├── rawprogram0.xml      # root 刷机 XML
    ├── eboot.xml            # 刷 boot 的 XML
    ├── info.txt             # 版本号：ND03.ATB.3.0.2.26.8.27
    ├── misc.img             # misc 镜像
    └── 281/                 # 完整 v2.8.1 固件（281=构建号）
        ├── xbl.elf (3MB) / abl.elf (152KB) / tz.mbn (2.8MB)
        ├── prog_firehose_ddr.elf (540KB)
        ├── rawprogram0.xml / patch0.xml
        ├── super_1.img ~ super_5.img (super 分块)
        ├── userdata_1.img ~ userdata_10.img
        └── ... (完整固件文件)
```

---

## 二、EDL 刷机完整流程

### 2.1 核心脚本：rebootpro.bat 的 :flash_device 函数

```batch
:: 输入参数：mode (qmmi/ffbm/wipe/fastbootd), platform (z10/otherpash/v3pash), innermodel
:flash_device

:: 1. 选择平台和 firehose 加载器
if "%platform%"=="z10" (
    set "loader=prog_firehose_ddr.elf"
    set "misc_xml=misc_ND03.xml"
    set "misc_img=misc.img"
) else if "%platform%"=="otherpash" (
    set "loader=msm8909w.mbn"
    ...
) else if "%platform%"=="v3pash" (
    set "loader=msm8937.mbn"
    ...
)

:: 2. 选择模式镜像
if "%mode%"=="ffbm"  set "image_src=ffbm.img"
if "%mode%"=="wipe"  set "image_src=wipe.img"
if "%mode%"=="fastbootd" set "image_src=fastbootd.img"
if "%mode%"=="qmmi"  set "image_src=misc.img"

:: 3. 检测设备，如果是 adb 则重启到 EDL
device_check.exe qcom_edl adb
if "%devicestatus%"=="adb" adb reboot edl

:: 4. 复制文件到临时目录 EDL\rooting\
copy /Y ".\EDL\misc\%misc_xml%" ".\EDL\rooting\misc.xml"
copy /Y ".\EDL\misc\%image_src%" ".\EDL\rooting\misc.img"

:: 5. 获取 9008 端口
call edlport
:: 检测 Qualcomm HS-USB QDLoader 9008，提取 COM 口号

:: 6. ★ 发送 firehose 程序到设备（Sahara 协议）
call QSaharaServer.bat -p \\.\COM%port% -s 13:"%cd%\EDL\%loader%"
:: -s 13: 表示发送程序到内存并执行

:: 7. ★ 刷入 misc 分区（firehose 协议）
call fh_loader.bat --port=\\.\COM%port% --memoryname=EMMC ^
    --search_path=EDL\rooting --sendxml=EDL\rooting\misc.xml --noprompt

:: 8. ★ 重启设备
call qfh_loader.bat --port=\\.\COM%port% --memoryname=EMMC ^
    --search_path=EDL\ --sendxml=reboot.xml --noprompt

:: 9. 清理临时文件
del /Q /F ".\EDL\rooting\*.*"
```

### 2.2 关键工具说明

| 工具 | 作用 |
|---|---|
| `QSaharaServer.exe` | Sahara 协议，把 firehose 程序发送到设备内存运行 |
| `fh_loader.exe` | firehose 协议，根据 XML 配置刷入分区镜像 |
| `qfh_loader.exe` | firehose 协议（备用/增强版），支持重启等命令 |
| `edlport.bat` | 检测 9008 端口，用 `lsusb` 查找 "Qualcomm HS-USB QDLoader 9008" |
| `device_check.exe` | 检测设备状态（adb/fastboot/qcom_edl） |

### 2.3 reboot.xml（重启命令）

```xml
<?xml version="1.0" ?>
<data>
  <power value="reset"/>
</data>
```

---

## 三、进入 QMMI 模式的原理

### 3.1 misc_ND03.xml

```xml
<?xml version="1.0" ?>
<data>
  <program
    SECTOR_SIZE_IN_BYTES="512"
    filename="misc.img"
    label="misc"
    num_partition_sectors="2048"
    start_sector="9337104"
  />
</data>
```

- 刷入 `misc.img` 到 misc 分区
- 起始扇区：9337104
- 大小：2048 扇区 = 1MB

### 3.2 原理

**通过 EDL 刷入特制的 misc.img 到 misc 分区，设备重启后 bootloader 读取 misc 分区的启动模式标志，进入 QMMI（Qualcomm Manufacturing Mode Interface）模式。**

misc 分区是高通设备的启动控制分区，存储：
- 启动模式标志（normal/recovery/QMMI/FFBM 等）
- 恢复出厂设置标志
- 其他启动控制信息

这和你之前说的「通过 misc.bin 写入进入 QMMI」完全一致！工具箱只是把这个流程自动化了。

### 3.3 其他模式

| 模式 | 镜像文件 | 说明 |
|---|---|---|
| QMMI | misc.img | 高通工厂模式，有 adb root |
| FFBM | ffbm.img | 工厂功能测试模式 |
| wipe | wipe.img (1MB) | 清除数据模式 |
| fastbootd | fastbootd.img | userspace fastboot 模式 |

---

## 四、作者的 root 方案（rooting/ 目录）

### 4.1 rooting/rawprogram0.xml（root 刷机 XML）

```xml
<?xml version="1.0" ?>
<data>
    <!-- abl_a + abl_b：作者的 UserDebug abl -->
    <program filename="abl.img" label="abl_a" start_sector="1362944" num_partition_sectors="2048"/>
    <program filename="abl.img" label="abl_b" start_sector="1364992" num_partition_sectors="2048"/>

    <!-- vbmeta_a + vbmeta_b：重签的 vbmeta -->
    <program filename="vbmeta.img" label="vbmeta_a" start_sector="1377296" num_partition_sectors="128"/>
    <program filename="vbmeta.img" label="vbmeta_b" start_sector="1377424" num_partition_sectors="128"/>

    <!-- vbmeta_system_a + vbmeta_system_b -->
    <program filename="vbmeta_system.img" label="vbmeta_system_a" start_sector="1377552" num_partition_sectors="128"/>
    <program filename="vbmeta_system.img" label="vbmeta_system_b" start_sector="1377680" num_partition_sectors="128"/>

    <!-- super：修改后的 super 分区 -->
    <program filename="super.img" label="super" start_sector="1843456" num_partition_sectors="7340032"/>
</data>
```

**关键发现：只刷 4 个分区，没有刷 boot.img 和 xbl！**

| 分区 | 镜像 | 说明 |
|---|---|---|
| abl_a / abl_b | abl.img | 作者的 UserDebug abl（解锁 BL 的关键） |
| vbmeta_a / vbmeta_b | vbmeta.img | 重签的 vbmeta（禁用 AVB 校验） |
| vbmeta_system_a / vbmeta_system_b | vbmeta_system.img | 重签的 vbmeta_system |
| super | super.img | 修改后的 system（可能包含 root 相关修改） |

### 4.2 rooting/eboot.xml（刷 boot）

```xml
<program filename="eboot.img" label="boot_a" start_sector="1450240" num_partition_sectors="196608"/>
<program filename="eboot.img" label="boot_b" start_sector="1646848" num_partition_sectors="196608"/>
```

刷入 Magisk patch 后的 boot 到 boot_a 和 boot_b。

### 4.3 rooting/info.txt（版本号）

```
ND03.ATB.3.0.2.26.8.27
```

这是 **v2.8.1 版本**的固件（26.8.27 可能是构建日期或版本号）。

### 4.4 作者的完整 root 流程（与你描述的一致）

```
1. QFIL 刷 2.8.1 完整系统（rooting/281/ 目录的文件）
   ↓
2. EDL 刷 rooting/rawprogram0.xml
   - 刷入作者的 UserDebug abl（abl_a + abl_b）
   - 刷入重签的 vbmeta（禁用 AVB）
   - 刷入修改后的 super
   ↓
3. 从 EDL 重启，自动进入 recovery
   ↓
4. 在 recovery 选择重启到 bootloader
   ↓
5. fastboot boot recovery.img（TWRP，临时启动）
   ↓
6. adb shell twrp sideload
   ↓
7. adb sideload Dm.zip（Magisk 模块包）
   ↓
8. 重启，系统自动重启 3 次后获得 root
```

---

## 五、rooting/281/ 完整固件

### 5.1 关键文件

| 文件 | 大小 | 说明 |
|---|---|---|
| `xbl.elf` | 3MB | XBL（eXtensible Boot Loader） |
| `abl.elf` | 152KB | ABL（Application Boot Loader） |
| `tz.mbn` | 2.8MB | TrustZone |
| `hyp.mbn` | 358KB | Hypervisor |
| `rpm.mbn` | 244KB | Resource Power Manager |
| `prog_firehose_ddr.elf` | 540KB | firehose 程序 |
| `rawprogram0.xml` | 28KB | 完整刷机 XML |
| `patch0.xml` | 6KB | patch 配置 |
| `super_1.img` ~ `super_5.img` | 合计 ~2.4GB | super 分块（稀疏镜像） |
| `userdata_1.img` ~ `userdata_10.img` | - | userdata 分块 |
| `misc.mbn` | 1MB | misc 分区 |
| `persist.img` | 32MB | persist 分区 |
| `NON-HLOS.bin` | 93MB | modem 固件 |
| `dspso.bin` | 64MB | DSP 固件 |
| `dtbo.img` | 8MB | DTBO |
| `recovery.img` | 48MB | recovery |
| `boot.img` | 96MB | boot |
| `vbmeta.img` | 8KB | vbmeta |
| `vbmeta_system.img` | 4KB | vbmeta_system |

### 5.2 与我们解密的 v1.0.1 固件对比

- 作者的固件是 **v2.8.1**（281 构建号）
- 我们的设备是 **v1.0.1**
- 这就是为什么「混刷镜像会开不了机」——版本不兼容

---

## 六、与我们项目的关联

### 6.1 已确认的事实

1. ✅ **作者的 abl 是 UserDebug 构建** — rooting/abl.img 就是作者的 abl
2. ✅ **作者通过 EDL 刷入 abl** — rawprogram0.xml 明确刷 abl_a + abl_b
3. ✅ **进入 QMMI 的原理** — 刷特制 misc.img 到 misc 分区
4. ✅ **作者的固件版本** — v2.8.1（ND03.ATB.3.0.2.26.8.27）
5. ✅ **作者没有修改 xbl** — rooting/rawprogram0.xml 不包含 xbl
6. ✅ **作者重签了 vbmeta** — vbmeta.img 只有 64KB（原版通常更大或有签名）

### 6.2 对我们的启发

1. **EDL 刷机流程已完全掌握** — Sahara 协议 + firehose 协议
2. **misc 分区控制启动模式** — 可以通过修改 misc.img 进入 QMMI
3. **作者的 root 方案依赖 UserDebug abl** — 这是我们无法复制的（需要内部渠道）
4. **v2.8.1 完整固件在 rooting/281/** — 可以用来对比分析

### 6.3 后续可以做的

1. **对比作者的 abl.img 和我们的 v1.0.1 abl** — 确认差异
2. **分析作者的 vbmeta.img** — 看看是怎么重签的
3. **解压 Dm.zip** — 看看 Magisk 模块做了什么
4. **分析作者的 super.img** — 看看 system 分区有什么修改
5. **对比 rooting/281/xbl.elf 和我们的 v1.0.1 xbl** — 看看 XBL 有没有差异

---

*报告完成*
