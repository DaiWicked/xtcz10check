# XTC ND03 (小天才 Z10) 逆向技术研究项目

> 设备：小天才 Z10，代号 ND03，内部代号 monaco
> 平台：高通骁龙 W5 Gen1 (SW5100)，4nm 四核 A53
> 存储：2GB LPDDR4X + 64GB **eMMC** (mmcblk0)
> 分区：A/B 双槽位
> 系统：CaremeOS 3.0，基于 AOSP Android 11
> 仅用于个人设备的技术学习研究，不传播不商用

---

## 一、项目目标

1. 理解他人 BL 解锁方案的技术原理
2. 在 v1.0.1 版本上复刻解锁思路（v1.0.1 保留 QMMI 漏洞可 adb root）
3. 定位并分析"家长验证"弹窗的触发逻辑
4. 探索家长验证的绕过/逆向方案
5. **掌握固件解密和镜像制作核心技术**，泛化到后续版本或其他 XTC 型号

---

## 二、重大突破（2026-10-07）

### 突破 1：固件全量解密算法已解决

整个固件包使用与 XML 相同的固定 XOR 密钥流：
- **算法**：256 字节 key_table 双重 XOR，等效 16384 字节周期密钥流，初始 index=41/count=41
- **规则**：文件 ≤32KB 全文 XOR；文件 >32KB 仅前 32 字节 XOR（其余本来就是明文）
- **验证**：abl.elf 解密后与设备 dump **逐字节 0 差异**；vbmeta 解密后 AVB 自哈希 MATCH
- **工具**：`tools/xtc_fw_decrypt.py`（支持大文件流式处理，v1.0.1 和 v2.8.1 全量解密成功）

### 突破 2：abl 代码已可读（LZMA 压缩，非全加密）

abl 结构链：`ELF(ARM32容器) → UEFI FV → FFS file(type=0x0B) → GUIDED section(EFI LZMA) → LZMA解压 → PE32+ ARM64`
- 解压后可直接拖进 Ghidra 分析（ImageBase=0，VA=文件偏移）
- **工具**：`tools/abl_unpack.py`（三个版本均解压成功）
- v1.0.1 release: 454856 字节，1757 条字符串
- v2.8.1 release: 454856 字节，1762 条字符串
- 作者 abl: 487624 字节，1913 条字符串

### 突破 3：release abl 本身就有解锁代码路径

关键字符串在**三个版本中都存在**：
- `"State: Unlocked, AvbSlotVerify returned %a, continue boot"` — 解锁即容忍 AVB 失败
- `"Device unlocked: %a"`
- `"assert fail: ops->read_is_device_unlocked != NULL"`
- `"--- XTCWriteDevInfo user key is not null , so we need clear it !"`
- `"Unsupport unlock bootloader: %r"`（标准解锁命令被移除的 stub）

**作者 abl 是官方 UserDebug 构建**（不是手工 patch）：
- 独有路径字符串 `ND08_System_HLOS_UserDebug`（stock 是 `SW5100_System_HLOS_User`）
- .text 比 stock 大 28KB，证书与 stock 同源（原厂签名所以 XBL 才肯加载）
- 构建日期 2025-01-10（介于 v1.0.1 和 v2.8.1 之间）

---

## 三、目录结构

```
H:\xtcz10check\
├── README.md                          ← 本文件
├── .gitignore
├── ND03解锁镜像对比分析报告.md        ← 第一阶段报告
├── ND03镜像解包对比分析报告.md        ← 第二阶段报告
│
├── ND03-2025-03-24-.../              ← 原版官方固件 v2.8.1（加密线刷包）
│
├── 2\250803\                         ← 作者解锁镜像（v2.8.1 明文）
│   ├── abl.img / boot.img / super.img
│   └── vbmeta.img / vbmeta_system.img
│
├── offline-files\                     ← 作者完整工具包（关键！）
│   ├── abl_a.img / boot_a.img / super.img
│   ├── vbmeta_a.img / vbmeta_system_a.img
│   ├── misc.img                       ← 13字节 "boot-fastboot"
│   ├── rawprogram0.xml                ← 明文刷写表（仅刷6分区，无devinfo）
│   ├── recovery.img                   ← TWRP（51.9MB，fastboot boot用）
│   ├── Dm.zip                         ← AnyKernel3 Magisk安装包（3.5MB）
│   └── prog_firehose_ddr.elf         ← EDL Firehose编程器（548KB）
│
├── tools\                             ← 自研工具链（核心！）
│   ├── xtc_fw_decrypt.py              ← 固件全量解密工具（已验证）
│   ├── abl_unpack.py                  ← abl LZMA 解压工具（输出 PE32+）
│   └── verify_decrypt.py              ← 解密结果验证脚本
│
├── decrypted_images\                  ← 解密后的明文镜像库
│   ├── v1.0.1\                        ← v1.0.1 全量解密（44文件成功）
│   └── v2.8.1\                        ← v2.8.1 全量解密（45文件成功）
│
├── unpacked_abl\                      ← abl 解压产物（PE32+ 供 Ghidra 分析）
│   ├── v1.0.1\                        ← release abl PE32+ (454856B)
│   ├── v2.8.1\                        ← release abl PE32+ (454856B)
│   └── author\                        ← 作者 UserDebug abl PE32+ (487624B)
│
└── v1.0.1_dump\                       ← v1.0.1设备dump的明文镜像
    ├── boot_v101.img (96MB)          ← 明文boot（QMMI下dd）
    ├── abl_v101.img (1MB)            ← 明文abl（标准ELF，代码段全加密）
    ├── vbmeta_v101.img (64KB)
    ├── vbmeta_system_v101.img (64KB)
    ├── super.img (3.5GB)
    ├── misc.img (1MB)                 ← "ffbm-02"
    ├── devinfo.img (4KB)              ← 全零（出厂未初始化）
    ├── xtcinfo.img (2MB)              ← MSM-STMSG-BACKUP（硬件校准）
    ├── persist.img (32MB)             ← 未知格式
    ├── xtcdata.img (600MB)            ← ext4，含系统日志
    └── *.py / *.txt                    ← 分析脚本和结果
```

---

## 三、已知情况

### 3.1 原版固件：固定 XOR 密钥流加密（已破解）

| 文件 | 加密方式 | 解密后 |
|---|---|---|
| abl.elf | 前32字节 XOR | ELF（与设备dump 0差异） |
| boot.img | 前32字节 XOR | ANDROID! |
| vbmeta.img | 全文 XOR（≤32KB） | AVB0 |
| rawprogram0/1/2.xml | 全文 XOR（≤32KB） | XML |
| super_*.img | 前32字节 XOR | sparse 镜像 |
| prog_firehose_ddr.elf | 已明文（v1.0.1） | ELF |

**算法**：256 字节 key_table 双重 XOR，密钥流周期 16384 字节。所谓"高通签名头 DB E2 43 0D"=密钥流前 4 字节。
**工具**：`tools/xtc_fw_decrypt.py`

### 3.2 作者 v2.8.1 完整解锁流程（已确认）

```
┌──────────────────────────────────────────────────────────┐
│ 阶段1：EDL 刷入（QFIL）                                    │
│                                                           │
│ 1. QFIL 刷原版 2.8.1 系统 xml（打底）                     │
│ 2. QFIL 刷 offline-files/rawprogram0.xml                  │
│    → 替换6个分区：abl_a / vbmeta_a / vbmeta_system_a     │
│                    boot_a / super / misc                   │
│    → 注意：不刷 devinfo！                                   │
│ 3. EDL 重启 → 自动进入 recovery                            │
└──────────────────────────────────────────────────────────┘
                           ↓
┌──────────────────────────────────────────────────────────┐
│ 阶段2：fastboot boot TWRP（关键！）                        │
│                                                           │
│ 4. recovery → 选择重启到 bootloader                        │
│ 5. fastboot boot recovery.img（TWRP，从内存启动不刷入）    │
│ 6. TWRP 启动成功 → adb 可用                                │
└──────────────────────────────────────────────────────────┘
                           ↓
┌──────────────────────────────────────────────────────────┐
│ 阶段3：sideload Dm.zip（安装 Magisk）                      │
│                                                           │
│ 7. adb shell twrp sideload                                │
│ 8. adb sideload Dm.zip（AnyKernel3 格式）                 │
│ 9. Dm.zip 自动执行：                                        │
│    - split_boot 提取当前 boot → magiskboot 解包            │
│    - magiskboot cpio ramdisk.cpio patch（注入Magisk）      │
│    - sed 修改 fstab（移除 avb/verify/forceencrypt）        │
│    - magiskboot dtb patch（移除设备树中的avb）              │
│    - 创建 .magisk（KEEPVERITY=false, KEEPFORCEENCRYPT=false）│
│    - 重新打包 → flash_boot 刷回 boot 分区                  │
│ 10. 重启 → Magisk初始化（自动重启三次）→ 获得 root          │
└──────────────────────────────────────────────────────────┘
```

**最终状态**：bootloader 显示 **secure=no, device state=unlocked**，可使用 fastboot 命令。

### 3.3 解锁机制分析（核心问题）

**关键事实**：
- rawprogram0.xml **不刷 devinfo**
- 用户 v1.0.1 的 devinfo **全零**（出厂未初始化，无 "DEVICEINFO" magic）
- fastboot getvar **没有 `unlocked` 变量**，只有 `secure: yes`（当前locked状态）
- dip、limits 分区全零；frp 有数据（工厂重置保护，与BL锁无关）
- abl 代码段（0x1000-0x24FFF）**全加密**，无法静态分析
- 作者 abl 与 v1.0.1 abl 对比：前4KB完全相同，差异只在0x25000后证书区域（版本差异）
- 刷完作者方案后显示 **secure=no**（不只是 unlocked，接近工程模式）

**三种可能的解锁机制**：

| 机制 | 说明 | 可能性 |
|---|---|---|
| **A. abl 启动时自动写 devinfo** | 作者修改的 abl 检测到 devinfo 无效（全零），自动构造标准结构并写入 is_unlocked=1 | 高 |
| **B. abl 被 patch 成工程模式** | abl 内部锁状态检查函数被 patch，始终返回 unlocked/secure=no，不修改 devinfo | 高 |
| **C. misc "boot-fastboot" 触发工厂解锁** | 特殊 misc 内容在 abl 中触发高通工厂解锁流程 | 中 |

> abl 代码全加密，作者需持有解密/加密工具才能修改。v1.0.1 复刻时**不建议修改 abl**（风险高），优先尝试手动写 devinfo。

### 3.4 abl 深度分析

```
abl_v101.img 结构：
├─ 0x0000-0x0FFF  ELF header + program headers（明文）
│   ├─ 入口点: 0x9FA00000
│   └─ PH[1]: PT_LOAD, 从0x1000加载到0x9FA00000, 大小0x24000(144KB), RWX
├─ 0x1000-0x24FFF  代码段（全加密！625个"字符串"全是乱码）
│   └─ 无法找到 AVB/unlock/verify 相关字符串
├─ 0x25000-0x26060  证书区域（明文 X.509 证书链）
│   ├─ "General Use XTC Key 1"（小天才专用签名密钥公钥）
│   ├─ "Generated Commercial Root CA1"
│   ├─ "Generated Commercial Attestation CA1"
│   ├─ "CDMA Technologies" / "SecTools" / "DongGuan"（东莞）
│   └─ 有效期：2023-12-21 至 2043-12-16
└─ 文件末尾86字节  dd命令输出残留（"2048+0 records in/out..."）
```

### 3.5 Dm.zip 分析（AnyKernel3 Magisk 安装包）

```
Dm.zip 内容：
├── anykernel.sh              ← 主脚本（Magisk patch + fstab修改 + dtb patch）
├── META-INF/com/google/android/
│   ├── updater-script        ← 67字节
│   └── update-binary         ← 13.5KB
├── tools/
│   ├── arm/                  ← ARM32工具（设备上运行）
│   │   ├── magiskboot        ← Magisk boot解包/打包/签名工具
│   │   ├── magiskpolicy      ← SELinux策略修改
│   │   ├── busybox           ← 工具集
│   │   ├── futility          ← Chrome OS vbutil_key
│   │   └── keycheck          ← 按键检测
│   ├── x86/                  ← x86工具（PC端）
│   ├── avb/
│   │   ├── verity.pk8        ← AVB私钥（PKCS#8）
│   │   └── verity.x509.pem   ← AVB公钥证书
│   ├── chromeos/             ← Chrome OS 签名密钥
│   ├── ak3-core.sh           ← AnyKernel3核心函数
│   ├── util_functions.sh     ← 工具函数
│   └── BootSignature_Android.jar
├── banner                     ← 显示横幅
└── README.md                  ← AnyKernel3说明
```

**关键操作**（anykernel.sh）：
1. `split_boot` 提取当前 boot 分区
2. `magiskboot cpio ramdisk.cpio patch` —— 注入 Magisk
3. sed 修改 fstab：移除 `avb`/`verify`/`forceencrypt`/`fsverity` 标志
4. `magiskboot dtb <dt> patch` —— patch 设备树中的 fstab
5. kernel hexpatch（移除 Samsung RKP/defex，对本设备可能无效）
6. `flash_boot` 重新打包并刷回

### 3.6 TWRP recovery.img 分析

- 标准 ANDROID! 格式，header_version=2
- kernel=32695136（与作者 boot.img kernel 大小完全相同，同一内核）
- ramdisk=17344923（17.3MB，含 TWRP）
- cmdline 末尾：`buildvariant=user buildvariant=eng`（双 buildvariant，TWRP 特征）

### 3.7 v1.0.1 设备情况

#### fastboot getvar 关键输出

```
(bootloader) secure: yes              ← 当前锁定状态
(bootloader) current-slot: a
(bootloader) slot-successful: a: yes
(bootloader) slot-retry-count: a: 7
(bootloader) kernel: uefi
(bootloader) product: monaco
(bootloader) max-download-size: 402653184 (384MB)
注意：没有 (bootloader) unlocked: 变量！
```

#### 分区检查结果

| 分区 | 内容 | 结论 |
|---|---|---|
| devinfo (p24) | 全零（4KB） | 出厂未初始化，无标准 magic |
| dip (p25) | 全零 | 无锁状态数据 |
| limits (p26) | 全零 | 无限制数据 |
| frp (p61) | 有数据（前32字节非零） | 工厂重置保护，与BL锁无关 |

#### 已 dump 镜像

| 镜像 | 内容 | 结论 |
|---|---|---|
| misc.img | `ffbm-02` | 高通工厂模式命令，进入QMMI可adb root |
| devinfo.img | 全零 | 设备信息为空 |
| xtcinfo.img | `MSM-STMSG-BACKUP` + 传感器校准 | 不是绑定信息，是高通SMEM备份 |
| persist.img | 未知格式 | 非ext4/erofs/f2fs，待分析 |
| xtcdata.img | ext4（600MB） | 含系统logcat日志 |
| boot_v101.img | 标准ANDROID!格式 | 明文boot，可用于Magisk修补 |
| abl_v101.img | 标准ARM ELF | 代码段全加密，证书区域明文 |
| vbmeta_v101.img | 标准AVB0 | 明文vbmeta |
| super.img | 3.5GB | 明文super，可解包 |

#### 小天才系统应用包名

| 包名 | 作用 |
|---|---|
| **com.xtc.i3launcher** | 桌面启动器（家长验证弹窗可能在此） |
| **com.xtc.xws** | 小天才穿戴服务（和家长端通信，绑定校验可能在此） |
| **com.xtc.datacenter** | 数据中心（含蓝牙服务） |
| com.xtc.setting | 设置 |
| com.xtc.theme | 主题 |
| com.xtc.absystemupdate | 系统更新 |

### 3.8 技术发现

1. **abl 代码段全加密**：从0x1000开始144KB全部加密，无法静态分析或patch
2. **新版 LP metadata**（major=10/minor=2）中 `LpExtent.physical_sector` 是 **4字节在偏移12**，phys_offset = physical_sector × 512
3. super 内有8个逻辑分区（_a和_b各4个），_b槽位全空
4. 设备存储是 **eMMC**（mmcblk0），不是 UFS
5. 设备内部代号是 **monaco**
6. **v1.0.1 保留 QMMI 漏洞**：misc 写 ffbm-02 可进工厂模式获 adb root（后续版本已砍掉）
7. **fastboot getvar 无 unlocked 变量**：小天才 abl 可能不使用标准解锁机制
8. **作者方案最终状态 secure=no**：不只是 unlocked，接近工程/调试模式

---

## 四、项目进度

### 已完成 ✅

| # | 任务 | 产出 |
|---|---|---|
| 1 | 工作区文件梳理 | 三套文件定位 |
| 2 | 原版固件加密状态确认 | 全加密，无法去头还原 |
| 3 | 作者 boot.img 解包 | Magisk修补确认，fstab修改确认 |
| 4 | 作者 vbmeta 分析 | RSA4096自定义重签确认 |
| 5 | 作者 super.img 解包 | 4个ext4分区提取成功 |
| 6 | 第一/二阶段对比报告 | 两份分析报告 |
| 7 | v1.0.1 完整分区表获取 | 77个分区定位 |
| 8 | v1.0.1 关键分区dump | boot/abl/vbmeta/super/misc/devinfo等10个 |
| 9 | ffbm-02 = QMMI入口确认 | 高通工厂模式命令 |
| 10 | abl 深度分析 | 代码段全加密，证书链含"General Use XTC Key 1" |
| 11 | 作者完整流程还原 | 三阶段：EDL刷入→fastboot boot TWRP→sideload Dm.zip |
| 12 | Dm.zip 分析 | AnyKernel3 Magisk安装包，含magiskboot和AVB密钥 |
| 13 | TWRP recovery 分析 | 标准boot格式，与作者boot同一内核 |
| 14 | fastboot getvar 分析 | 无unlocked变量，secure=yes |
| 15 | dip/limits/frp 检查 | dip/limits全零，frp有数据（非BL锁） |
| 16 | 解锁机制推导 | abl自动写devinfo / abl patch工程模式 / misc触发 |

### 进行中 / 待完成 ⏳

| # | 任务 | 优先级 | 说明 |
|---|---|---|---|
| 17 | **QMMI下手动写devinfo测试解锁** | **最高** | 构造高通标准devinfo（is_unlocked=1），重启看是否显示unlocked |
| 18 | 制作v1.0.1 Magisk patch boot | 高 | 参考Dm.zip做法，对v1.0.1明文boot做Magisk修补 |
| 19 | 自定义RSA4096重签v1.0.1 vbmeta | 高 | 用avbtool生成包含修改后boot哈希的vbmeta |
| 20 | 解锁后刷入修改boot+vbmeta测试 | 高 | QMMI下dd刷入，重启验证能否启动并获root |
| 21 | dump v1.0.1 super并解包 | 中 | 含system/vendor所有APK，定位家长验证 |
| 22 | 触发家长验证弹窗抓logcat | 中 | QMMI或正常模式下adb logcat（不需root） |
| 23 | 深入分析persist.img | 中 | 未知格式，可能存绑定状态 |
| 24 | 反编译家长验证相关APK | 中 | com.xtc.i3launcher / com.xtc.xws |
| 25 | 家长验证绕过方案 | 低 | Magisk模块 / LSPosed hook / 修改配置 |

---

## 五、后续安排

### 第一阶段：解锁 BL（当前重点）

1. **QMMI 下手动写 devinfo 测试**（零风险，可随时恢复）：
   ```bash
   # 备份
   dd if=/dev/block/by-name/devinfo of=/sdcard/devinfo_backup.bin
   # 构造高通标准 devinfo（is_unlocked=1）
   echo -ne 'DEVI' | dd of=/dev/block/by-name/devinfo bs=1 seek=0 count=4 conv=notrunc
   echo -ne 'RNFO' | dd of=/dev/block/by-name/devinfo bs=1 seek=4 count=4 conv=notrunc
   echo -ne '\x01\x00\x00\x00' | dd of=/dev/block/by-name/devinfo bs=1 seek=8 count=4 conv=notrunc
   echo -ne '\x01\x00\x00\x00' | dd of=/dev/block/by-name/devinfo bs=1 seek=12 count=4 conv=notrunc
   # 重启到 bootloader 检查状态
   reboot bootloader
   fastboot getvar secure
   fastboot getvar unlocked
   ```
2. 如果解锁成功 → 制作 Magisk patch boot + 重签 vbmeta → fastboot flash 刷入
3. 如果解锁失败 → 分析小天才自定义 devinfo 结构，或尝试其他偏移

### 第二阶段：获取 root 权限

1. 对 v1.0.1 明文 boot.img 做 Magisk 修补（参考 Dm.zip 中的 magiskboot）
2. 用 avbtool 自定义 RSA4096 重签 vbmeta
3. 解锁状态下 fastboot flash boot / vbmeta
4. 重启验证 Magisk 权限

### 第三阶段：定位家长验证

1. dump v1.0.1 super → 解包 system/vendor
2. 完整应用列表 + 反编译 com.xtc.i3launcher / com.xtc.xws
3. 正常模式下 adb logcat 抓家长验证弹窗日志（不需root）
4. 分析验证逻辑（本地校验 or 联网校验）

### 第四阶段：家长验证绕过

1. 方案A：Magisk 模块停止/替换验证服务
2. 方案B：LSPosed hook 验证 API
3. 方案C：修改 persist/xtcdata 中的绑定状态
4. 方案D：如果联网校验，模拟验证通过

---

## 六、关键命令速查

### QMMI 模式入口

```bash
# 正常模式下（如有adb）写入misc
adb shell "echo -ne 'ffbm-02' | dd of=/dev/block/by-name/misc bs=1 count=7 conv=notrunc"
adb reboot
# 重启后自动进入 QMMI 工厂模式，adb root 可用
```

### QMMI 模式下 dump 分区

```bash
adb root
adb shell
# 查看分区表
ls -la /dev/block/by-name/
# dump单个分区到设备
dd if=/dev/block/mmcblk0pXX of=/sdcard/xxx.img
# 流式直读到PC（大分区推荐）
adb exec-out dd if=/dev/block/mmcblk0p46 > super_v101.img
```

### 手动写 devinfo 测试解锁

```bash
# 见第五阶段第一阶段的完整命令
# 恢复：dd if=/sdcard/devinfo_backup.bin of=/dev/block/by-name/devinfo
```

### AVB 自定义签名

```bash
# 生成RSA4096密钥
openssl genrsa -out avb_private.pem 4096
# 重签vbmeta（需avbtool.py）
python avbtool.py make_vbmeta_image \
  --output vbmeta_signed.img \
  --key avb_private.pem \
  --algorithm SHA256_RSA4096 \
  --flag 0 \
  --include_descriptors_from_image boot_modified.img
```

### super 解包

```bash
python H:\xtcz10check\unpack_work\extract_super2.py
# 输入：super.img → 输出：4个ext4分区
```

---

## 七、风险提示

1. **刷写有风险**：修改后的镜像刷入可能导致无法启动，务必保留原版加密线刷包，随时可EDL救砖
2. **abl 刷错风险最高**：abl 损坏可能导致无法进 EDL，v1.0.1 复刻时**不要修改 abl**，优先手动写 devinfo
3. **手动写 devinfo 零风险**：已备份全零 devinfo，随时可 dd 恢复，即使解锁失败也不影响正常启动
4. **QMMI 模式是临时的**：重启后 misc 命令被清除，需要重新写入
5. **不要跨版本混刷**：v2.8.1 镜像不能直接刷到 v1.0.1（内核/vendor/modem 不匹配）
6. **家长验证可能云端校验**：即使本地绕过，联网后后端可能根据设备SN重新要求验证

---

## 八、参考资料

- 作者完整工具包：`H:\xtcz10check\offline-files\`
- 作者镜像目录：`H:\xtcz10check\2\250803\`
- 第一阶段报告：`H:\xtcz10check\ND03解锁镜像对比分析报告.md`
- 第二阶段报告：`H:\xtcz10check\ND03镜像解包对比分析报告.md`
- v1.0.1 分区表：`F:\xtcz10check\v1.0.1\分区.txt`
- v1.0.1 dump 镜像：`H:\xtcz10check\v1.0.1_dump\`
- fastboot getvar 输出：`F:\xtcz10check\fastboot getvar.txt`
- 其他分区检查：`F:\xtcz10check\查看其他分区.txt`
- Android AVB 工具：AOSP `external/avb/avbtool.py`
- 高通 EDL 工具：bkerler/edl（开源 Firehose 读写工具）
- AnyKernel3：osm0sis/AnyKernel3（GitHub）

---

## 六、核心技术工具链（已完成）

### 6.1 固件全量解密：`tools/xtc_fw_decrypt.py`

```bash
# 解密整个固件目录
python tools/xtc_fw_decrypt.py ND03_V1.0.1 decrypted_images/v1.0.1

# 解密单个文件
python tools/xtc_fw_decrypt.py abl.elf abl_decrypted.elf
```

- 算法：固定 XOR 密钥流（256 字节 key_table 双重 XOR，周期 16384 字节）
- 规则：≤32KB 全文 XOR，>32KB 仅前 32 字节 XOR
- 支持大文件流式处理（避免 MemoryError）
- 自动检测已明文文件，magic 验证

### 6.2 abl 解压：`tools/abl_unpack.py`

```bash
# 解压单个 abl（自动检测加密并解密）
python tools/abl_unpack.py decrypted_images/v1.0.1/abl.elf unpacked_abl/v1.0.1

# 批量解压目录
python tools/abl_unpack.py decrypted_images/v1.0.1 unpacked_abl/v1.0.1
```

输出：
- `*_pe32.bin` — 解压后的 PE32+ ARM64 镜像（可直接拖进 Ghidra）
- `*_strings.txt` — 可读字符串列表
- `*_info.txt` — 结构信息（ELF/FV/FFS/Section/PE 头）

### 6.3 解密验证：`tools/verify_decrypt.py`

对比解密后的镜像与设备 dump，验证解密正确性。

---

## 七、当前研究重点（abl 解锁机制代码级分析）

### 已确认事实

1. **release abl 本身就有解锁代码路径**：`"State: Unlocked, AvbSlotVerify returned %a, continue boot"` 在三个版本中都存在
2. **解锁状态读取协议**：`ops->read_is_device_unlocked` 是 abl 内部的函数指针协议
3. **abl 内部有写 devinfo 的函数**：`XTCWriteDevInfo`，涉及 "user key" 概念
4. **标准 fastboot 解锁命令被移除**：`"Unsupport unlock bootloader: %r"` 是 stub
5. **作者 abl 是官方 UserDebug 构建**：不是手工 patch，解锁能力是"构建变体"属性

### 待解决问题（需要 Ghidra 分析）

1. `read_is_device_unlocked` 从哪里读取解锁状态？（devinfo 分区？某个寄存器？某个 eMMC 分区？）
2. devinfo 结构的字段偏移和 magic 是什么？（为什么我们手动写标准 devinfo 不生效？）
3. `XTCWriteDevInfo` 的 "user key" 是什么？（签名？序列号？）
4. UserDebug 构建和 User 构建在解锁判定逻辑上有什么差异？
5. 是否存在其他进入 unlocked 状态的路径（不依赖 devinfo）？

### 下一步

- 安装 Ghidra，加载 `unpacked_abl/v1.0.1/abl_pe32.bin`（ImageBase=0，ARM64）
- 定位 `"State: Unlocked..."` 字符串的引用，回溯到解锁判定函数
- 定位 `read_is_device_unlocked` 的实现，追踪状态来源
- 定位 `XTCWriteDevInfo` 函数，理解 devinfo 写入协议

---

## 八、已验证死路（避免重复尝试）

| 方案 | 结果 | 原因 |
|---|---|---|
| 手动写标准 devinfo (is_unlocked=1) | 不生效 | devinfo 格式/位置可能不是标准高通格式 |
| devinfo 全写 0xFF | 不生效 | 同上 |
| fastboot oem/flashing unlock | unknown command | 小天才移除了标准解锁接口 |
| AVB 重命名漏洞 (vbmeta→xbmeta) | 直接到 bootloader | 无 NO_AVB 回退路径 |
| flags=2 vbmeta | 原理上不可能 | flags 在被签名区域内，自校验失配 |
| 手动制作 Magisk boot | 8个致命缺陷 | 需要严格匹配版本和格式 |
| 方案A（刷作者abl获unlocked后刷回原版） | 状态不保留 | unlocked 状态由 abl 运行时判定，不持久化 |
| 跨版本混刷 (v2.8.1 abl + v1.0.1 system) | 卡 logo | 版本不匹配 |
| CVE-2026-24088 公开利用链 | 不适用 | ND03 无 efisp/gbl 分区，Android 11 时代 ABL |

---

*最后更新：2026-10-07*
