# 操作手册：方向 1 —— 实测 `flashing unlock` 是否持久（设备可用时执行）

> 适用设备：小天才 Z10（ND03 / `monaco_go`）已 root 的 QMMI 环境 + EDL 访问
> 前置结论（本文不做重复论证，见 `分析报告_解锁后续方向与密钥依赖评估_DeepSeek.md`）：
> - 私钥拿不到，但解锁**不需要私钥**：需要的是 ①已签名的宽松 abl（作者 ND08 UserDebug，已有 `offline-files\abl_a.img`）②授权位 `IsAllowUnlock`（= abl 状态结构 `0x75390+0xC`，由 `oem device-info` 打印，来源为 **FRP 分区**）③设备自己写 RPMB。
> - stock abl **没有** unlock 代码，作者 abl 有完整实现；`flashing unlock` 的每条分支回显字符串都已解码，可直接当诊断仪表。
> 目标：用最小改动判定"**打开授权位 + 宽松 abl** 能否让解锁持久化"。
> 风险：中等，全程 EDL 可回滚。**红线见 §7。**

---

## ⚠️ 更新（先读这段）：本手册的"解锁持久化"前提已被推翻

设备实测 + 反汇编复核（详见 `reports/分析报告_IsAllowUnlock答疑与替代root方案_DeepSeek.md`）：

1. **作者 abl 结构性无法持久解锁**：`is_unlocked()` 包装器（0x27060）被桩强制恒返回 1，而解锁处理器在"当前值 == 请求值"时打印 `Device already : %a` 后**提前返回、不写任何东西** ⇒ `flashing unlock` 永远走这条捷径；`flashing lock` 能到写入路径但要过**按键确认界面**（Z10 无音量键）且方向相反；lock→unlock 同样因桩而不可能。
2. **`IsAllowUnlock` 不值得再追**：`.data` 初值即 0、`.text` 无写入点、`frp/devinfo/persist/xtcinfo/misc` 内没有任何可写的明文授权位（已全部扫描）。
3. **改走"不解锁也能 root"**：同族 iMoo/ReX 公开验证过的方法——把 Magisk 修补镜像刷进 **`recovery_a`**，并用 `misc` 的 BCB 命令 **`boot-recovery`** 引导（已从其 `misc.bin` 逐字节确认）。产物已备好：`v1.0.1_dump\misc_boot_recovery.img`、`v1.0.1_dump\vbmeta_a_flags3_65536.img`。

⇒ **§3（P2 FRP）与 §5（P4 改 FRP allow 位）作废**；下面的备份/写入/回滚步骤仍有效，只是目标从"解锁"改为"刷 recovery + misc 引导"。另注意：`vbmeta_v101*.img` 是 65,618 字节（尾部混入了 `dd` 日志文本），比分区多 82 字节，**不要直接刷**，改用新生成的 65,536 字节版本。

---

## 0. 环境与已知怪癖

| 项 | 值 |
|---|---|
| 工具 | `H:\xtcz10check\edl_tool\edlclient\edl.py`（bkerler/edl） |
| 编程器 | `H:\xtcz10check\decrypted_images\v1.0.1\prog_firehose_ddr.elf`（548,864 B，明文，v1.0.1/v2.8.1 通用） |
| 作者 abl 分区镜像 | `H:\xtcz10check\offline-files\abl_a.img`（1,048,576 B = 2048 扇区，正好一整个分区） |
| 当前 misc 内容 | `ffbm-02`（工厂模式 BCB），已 dump 为 `v1.0.1_dump\misc.img` |
| 已 dump 备份 | `abl_a_v101_backup.img`、`misc.img`、`devinfo.img`、`persist.img`、`vbmeta_v101.img`、`vbmeta_system_v101.img`、`super.img`、`xtcinfo.img`、`xtcdata.img` |

**已知怪癖（务必遵守）**
1. `edl.py` 连接时若一直打点（`....`）＝主机没拿到设备：用 Zadig（或仓库 `edl_tool\Drivers\Windows`）把 `05c6:9008` 绑成 **WinUSB/libusb**，不要用 Qualcomm HS-USB QDLoader 的 COM 口。
2. 本机特性：**执行若干命令后必须退出 EDL 重进**，重新加载 firehose。因此把备份/写入分成**小批次**，每批结束后重新进 EDL。
3. **读写都必须带 `--loader=`**，避免自动探测失败。
4. 不要写短文件到 `misc`（见 §3.2），否则 BCB 命令会与旧字节粘连。

---

## 1. 分区扇区表（来自 `decrypted_v1.0.1\rawprogram0.xml`，LUN0）

| 分区 | start_sector | sectors | 大小 | 用途 |
|---|---|---|---|---|
| `frp` | **9340816** | **1024** | 512 KB | **授权位所在，最关键** |
| `devinfo` | 1373184 | 8 | 4 KB | 已确认全零（状态不在此） |
| `misc` | 9337104 | 2048 | 1 MB | BCB，控制进 fastboot |
| `abl_a` | 1362944 | 2048 | 1 MB | 当前启动槽（待替换为作者 abl） |
| `abl_b` | 1364992 | 2048 | 1 MB | 备用槽（保持 stock，退路） |
| `vbmeta_a` | 1377296 | 128 | 64 KB | |
| `vbmeta_b` | 1377424 | 128 | 64 KB | |
| `vbmeta_system_a` | 1377552 | 128 | 64 KB | |
| `vbmeta_system_b` | 1377680 | 128 | 64 KB | |
| `kmsgdumper` | 9330960 | 4096 | 2 MB | 启动日志（诊断用） |
| `logfs` | 9687728 | 4096 | 2 MB | 日志 |
| `logdump` | 9695920 | 126976 | 62 MB | 日志 |

---

## 2. 阶段 P1：只读备份（零风险，先做）

```powershell
cd H:\xtcz10check
$L = "decrypted_images\v1.0.1\prog_firehose_ddr.elf"

# 批次 1：最关键的小分区
py -3 edl_tool\edlclient\edl.py rs 9340816  1024 v1.0.1_dump\frp_backup.img            --loader=$L
py -3 edl_tool\edlclient\edl.py rs 1373184     8 v1.0.1_dump\devinfo_backup2.img      --loader=$L
py -3 edl_tool\edlclient\edl.py rs 9337104  2048 v1.0.1_dump\misc_backup.img          --loader=$L
# 退出 EDL，重进，再执行批次 2
py -3 edl_tool\edlclient\edl.py rs 1362944  2048 v1.0.1_dump\abl_a_backup.img         --loader=$L
py -3 edl_tool\edlclient\edl.py rs 1364992  2048 v1.0.1_dump\abl_b_backup.img         --loader=$L
# 退出 EDL，重进，再执行批次 3（vbmeta ×4 + 日志）
py -3 edl_tool\edlclient\edl.py rs 1377296   128 v1.0.1_dump\vbmeta_a_backup.img      --loader=$L
py -3 edl_tool\edlclient\edl.py rs 1377424   128 v1.0.1_dump\vbmeta_b_backup.img      --loader=$L
py -3 edl_tool\edlclient\edl.py rs 9330960  4096 v1.0.1_dump\kmsgdumper_backup.img    --loader=$L
```

**校验**（大小必须等于 sectors×512）：

```powershell
Get-ChildItem v1.0.1_dump\*_backup*.img | Select-Object Name,Length
# frp_backup.img 应为 524288；misc/abl 各 1048576；devinfo 4096；vbmeta 各 65536
```

> 若 `rs` 报错或返回全零：先确认 `frp` 是否落在 LUN0（本机 XML 是 `physical_partition_number="0"`），必要时加 `--lun=0`。

---

## 3. 阶段 P2：解析 FRP，确定授权位 ❌ 已作废（见顶部更新；FRP +0x08 已被实测否定）

```powershell
py -3 deep_check\frp_tool.py analyze v1.0.1_dump\frp_backup.img
```

判读要点：
- 反汇编证据：`oem device-info` 在 0x34EE8 用 `ldr w2,[x23,#0xC]`（x23 = abl 状态结构 0x75390）打印 `IsAllowUnlock is %d`；而该值预期来自 FRP 分区（`"frp"` 宽字符串在 0x55E1A，由设备信息/解锁路径引用）。
- 预期 FRP 里有一个 u32 标志：**`1` = 允许解锁，`0` = 不允许**。候选偏移：**+0x08**（历史推断，本次待证）。
- 记录：非零 u32 的**所有**偏移与值；若 +0x08 已是 1，则 P4 可跳过。

**技巧**：`oem device-info` 的值就是同一个字段（§5 会打印），所以用"FRP dump 的候选偏移"与"设备打印的 IsAllowUnlock"做对照，即可反推真实偏移。

---

## 4. 阶段 P3：刷作者 abl 进入 fastboot（只读判定）

### 4.1 生成 misc 镜像（进入 fastboot 用）

```powershell
# 用原始 misc 备份做底，只改 BCB 命令 → 避免短写粘连
py -3 deep_check\make_misc_bcb.py boot-fastboot v1.0.1_dump\misc_boot_fastboot.img --from v1.0.1_dump\misc_backup.img
# 复核：前 16 字节应为 62 6F 6F 74 2D 66 61 73 74 62 6F 6F 74 00 00 00
```

### 4.2 写入（EDL）

```powershell
$L = "decrypted_images\v1.0.1\prog_firehose_ddr.elf"
py -3 edl_tool\edlclient\edl.py ws 1362944 offline-files\abl_a.img                         --loader=$L   # 作者 abl → A 槽
py -3 edl_tool\edlclient\edl.py ws 9337104 v1.0.1_dump\misc_boot_fastboot.img              --loader=$L   # misc: boot-fastboot
py -3 edl_tool\edlclient\edl.py reset --resetmode=reset --loader=$L
```

### 4.3 只读判定（**不改任何东西**，这一步先拿基线）

设备应进入 fastboot（作者 abl）：

```powershell
fastboot devices
fastboot oem device-info            # 期望看到 IsAllowUnlock / Device unlocked / Device critical unlocked
fastboot flashing get_unlock_ability # 作者 abl 专有；回显 "get_unlock_ability: %d"
```

**记录三个值**：
- `Device unlocked: ` ?
- `IsAllowUnlock is ` ?
- `get_unlock_ability: ` ?

---

## 5. 阶段 P4：如需要，翻 FRP 授权位（A/B 对照实验） ❌ 已作废（FRP 不是明文授权位；改用 §R1/R2 的 recovery 路线）

仅当 P4.3 显示 `IsAllowUnlock is 0` 时执行。

```powershell
# 1) 生成改好的副本（示例：+0x08 置 1；偏移以 P2 的实际分析为准）
py -3 deep_check\frp_tool.py set v1.0.1_dump\frp_backup.img v1.0.1_dump\frp_allow1.img 0x08 1
# 2) 复核副本内容与大小
py -3 deep_check\frp_tool.py analyze v1.0.1_dump\frp_allow1.img
Get-Item v1.0.1_dump\frp_allow1.img | Select-Object Length     # 必须 524288
# 3) 写回 FRP
$L = "decrypted_images\v1.0.1\prog_firehose_ddr.elf"
py -3 edl_tool\edlclient\edl.py ws 9340816 v1.0.1_dump\frp_allow1.img --loader=$L
# 4) 回读校验（应与写入一致）
py -3 edl_tool\edlclient\edl.py rs 9340816 1024 v1.0.1_dump\frp_verify.img --loader=$L
```

重启回 fastboot（misc 仍是 `boot-fastboot`），再执行 §4.3 的两条命令：
- **`IsAllowUnlock` 变成 1** ⇒ 证实"FRP → 授权位"链路，**授权门已打开**，进 P5。
- 仍为 0 ⇒ 授权位不来自 FRP（或需要别的条件），停止改 FRP，回滚（§7），转方向 2。

---

## 6. 阶段 P5：执行解锁 + 回显判读表

```powershell
fastboot flashing unlock
```

**回显判读表（本轮反汇编得到的原文，逐条对应代码分支）**：

| 设备回显 | 含义 | 下一步 |
|---|---|---|
| `Device already : unlocked` | 已经是解锁状态 | 直接进 P6 验证持久性 |
| `Flashing Unlock is not allowed` | **授权门未过**（`0x7539C == 0`） | 回 P4 改 FRP；若 FRP 无效 → 转方向 2 |
| `Command not support: the display is not enabled` | 显示未使能，命令被拒 | 点亮屏幕后重试；或看是否是 display 分支导致 |
| `Display is enabled` / `Display is not supported` | 调试/状态输出 | 记录，用于判断走了哪条分支 |
| `Set device unlocked failed: 0x...` | 走到了写入步骤但 provider 拒绝 | **真正的坏消息**：记下状态码，转方向 2（provider/TZ 侧） |
| 要求按 VOL/Power 确认的提示（见 `Do not unlock the bootloader` 等 UI 文案） | 需要按键确认 | **见风险 R1** |
| `OKAY` / 无错误 | 写入成功 | 进 P6 |

> 作者 abl 里存在标准解锁确认 UI 文案（"Press the Volume keys to select whether to unlock the bootloader, then the Power Button to continue" / "DO NOT UNLOCK THE BOOTLOADER"），而 **Z10 没有音量键**。若 P5 卡在按键确认，见 §8 风险 R1 的处理顺序。

---

## 7. 阶段 P6：验证持久性（本实验的核心）

```powershell
# 1) 恢复 misc 为原始内容（去掉 boot-fastboot）
$L = "decrypted_images\v1.0.1\prog_firehose_ddr.elf"
py -3 edl_tool\edlclient\edl.py ws 9337104 v1.0.1_dump\misc_backup.img --loader=$L
# 2) 把 stock abl 写回 A 槽（B 槽本来就是 stock，保持不动）
py -3 edl_tool\edlclient\edl.py ws 1362944 v1.0.1_dump\abl_a_backup.img --loader=$L
py -3 edl_tool\edlclient\edl.py reset --resetmode=reset --loader=$L
```

然后**再次进入 fastboot**（再写一次 `boot-fastboot` 的 misc，或用 QMMI 的方式），用 **stock abl** 读取状态：

```powershell
fastboot oem device-info     # stock abl 也有这条命令（字符串 "IsAllowUnlock is %d" 在两版都存在）
```

| `Device unlocked:` | 结论 |
|---|---|
| `true` | ✅ **解锁持久化成功**（全程未使用任何私钥）→ 进入"刷 Magisk / 关 AVB 校验"阶段 |
| `false` | ❌ 未持久：授权位不是唯一门槛，或 TZ 拒绝写入 → 转方向 2（provider / `0x42ED0` 提供者表 / `C0DD69AC` 协议） |

补充读数（Android 侧，若能起系统）：`adb shell getprop ro.boot.verifiedbootstate`、`ro.boot.flash.locked`。

---

## 8. 风险与处理

| 编号 | 风险 | 处理 |
|---|---|---|
| **R1** | `flashing unlock` 需要 VOL/Power 按键确认，而 Z10 无音量键 | 依次尝试：① 先 `fastboot flashing get_unlock_ability` 看是否有非交互路径；② 试 `fastboot flashing unlock_critical`；③ 试 `fastboot oem unlock`（作者 abl 带 5 个 `oem` 命令）；④ 检查 `IsAllowUnlock=1` 时是否跳过确认；⑤ 若确认必须物理键，则本方案卡死，转方向 2/3 |
| **R2** | misc 写入不当导致 BCB 粘连、无法进 fastboot | 只用 `make_misc_bcb.py` 生成**整分区大小**镜像；异常时写回 `misc_backup.img` |
| **R3** | 刷 abl 后不启动 | B 槽保持 stock；用 EDL 把 `abl_a_backup.img` 写回即恢复 |
| **R4** | FRP 写入后设备行为异常（FRP 也参与恢复出厂/防回滚） | 只需写回 `frp_backup.img` 即可回滚（EDL 写分区不受签名限制） |
| **R5** | RPMB 相关 | **绝不**直写 RPMB、**绝不**使用 `edl.py provision` / `Provision RPMB`（一次性，砖机风险） |

---

## 9. 红线（不可越界）

1. 不做 `edl.py provision`、不碰 RPMB。
2. 不改 GPT / 分区表。
3. 一次只改一个变量，改前必须有该分区的只读备份。
4. `misc`、`frp`、`abl_a` 三个分区任何写入前，都要先确认备份文件大小 = 扇区数×512。
5. 每次写完都**回读校验**（`rs` 到新文件，与写入文件逐字节比较）。

---

## 10. 执行记录表（照抄填）

| 步骤 | 命令/操作 | 回显或结果 | 结论 |
|---|---|---|---|
| P1 | frp_backup.img 大小 | | |
| P1 | misc/devinfo/abl 备份大小 | | |
| P2 | FRP 非零 u32 偏移与值 | | 候选 allow = |
| P3 | `oem device-info` | Device unlocked=? / IsAllowUnlock=? | |
| P3 | `flashing get_unlock_ability` | | |
| P4 | 写 FRP 后 `IsAllowUnlock` | | FRP 是否为来源 |
| P5 | `flashing unlock` 回显 | | |
| P6 | 刷回 stock 后 `Device unlocked` | | **持久?** |

---

### 附：本文用到的脚本

| 脚本 | 用途 |
|---|---|
| `deep_check/frp_tool.py` | FRP dump 结构分析；把某个偏移的 u32 改成指定值（**输出到新文件**，不原地改） |
| `deep_check/make_misc_bcb.py` | 生成整分区大小的 misc 镜像（BCB 命令：`boot-fastboot` / `ffbm-02` / 空） |
| `deep_check/check_abl_unlock_stub.py` | 任何同族 abl 的解锁面秒筛（构建类型 / IsUnlocked 桩 / 命令面） |
| `deep_check/check_frp_reader.py`、`check_allowunlock_print.py` | 本次反汇编证据的复现脚本（FRP 读取路径、`IsAllowUnlock` 打印点） |
