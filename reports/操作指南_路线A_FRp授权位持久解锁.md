# 路线 A：FRP 授权位 + 作者 abl 持久解锁 - 操作指南

> 目标：通过设置 FRP 分区的 IsAllowUnlock 授权位，配合作者 UserDebug abl 的 `flashing unlock` 命令，实现持久化 Bootloader 解锁
> 风险：低。所有分区写入都能用 EDL 恢复。`flashing unlock` 会清 userdata（可接受）
> 前置条件：EDL 可用（数据线按钮+电源键进9008），Zadig 已把 05c6:9008 绑成 WinUSB

---

## 阶段 0：准备工作

### 0.1 确认工具就绪

```powershell
cd H:\xtcz10check

# 确认 EDL 工具
dir edl_tool\edlclient\edl.py

# 确认 firehose 编程器
dir decrypted_images\v1.0.1\prog_firehose_ddr.elf

# 确认作者 abl
dir offline-files\abl_a.img

# 确认脚本
dir scripts\frp_tool.py
dir scripts\make_misc_bcb.py
```

### 0.2 确认设备可进 EDL

1. 关机
2. 按住数据线按钮不放
3. 按电源键开机
4. 设备应进入 9008 模式（设备管理器可见 Qualcomm HS-USB QDLoader 或 WinUSB）

---

## 阶段 1：EDL 备份关键分区（零风险，必须先做）

### 1.1 进入 EDL 模式

关机 → 按住数据线按钮 → 按电源键 → 进入 9008

### 1.2 备份 FRP 分区（最关键）

```powershell
cd H:\xtcz10check
$L = "decrypted_images\v1.0.1\prog_firehose_ddr.elf"

py -3 edl_tool\edlclient\edl.py rs 9340816 1024 v1.0.1_dump\frp_backup.img --loader=$L
```

**校验**：
```powershell
Get-Item v1.0.1_dump\frp_backup.img | Select-Object Length
# 应为 524288 (512 KB = 1024 扇区 × 512)
```

### 1.3 备份其他关键分区（分批次，每批后重进 EDL）

**批次 1（FRP 之后）**：
```powershell
py -3 edl_tool\edlclient\edl.py rs 1373184 8 v1.0.1_dump\devinfo_backup.img --loader=$L
py -3 edl_tool\edlclient\edl.py rs 9337104 2048 v1.0.1_dump\misc_backup.img --loader=$L
```

**退出 EDL，重进，批次 2**：
```powershell
py -3 edl_tool\edlclient\edl.py rs 1362944 2048 v1.0.1_dump\abl_a_backup.img --loader=$L
py -3 edl_tool\edlclient\edl.py rs 1364992 2048 v1.0.1_dump\abl_b_backup.img --loader=$L
```

**退出 EDL，重进，批次 3**：
```powershell
py -3 edl_tool\edlclient\edl.py rs 1377296 128 v1.0.1_dump\vbmeta_a_backup.img --loader=$L
py -3 edl_tool\edlclient\edl.py rs 1377424 128 v1.0.1_dump\vbmeta_b_backup.img --loader=$L
```

### 1.4 校验所有备份

```powershell
Get-ChildItem v1.0.1_dump\*_backup*.img | Select-Object Name, Length
```

预期大小：
- frp_backup.img = 524288
- devinfo_backup.img = 4096
- misc_backup.img = 1048576
- abl_a_backup.img = 1048576
- abl_b_backup.img = 1048576
- vbmeta_a_backup.img = 65536
- vbmeta_b_backup.img = 65536

---

## 阶段 2：分析 FRP 分区，定位 IsAllowUnlock

### 2.1 分析 FRP 内容

```powershell
py -3 scripts\frp_tool.py analyze v1.0.1_dump\frp_backup.img
```

**重点关注**：
- 是否全零？（如果全零，候选偏移 +0x08 的值为 0）
- 候选偏移 +0x08 的当前值
- 所有非零 u32 值的位置

### 2.2 根据分析结果决定下一步

**情况 A：FRP 全零或 +0x08 = 0**
→ 直接进入阶段 3，在 +0x08 写入 1 测试

**情况 B：+0x08 已经是 1**
→ 授权位已打开！直接跳到阶段 4（刷作者 abl + flashing unlock）

**情况 C：+0x08 不是 0/1，或有其他非零值**
→ 需要进一步分析，记录所有非零偏移，准备变异测试

---

## 阶段 3：变异测试 - 找到 IsAllowUnlock 偏移（用原版 abl，零风险）

> 原理：原版 abl 的 `oem device-info` 会打印 `IsAllowUnlock is %d`，我们改 FRP 后看打印值是否变化

### 3.1 生成修改后的 FRP（候选偏移 +0x08 置 1）

```powershell
py -3 scripts\frp_tool.py set v1.0.1_dump\frp_backup.img v1.0.1_dump\frp_allow1_0x08.img 0x08 1
```

### 3.2 写入修改后的 FRP

进入 EDL：
```powershell
$L = "decrypted_images\v1.0.1\prog_firehose_ddr.elf"
py -3 edl_tool\edlclient\edl.py ws 9340816 v1.0.1_dump\frp_allow1_0x08.img --loader=$L
```

### 3.3 生成进入 fastboot 的 misc

```powershell
py -3 scripts\make_misc_bcb.py boot-fastboot v1.0.1_dump\misc_boot_fastboot.img --from v1.0.1_dump\misc_backup.img
```

### 3.4 写入 misc 并重启

```powershell
py -3 edl_tool\edlclient\edl.py ws 9337104 v1.0.1_dump\misc_boot_fastboot.img --loader=$L
py -3 edl_tool\edlclient\edl.py reset --resetmode=reset --loader=$L
```

### 3.5 设备应进入 fastboot（原版 abl）

```powershell
fastboot devices
fastboot oem device-info
```

**观察输出**：
- 如果看到 `IsAllowUnlock is 1` → ✅ 找到正确偏移！授权门已打开
- 如果还是 `IsAllowUnlock is 0` → ❌ +0x08 不对，需要试其他偏移

### 3.6 如果 +0x08 不对，尝试其他候选偏移

根据阶段 2 的分析结果，依次尝试非零 u32 附近的偏移，或常见偏移：
- 0x00, 0x04, 0x08, 0x0C, 0x10
- 0x100, 0x108, 0x200, 0x208

每次测试：
1. 恢复原 FRP：`edl ws 9340816 frp_backup.img`
2. 生成新偏移的修改版：`frp_tool.py set frp_backup.img frp_test.img <offset> 1`
3. 写入并重启进 fastboot
4. `fastboot oem device-info` 看 IsAllowUnlock

### 3.7 找到正确偏移后，恢复原 FRP

```powershell
# 进入 EDL
py -3 edl_tool\edlclient\edl.py ws 9340816 v1.0.1_dump\frp_backup.img --loader=$L
```

---

## 阶段 4：刷作者 abl + 执行 flashing unlock

### 4.1 确认授权位已打开

在原版 abl 下：
```powershell
fastboot oem device-info
# 应显示 IsAllowUnlock is 1
```

### 4.2 刷作者 abl 到 A 槽

进入 EDL：
```powershell
$L = "decrypted_images\v1.0.1\prog_firehose_ddr.elf"
py -3 edl_tool\edlclient\edl.py ws 1362944 offline-files\abl_a.img --loader=$L
```

### 4.3 写入 FRP 授权位（如果还没写）

```powershell
py -3 edl_tool\edlclient\edl.py ws 9340816 v1.0.1_dump\frp_allow1_0x08.img --loader=$L
```

### 4.4 写入 misc 进 fastboot 并重启

```powershell
py -3 edl_tool\edlclient\edl.py ws 9337104 v1.0.1_dump\misc_boot_fastboot.img --loader=$L
py -3 edl_tool\edlclient\edl.py reset --resetmode=reset --loader=$L
```

### 4.5 在作者 abl 下执行解锁

```powershell
fastboot devices
fastboot oem device-info
# 记录：Device unlocked, IsAllowUnlock, Device critical unlocked

fastboot flashing get_unlock_ability
# 记录返回值

fastboot flashing unlock
# 可能需要屏幕确认（如果有提示）
# 期望输出：OKAY 或 "Device already : unlocked!"

fastboot oem device-info
# 再次记录状态
```

**关键观察**：
- 如果 `flashing unlock` 输出 `Flashing Unlock is not allowed` → 授权位没生效，回到阶段 3
- 如果输出 `OKAY` 或 `Device already : unlocked!` → 继续阶段 5

---

## 阶段 5：持久性判定（最关键的一步）

### 5.1 刷回原版 v1.0.1 abl

进入 EDL：
```powershell
$L = "decrypted_images\v1.0.1\prog_firehose_ddr.elf"
py -3 edl_tool\edlclient\edl.py ws 1362944 v1.0.1_dump\abl_a_backup.img --loader=$L
py -3 edl_tool\edlclient\edl.py reset --resetmode=reset --loader=$L
```

### 5.2 进入 fastboot 检查状态

```powershell
fastboot devices
fastboot oem device-info
fastboot getvar unlocked
```

### 5.3 判定结果

**🎉 情况 A：Device unlocked: true, unlocked: yes**
→ **持久解锁成功！** 状态已写入 RPMB
→ 官方签名 abl + 持久解锁 = 目标达成
→ 后续可以正常进系统，用原版 abl 就能刷任意分区

**😞 情况 B：Device unlocked: false, unlocked: no**
→ 解锁没有持久化
→ 作者 abl 的 flashing unlock 也只是"报告"而没写状态（或 TZ 拒绝）
→ 记录此结果，转路线 B（先用作者 abl 把设备用起来）或路线 C（UEFI 变量注入）

---

## 阶段 6：恢复（如果需要）

### 6.1 恢复所有分区到原始状态

```powershell
# 进入 EDL
$L = "decrypted_images\v1.0.1\prog_firehose_ddr.elf"

# 恢复 FRP
py -3 edl_tool\edlclient\edl.py ws 9340816 v1.0.1_dump\frp_backup.img --loader=$L

# 恢复 abl
py -3 edl_tool\edlclient\edl.py ws 1362944 v1.0.1_dump\abl_a_backup.img --loader=$L

# 恢复 misc（正常启动）
py -3 scripts\make_misc_bcb.py boot-normal v1.0.1_dump\misc_normal.img --from v1.0.1_dump\misc_backup.img
py -3 edl_tool\edlclient\edl.py ws 9337104 v1.0.1_dump\misc_normal.img --loader=$L

# 重启
py -3 edl_tool\edlclient\edl.py reset --resetmode=reset --loader=$L
```

---

## 已知怪癖（务必遵守）

1. **EDL 连接**：若一直打点（`....`）= 主机没拿到设备，用 Zadig 把 05c6:9008 绑成 WinUSB/libusb
2. **本机特性**：执行若干命令后必须退出 EDL 重进，重新加载 firehose
3. **读写都必须带 `--loader=`**，避免自动探测失败
4. **不要写短文件到 misc**，否则 BCB 命令会与旧字节粘连（用 --from 基于备份生成）
5. **一次只改一个变量**，改完立即验证，避免多因素叠加无法定位

---

## 分区扇区表（LUN0）

| 分区 | start_sector | sectors | 大小 | 用途 |
|------|-------------|---------|------|------|
| frp | 9340816 | 1024 | 512 KB | ★ 授权位所在 |
| devinfo | 1373184 | 8 | 4 KB | 设备信息（状态不在此） |
| misc | 9337104 | 2048 | 1 MB | BCB，控制启动模式 |
| abl_a | 1362944 | 2048 | 1 MB | 当前启动槽 |
| abl_b | 1364992 | 2048 | 1 MB | 备用槽（保持 stock） |
| vbmeta_a | 1377296 | 128 | 64 KB | |
| vbmeta_b | 1377424 | 128 | 64 KB | |

---

## 红线（绝对不要碰）

1. ❌ `Provision RPMB` 类操作（一次性、可能变砖）
2. ❌ 直接写 RPMB 分区（需要熔断 key）
3. ❌ 刷错机型的关键固件（xbl/tz/hyp）
4. ❌ 熔丝操作（QFPROM）
