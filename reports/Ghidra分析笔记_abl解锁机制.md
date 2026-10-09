# Ghidra 分析笔记：小天才 Z10 (ND03) v1.0.1 abl 解锁机制

> 分析目标：`unpacked_abl/v1.0.1/abl_pe32_clean.bin` (PE32+ ARM64, ImageBase=0)
> 分析时间：2026-10-07
> 工具：Ghidra 12.1.4
> **最后更新：2026-10-07 深夜（包含 DeepSeek 交叉验证 + 路径 A 测试结果 + XBL 分析 + DeepSeek VBProtocol/TrustZone 复查）**

---

## ⚠️ 重要更新日志

### 2026-10-07 深夜更新
- **DeepSeek 指令级交叉验证完成**：修正 3 处错误（magic 分支方向、GUID 末4位、FUN_0001d8a8 条件），确认作者解锁机制（UserDebug 构建 thunk 返回 0）
- **路径 A 测试结果**：devinfo[0x0D]=1 但 AVB 仍 enforcing；magic 错误版 devinfo 未被修正（FUN_00025ce8 读取失败）
- **FUN_0001cff8 分析**：devinfo 读写通过 VB Protocol 的 ReadWriteDeviceInfo（vtable+0x08），不是直接读 eMMC！
- **VB Protocol vtable 完整结构**：+0x08=ReadWriteDeviceInfo, +0x30=ResetDeviceState, +0x38=ReadSecureState
- **XBL 分析**：XBL 是高通自定义多组件 ELF（非标准 UEFI FV），已提取 11 个段；**XBL 中未找到 VB Protocol GUID**，protocol 实现位置待确认
- **核心问题**：abl 通过 VB Protocol 读写 devinfo，但 ReadWriteDeviceInfo 调用失败，导致 abl 看不到直接 dd 写入 eMMC 的 devinfo 数据
- **DeepSeek VBProtocol/TrustZone 复查（第二轮）**：修正函数归属（XTCReadWriteDeviceInfo 属于 FUN_0001dbe0 +0x58，不是 FUN_0001cff8 +0x08）；确认"设备锁定与 fail-open 不矛盾"（读失败→早退→字节保持0→锁定，ReadSecureState 根本不被调用）；确认 magic="ANDROID-BOOT!" 是标准 lk/高通 devinfo 非 XTC 自创；确认 provider 不在任何 QFIL 包提供的组件里（108 文件 0 命中），可能在未提供文件的分区或根本不存在
> **交叉验证**：2026-10-07 DeepSeek 指令级复核（见 `分析报告_abl解锁机制交叉验证_DeepSeek.md`），修正 3 处错误，确认作者解锁机制

---

## ⚠️ DeepSeek 交叉验证修正记录（2026-10-07）

### 修正 1：magic 分支方向（关键！影响解锁路径推演）
- **之前错误**：认为 `if (memcmp==0) return 0` 是 magic 不匹配时返回
- **正确**：`cbz x0, 0x25E5C` —— **相等（magic 匹配）时跳 return 0**，什么都不写；**不相等时才**打印 "Device Magic does not match" 并进入初始化路径
- **影响**：magic 匹配时 ABL **完全跳过刷新与写回** ⇒ 手写 devinfo 内容不会被覆盖！这是路径 A 可行的关键依据

### 修正 2：GUID 末 4 位
- **之前错误**：`{8e5eff91-21b6-47d3-af2b-c15a01e00000}`
- **正确**：`{8e5eff91-21b6-47d3-af2b-c15a01e020ec}`
- 0x51AF0 处 16 字节 = `91 ff 5e 8e b6 21 d3 47 af 2b c1 5a 01 e0 20 ec`

### 修正 3：FUN_0001d8a8 条件方向
- **之前错误**：跳过条件 `(uVar4==0) || (FUN_00057d8()==3)`
- **正确**：reset **执行**条件是 `(FUN_00057E0()!=0) && (FUN_00057D8()!=3)`

### 🏆 重大发现：作者 abl 解锁的确定性机制（指令级证据）
- **不是 patch、不是 devinfo、不是 secure state**
- 而是 **FUN_00016408 这个 thunk 在 release 与 userdebug 两种构建配置下返回相反常量**：
  - release v1.0.1 @0x16408: `mov w0,#1; ret` → 返回 1 → IsUnlocked 返回 devinfo[0x0D]
  - 作者 UserDebug @0x16520: `mov w0,wzr; ret` → 返回 0 → IsUnlocked **恒返回 1（解锁）**
- 这解释了"为什么找不到 patch 字节"——根本没有 patch，是构建变体差异（供应链层面的产品化问题）

### 🎯 对 v1.0.1 的可行动结论：路径 A（构造 devinfo）可行！
- release abl 的解锁状态由 **devinfo[0x0D]** 支配
- devinfo 只校验 13 字节 magic，**没有签名、没有 CRC/哈希**
- magic 匹配时 ABL 跳过刷新 ⇒ 手写内容不会被覆盖
- **建议写入字节**：
  ```
  0x00: "ANDROID-BOOT!" (13B)
  0x0D: 01 (is_unlocked)
  0x0E: 01 (is_unlock_critical)
  0x0F: 00
  0x90: 01
  其余: 00
  ```

---

## 一、核心函数关系图（DeepSeek 验证后修正版）

```
FUN_00025ce8 (ReadAndUpdateDevInfo) ★核心★
  │
  ├── 读取 devinfo 分区 → DAT_00064938 (0xa50 字节)
  │     └─ magic = "ANDROID-BOOT!" (13字节)
  ├── 读取 XTC Device Info → DAT_00065388 (0xa50 字节)
  │
  ├── memcmp(buf, "ANDROID-BOOT!", 13)
  │     ├─ ★ 相等（magic 匹配）→ 直接 return 0，不刷新、不写回 ★
  │     └─ 不匹配 → 打印 "Device Magic does not match"
  │                → 清零缓冲区 → 写回 magic → 设字段
  │                → 调用 FUN_0001d7a8() → secure state
  │                → buf[0xD]=buf[0xE]=(state==0)  ★is_unlocked
  │                → buf[0x90]=1
  │                → 写回 devinfo 分区
  │
  ├── DAT_00064945 = devinfo_buf[0x0D]  ← 解锁状态！
  │   （注意：DAT_00064945 就是 devinfo 缓冲区 +0x0D，不是独立全局变量）
  │
  └── 写回 devinfo 分区（仅 magic 不匹配时的初始化路径）

FUN_00025968 (IsUnlocked)
  ├── t = FUN_00016408()
  │     ├─ release: mov w0,#1 → t=1 → 返回 devinfo_buf[0x0D]
  │     └─ UserDebug: mov w0,wzr → t=0 → 恒返回 1（解锁）★作者机制
  └── return (t & 0xFF) ? devinfo_buf[0x0D] : 1

FUN_000057e8 (LoadImageAndAuthVB2)
  └── bVar6 = FUN_00025968() → 控制 AVB 验证严格程度
```

---

## 二、函数详细分析

### 2.1 FUN_000057e8 — 镜像加载与 AVB 验证主函数

- **地址**：`0x57e8`
- **签名**：`uint * FUN_000057e8(char *param_1, uint param_2, wchar_t *param_3)`
- **大小**：约 0x1900 字节（非常大，核心逻辑函数）
- **调用者**：`FUN_00001778` 和 `FUN_00032cdc`
- **功能**：加载 boot/recovery 镜像，执行 AVB 验证，决定是否启动

#### 关键逻辑

**第 198 行：读取解锁状态**
```c
bVar6 = FUN_00025968();  // is_unlocked
uVar9 = (uint)(bVar6 != 0);
```

**第 421-468 行：AVB 验证后的分支判定（核心！）**
```c
if (/* 多 slot 条件满足 */) {
    uVar2 = uVar9 | 4;  // 解锁状态下 flags 加 4 (ALLOW_VERIFICATION_ERROR?)
    if (!非多slot) {
        uVar2 = uVar9;   // 单 slot 用原始值
    }
    uVar14 = FUN_00008768(..., uVar2, uVar24, ...);  // AvbSlotVerify
    uVar9 = uVar14;  // AVB 验证结果
    
    if (bVar6 != 0) {  // ===== 解锁状态 =====
        bVar5 = uVar9 == 5;  // AVB_ERROR_VERIFICATION?
        if (uVar9 < 6) {
            FUN_000074f4();  // 可能是清除错误状态
            uVar3 = 1;  // 标记为可继续
            if (!bVar5) {
                // 打印 "ERROR: Device State %a,AvbSlotVerify returned %a"
                goto LAB_000064fc;  // 但仍然继续（解锁状态）
            }
        }
        // ===== 这里调用 FUN_0000742c() 打印 "State: Unlocked..." =====
        FUN_00002a64();  // 可能是获取调试输出状态
        FUN_00007414();  // 同上
        // 继续启动流程
    }
    
    if (uVar9 != 0) goto LAB_000064c4;  // AVB 有错误但解锁状态下继续
    // AVB 验证通过，正常加载镜像
}
```

**第 665-685 行：第二次 AVB 验证（vendor_boot 等）**
```c
if (bVar6 == 0) {  // 锁定状态
    if (uVar9 != 0) goto LAB_0000673c;  // 任何错误都报错
} else {  // 解锁状态
    bVar5 = uVar9 == 5;
    if ((5 < uVar9) || (FUN_000074f4(), bVar5)) {
        // 错误处理，但解锁状态下更宽容
    }
    // 打印 "State: Unlocked..." (第二次)
}
```

**第 820-826 行：设置 verifiedbootstate**
```c
if (bVar6 == 0) {
    iVar8 = (uint)((char)*puVar12 != '\0') << 1;  // 锁定：根据 slot 后缀
} else {
    iVar8 = 1;  // 解锁：固定为 1 (green?)
}
*(int *)(param_1 + 0x438) = iVar8;
```

**第 864-868 行：写入内核 cmdline**
```c
FUN_000072c8(param_1, " androidboot.verifiedbootstate=");
// 根据 param_1[0x438] 从字符串表 UNK_00041428 选择值
// 0=orange, 1=green, 2=yellow, ...
```

#### 关键字符串引用

| 字符串 | 地址 | 用途 |
|---|---|---|
| `"State: Unlocked, AvbSlotVerify returned %a, continue boot"` | `0x410a2` | 解锁状态下 AVB 失败时打印 |
| `"ERROR: Device State %a,AvbSlotVerify returned %a"` | 附近 | 锁定状态下 AVB 失败时打印 |
| `"No bootable slots found enter fastboot mode"` | 附近 | 无可启动槽位 |
| `"VB2: Authenticate complete! boot state is: %a"` | 附近 | AVB 认证完成 |
| `" androidboot.verifiedbootstate="` | 附近 | 内核 cmdline 参数 |

---

### 2.2 FUN_00025968 — 解锁状态读取（包装函数）

- **地址**：`0x25968`
- **签名**：`undefined1 FUN_00025968(void)`
- **大小**：约 0x30 字节（非常小）
- **返回值**：`undefined1`（布尔值，0=锁定，非0=解锁）
- **被调用**：`FUN_000057e8` 第 198 行

#### 反编译代码
```c
undefined1 FUN_00025968(void)
{
  uVar2 = FUN_00016408();        // 永远返回 1（stub！）
  uVar1 = DAT_00064945;           // 全局变量（实际解锁状态）
  if ((uVar2 & 0xff) == 0) {
    uVar1 = 1;
  }
  return uVar1;  // 因为 FUN_00016408 永远返回 1，所以永远返回 DAT_00064945
}
```

#### 关键发现

1. **`FUN_00016408()` 是 stub，永远返回 1**（在 release 版本中被硬编码）
2. **因此解锁状态完全由 `DAT_00064945` 决定**
3. `DAT_00064945` 由 `FUN_00025ce8` 在读取 devinfo 后设置（见 2.4 节）

---

### 2.3 FUN_00016408 — stub 函数（硬编码返回 1）

- **地址**：`0x16408`
- **反编译代码**：
```c
undefined8 FUN_00016408(void)
{
  return 1;  // 永远返回 1
}
```
- **说明**：在 release 版本中，这个函数被简化为直接返回 1 的 stub。可能在 UserDebug 版本中有不同实现（真正读取某个状态）。

---

### 2.4 FUN_00025ce8 — devinfo 读取与解锁状态设置 ★核心★

- **地址**：`0x25ce8`
- **签名**：`longlong FUN_00025ce8(void)`
- **功能**：读取 devinfo 分区，验证 magic，计算解锁状态，写回 devinfo
- **被调用**：待确认（需要查 XREF）
- **设置的全局变量**：`DAT_00064945`（解锁状态）、`DAT_00064946`、`DAT_00064947`、`DAT_000649c8`、`DAT_000649cc`

#### 反编译代码（带注释）
```c
longlong FUN_00025ce8(void)
{
  // 检查是否已读取过（缓存标志 DAT_00065dd8）
  if ((DAT_00065dd8 & 1) == 0) {
    // 读取 Device Info 分区 → DAT_00064938 (0xa50 = 2640 字节)
    lVar2 = FUN_0001cff8(0, &DAT_00064938, 0xa50);
    if (lVar2 != 0) {
      // 打印 "Unable to Read Device Info: %r"
      return lVar2;
    }
    // 读取 XTC Device Info → DAT_00065388 (0xa50 字节)
    lVar2 = FUN_0001dbe0(0, &DAT_00065388, 0xa50);
    if (lVar2 != 0) {
      // 打印 "Unable to Read XTC Device Info: %r"
      return lVar2;
    }
    DAT_00065dd8 = 1;  // 标记已读取
  }
  
  // ★ 验证 devinfo magic = "ANDROID-BOOT!" (13字节)
  // 注意：不是标准高通的 "BOOT"/"XBCR"，是小天才自定义的！
  lVar2 = FUN_00035564(&DAT_00064938, "ANDROID-BOOT!", 0xd);
  if (lVar2 == 0) {
    return 0;  // magic 不匹配，直接返回
  }
  // magic 不匹配时打印 "Device Magic does not match"
  
  // 通过函数指针调用（可能是 memset/清除字段）
  (**(code **)(DAT_00055ce8 + 0x168))(&DAT_00064938, 0xa50, 0);
  (**(code **)(DAT_00055ce8 + 0x160))(&DAT_00064938, "ANDROID-BOOT!", 0xd);
  
  DAT_000649cc = 0;
  (**(code **)(DAT_00055ce8 + 0x168))(&DAT_000651d0, 0x100, 0);
  (**(code **)(DAT_00055ce8 + 0x168))(&DAT_000649d0, 0x800, 0);
  
  // ★★★ 调用 FUN_0001d7a8() 计算解锁状态 ★★★
  cVar1 = FUN_0001d7a8();
  
  // ★ 设置解锁状态！FUN_0001d7a8() 返回 0 → 解锁（DAT_00064945 = 1）
  DAT_00064945 = cVar1 == '\0';
  
  DAT_00064947 = 0;
  DAT_000649c8 = 1;
  DAT_00064946 = DAT_00064945;  // 复制到备份变量
  
  // ★ 写回 devinfo 分区（修改后的数据）
  lVar2 = FUN_0001cff8(1, &DAT_00064938, 0xa50);
  if (lVar2 == 0) {
    return 0;
  }
  // 写回失败打印 "Unable to Write Device Info: %r"
  
  return lVar2;
}
```

#### 重大发现

1. **devinfo 的 magic 是 `"ANDROID-BOOT!"`（13字节），是标准 lk/高通 devinfo magic（非 XTC 自创）！**
   - 来源：AOSP lk（Little Kernel）`app/aboot/devinfo.h`
   - 参考：https://android.googlesource.com/kernel/lk/+/058f1cd30fb09a65bd8fd4b782b182f3f3957fd9/app/aboot/devinfo.h
   - XTC 只是扩展了大小（0xA50 = 2640 字节），标准 lk devinfo 更小
   - 这解释了为什么手动写标准 devinfo（magic="BOOT"/"XBCR"）不生效——magic 不对

2. **devinfo 大小 0xa50 = 2640 字节**（XTC 扩展），读入全局缓冲区 `DAT_00064938`（.data 段初值全 0）

3. **解锁状态由 `FUN_0001d7a8()` 计算**（地址 `0x1d7a8`）
   - 返回 0 → 解锁（`DAT_00064945 = 1`）
   - 返回非 0 → 锁定（`DAT_00064945 = 0`）
   - **这是下一个最关键的分析目标！**

4. **函数会修改 devinfo 后写回分区**
   - 清除某些字段（通过函数指针调用）
   - 设置解锁状态等字段
   - 然后写回 devinfo 分区

5. **还有一个 XTC Device Info**（`DAT_00065388`），通过 `FUN_0001dbe0` 读取
   - 可能包含小天才特有的设备信息（绑定状态？家长控制？）

#### devinfo 读写函数

| 函数 | 调用方式 | 功能 |
|---|---|---|
| `FUN_0001cff8(0, buf, size)` | 第一个参数=0 | 读取 devinfo 分区 |
| `FUN_0001cff8(1, buf, size)` | 第一个参数=1 | 写回 devinfo 分区 |
| `FUN_0001dbe0(0, buf, size)` | 第一个参数=0 | 读取 XTC Device Info |

#### devinfo 结构（已知部分）

| 偏移（相对 DAT_00064938） | 大小 | 字段 | 值 |
|---|---|---|---|
| `0x00` | 13 字节 | magic | `"ANDROID-BOOT!"` |
| `0x0d` | ? | 后续字段 | 待分析 |
| `0x94` (=0x649cc-0x64938) | ? | 某个字段 | 被清零 |
| `0x298` (=0x64bd0-0x64938) | ? | 某个字段 | 被设置为 1 |
| `0x?` | ? | is_unlocked 字段 | 由 FUN_0001d7a8 计算后设置 |

**注意**：`DAT_00064945` 是全局变量（在 devinfo 缓冲区之外），不是 devinfo 结构的字段。但函数在设置全局变量后会写回 devinfo，说明 devinfo 中也有对应的字段存储解锁状态。

---

### 2.5 FUN_0001d7a8 — secure state 读取（通过 UEFI VB Protocol）★核心★

- **地址**：`0x1d7a8`
- **签名**：`undefined1 FUN_0001d7a8(void)`
- **功能**：通过 UEFI Verified Boot Protocol 读取 secure state（安全状态）
- **被调用**：`FUN_00025ce8` 第 51 行
- **返回值**：`undefined1`（0=解锁，非0=锁定）
- **关键字符串**：`"Error Reading the secure state: %r\n"`、`"Unable to locate VB protocol: %r\n"`

#### 反编译代码（带注释）
```c
undefined1 FUN_0001d7a8(void)
{
  plVar4 = FUN_000287b0();  // 获取 UEFI 栈框架指针
  lVar7 = *plVar4;
  *plVar4 = lVar7 + -0x20;  // 分配栈空间
  
  lVar1 = DAT_000520c0;  // 栈 canary（栈完整性保护）
  *(undefined1 *)(lVar7 + -0x14) = 0;  // 输出缓冲区初始化为 0
  *(longlong *)(lVar7 + -8) = lVar1;
  
  // ★ 第1步：定位 UEFI Verified Boot (VB) Protocol
  // DAT_00055ce8 + 0x140 是函数指针（类似 gBS->LocateProtocol）
  lVar5 = (**(code **)(DAT_00055ce8 + 0x140))(&DAT_00051af0, 0, lVar7 + -0x10);
  
  if (lVar5 == 0) {
    // ★ 第2步：调用 VB Protocol 的方法（偏移 0x38）读取 secure state
    // protocol 对象存在 *(longlong *)(lVar7 + -0x10)
    // 调用 protocol->vtable[0x38/8](protocol, output_buffer)
    lVar5 = (**(code **)(*(longlong *)(lVar7 + -0x10) + 0x38))
                      (*(longlong *)(lVar7 + -0x10), lVar7 + -0x14);
    if (lVar5 == 0) {
      // 成功读取 secure state
      uVar3 = *(undefined1 *)(lVar7 + -0x14);  // 读取结果
      goto LAB_0001d878;
    }
    // 读取失败，打印 "Error Reading the secure state: %r"
    ...
  } else {
    // 定位 VB protocol 失败，打印 "Unable to locate VB protocol: %r"
    ...
  }
  
  uVar3 = 0;  // ★ 默认返回 0（解锁！）
  
LAB_0001d878:
  // 栈 canary 检查
  if (lVar1 == *(longlong *)(lVar7 + -8)) {
    *plVar4 = lVar7;
    return uVar3;  // 返回 secure state
  }
  FUN_00010574();  // 栈破坏，死循环
}
```

#### 重大发现

1. **解锁状态称为 "secure state"（安全状态），通过 UEFI VB Protocol 读取**
   - 不是直接读 devinfo 的某个字段
   - 而是通过 UEFI Verified Boot Protocol 的方法读取
   - 字符串 `"Error Reading the secure state: %r\n"` 证实了命名

2. **读取路径**：
   ```
   FUN_0001d7a8()
     ├─→ Locate VB Protocol (DAT_00055ce8 + 0x140 函数指针)
     └─→ protocol->vtable[7] (偏移 0x38) → ReadSecureState(protocol, &output)
   ```

3. **返回值含义**：
   - `secure state = 0` → 解锁（`DAT_00064945 = 1`）
   - `secure state != 0` → 锁定（`DAT_00064945 = 0`）

4. **默认解锁！**：
   - 如果定位 VB Protocol 失败 → `uVar3 = 0` → 解锁
   - 如果读取 secure state 失败 → `uVar3 = 0` → 解锁
   - 这意味着安全机制是"默认安全"（secure by default）的反面——只有成功读取到非 0 的 secure state 才会锁定

5. **secure state 可能存储在**：
   - RPMB（Replay Protected Memory Block，eMMC 安全分区）
   - TrustZone/TEE 安全存储
   - eFuse（一次性可编程熔丝）
   - 某个被签名保护的分区
   - **需要进一步分析 VB Protocol 的实现来确认**

#### VB Protocol 结构（推测）

```c
typedef struct {
    // 前 0x38 字节是其他方法（7个函数指针）
    void *vtable[...];  // 偏移 0x00 - 0x37
    // 偏移 0x38 是 ReadSecureState 方法
    EFI_STATUS (*ReadSecureState)(VB_PROTOCOL *This, UINT8 *SecureState);  // 偏移 0x38
    // 后续还有其他方法...
} VB_PROTOCOL;
```

#### 下一步分析目标

| 目标 | 地址 | 目的 |
|---|---|---|
| `DAT_00055ce8 + 0x140` 指向的函数 | 待定位 | 定位 VB Protocol 的函数（类似 LocateProtocol） |
| VB Protocol 的实现 | 待定位 | 找到 ReadSecureState 的真正实现，看它从哪里读 |
| `DAT_00051af0` | `0x51af0` | 可能是 VB Protocol 的 GUID |
| `FUN_000287b0` | `0x287b0` | UEFI 栈框架函数（可能是 GetSystemTable） |

---

### 2.6 FUN_0000742c — "State: Unlocked" 日志包装函数

- **地址**：`0x742c`
- **功能**：打印 `"State: Unlocked, AvbSlotVerify returned %a, continue boot"` 日志
- **被调用**：`FUN_000057e8` 中两处（第 443 行附近和第 682 行附近）

#### 反编译代码
```c
void FUN_0000742c(/* AvbSlotVerify 返回值通过 x0 传入 */)
{
    adrp x1, 0x41000        ; 字符串地址高 21 位
    mov  x2, x0             ; x2 = AvbSlotVerify 返回值 (%a 参数)
    add  x1, x1, #...       ; 完整字符串地址
    mov  w0, #0x40000       ; 日志级别
    b    FUN_000025f0       ; 跳转到日志输出函数
}
```

---

## 三、param_1 结构体字段偏移（BootInfo）

`FUN_000057e8` 的第一个参数 `param_1` 是一个大型结构体指针，已知字段偏移：

| 偏移 | 类型 | 用途 |
|---|---|---|
| `0x428` | `longlong` | 已加载分区数量（NumLoadedPartition） |
| `0x430` | `ulonglong*` | 指向某个版本号指针（`**(param_1 + 0x430) < 0x10002` 判断） |
| `0x438` | `int` | verifiedbootstate 索引（0=orange, 1=green, 2=yellow） |
| `0x440` | `undefined1*` | 指向 cmdline 缓冲区 |
| `0x450` | `uint**` | VB2Data 指针 |
| `0x458` | `uint` | boot/recovery 镜像 header version |

---

## 四、已确认的解锁机制

### 4.1 解锁状态如何影响启动

```
设备启动
  │
  ├─→ FUN_00025968() 读取解锁状态
  │     └─→ FUN_00016408() 真正读取（待分析）
  │
  ├─→ bVar6 = is_unlocked
  │
  ├─→ 加载 boot 镜像，执行 AvbSlotVerify
  │
  ├─→ 如果 AVB 验证失败：
  │     ├─→ bVar6 != 0 (解锁) → 打印 "State: Unlocked..."，继续启动 ✅
  │     └─→ bVar6 == 0 (锁定) → 打印 "ERROR: Device State..."，进入 fastboot ❌
  │
  └─→ 设置内核 cmdline: androidboot.verifiedbootstate=
        ├─→ 解锁: green (1)
        └─→ 锁定: 根据 slot 后缀 (orange/yellow)
```

### 4.2 关键问题（待解答）

1. **`FUN_00016408()` 从哪里读取解锁状态？**
   - devinfo 分区？
   - 某个 eMMC 分区的固定偏移？
   - 寄存器/eFuse？
   - 全局变量（在更早的启动阶段被设置）？

2. **`DAT_00064945` 在哪里被设置？**
   - 可能是 fastboot 命令处理函数中设置
   - 可能是 devinfo 写入函数中设置
   - 可能是启动时从某个存储位置读取后缓存

3. **为什么手动写 devinfo 不生效？**
   - devinfo 格式不对？
   - FUN_00016408 不读 devinfo？
   - 有签名/校验？

---

## 五、下一步分析计划（已更新）

### 优先级 1：追踪 VB Protocol 的 ReadSecureState 实现 ★最关键★
- `FUN_0001d7a8` 通过 UEFI VB Protocol 读取 secure state
- 需要找到 protocol 的 ReadSecureState 方法（vtable 偏移 0x38）的真正实现
- 看它从哪里读取：RPMB？TrustZone？eFuse？某个分区？
- 方法：先分析 `DAT_00055ce8 + 0x140` 指向的 LocateProtocol 函数，找到 protocol 安装位置

### 优先级 2：分析 DAT_00055ce8（UEFI 启动服务表？）
- `DAT_00055ce8` 被大量函数引用，偏移 0x140、0x160、0x168 都是函数指针
- 可能是 gBS（Boot Services）或 gST（System Table）的副本
- 偏移 0x140 = LocateProtocol？
- 偏移 0x160/0x168 = SetMem/CopyMem？

### 优先级 3：分析 DAT_00051af0（VB Protocol GUID？）
- 作为 LocateProtocol 的第一个参数传入
- 可能是 EFI_GUID 结构（16字节）
- 可以确认 VB Protocol 的 GUID

### 优先级 4：分析 devinfo 完整结构
- magic = "ANDROID-BOOT!"（已知）
- 大小 0xa50 = 2640 字节
- FUN_00025ce8 修改了哪些字段？（偏移 0x94=清零, 0x290=设1）
- is_unlocked 字段是否也在 devinfo 中？（函数写回 devinfo 说明有对应字段）

### 优先级 5：分析 FUN_0001cff8（devinfo 读写函数）
- 确认它读的是哪个分区（devinfo 分区 mmcblk0p24？）
- 第一个参数 0=读，1=写

### 优先级 6：追踪 FUN_00025ce8 的调用者
- 谁在什么时候调用 devinfo 读取和解锁状态设置？
- 是启动时自动调用？还是 fastboot 命令触发？

### 优先级 7：对比作者 UserDebug abl 的同一函数
- FUN_0001d7a8 在 UserDebug 版本中是否直接返回 0？
- VB Protocol 在 UserDebug 版本中是否不同？
- devinfo 格式是否相同？

---

## 六、已知函数地址索引（v1.0.1 release abl，已更新）

| 地址 | 函数名（推测） | 功能 | 状态 |
|---|---|---|---|
| `0x57e8` | FUN_000057e8 | LoadImageAndAuthVB2（镜像加载+AVB验证主函数） | ✅ 已分析 |
| `0x25ce8` | FUN_00025ce8 | ReadAndUpdateDevInfo（devinfo读取+解锁状态设置）★核心 | ✅ 已分析 |
| `0x25968` | FUN_00025968 | is_unlocked 读取（包装函数） | ✅ 已分析 |
| `0x16408` | FUN_00016408 | stub（永远返回 1） | ✅ 已分析 |
| `0x1d7a8` | FUN_0001d7a8 | **secure state 读取（通过 UEFI VB Protocol）** | ✅ 已分析 |
| `0x259a0` | FUN_000259a0 | 另一个状态读取（可能是 secure/verity） | ⏳ 待分析 |
| `0x1cff8` | FUN_0001cff8 | devinfo 分区读写（0=读，1=写） | ⏳ 待分析 |
| `0x1dbe0` | FUN_0001dbe0 | XTC Device Info 读取 | ⏳ 待分析 |
| `0x35564` | FUN_000035564 | 字符串比较（memcmp？） | ⏳ 待分析 |
| `0x287b0` | FUN_000287b0 | UEFI 栈框架函数（可能是 GetSystemTable） | ⏳ 待分析 |
| `0x742c` | FUN_0000742c | "State: Unlocked..." 日志包装 | ✅ 已分析 |
| `0x8768` | FUN_00008768 | AvbSlotVerify（AVB 槽位验证） | ⏳ 待分析 |
| `0x25f0` | FUN_000025f0 | 日志输出函数（DebugPrint） | ✅ 已知 |

### 全局变量

| 地址 | 名称 | 用途 | 状态 |
|---|---|---|---|
| `0x64945` | DAT_00064945 | **解锁状态**（0=锁定，1=解锁），由 FUN_00025ce8 设置 | ✅ 已定位 |
| `0x64946` | DAT_00064946 | 解锁状态备份（=DAT_00064945） | ✅ 已定位 |
| `0x64947` | DAT_00064947 | 某个状态（被清零） | ✅ 已定位 |
| `0x64938` | DAT_00064938 | **devinfo 缓冲区**（0xa50 字节，magic="ANDROID-BOOT!"） | ✅ 已定位 |
| `0x649cc` | DAT_000649cc | devinfo 相关字段（被清零） | ✅ 已定位 |
| `0x649c8` | DAT_000649c8 | devinfo 相关字段（被设为 1） | ✅ 已定位 |
| `0x65388` | DAT_00065388 | XTC Device Info 缓冲区（0xa50 字节） | ✅ 已定位 |
| `0x65dd8` | DAT_00065dd8 | devinfo 已读取缓存标志 | ✅ 已定位 |
| `0x41428` | UNK_00041428 | verifiedbootstate 字符串表（orange/green/yellow...） | ✅ 已定位 |
| `0x410a2` | s_State_Unlocked... | "State: Unlocked, AvbSlotVerify returned %a, continue boot\n" | ✅ 已定位 |

---

## 七、已确认的解锁机制（更新版）

### 7.1 完整流程

```
设备启动 (ABL)
  │
  ├─→ FUN_00025ce8() 被调用（时机待确认）
  │     │
  │     ├─→ 读取 devinfo 分区 → DAT_00064938 (0xa50 字节)
  │     │     └─ magic 必须是 "ANDROID-BOOT!"（自定义格式）
  │     ├─→ 读取 XTC Device Info → DAT_00065388
  │     │
  │     ├─→ FUN_0001d7a8() 计算解锁状态 ★待分析★
  │     │     └─→ 返回 0 → 解锁，返回非 0 → 锁定
  │     │
  │     ├─→ DAT_00064945 = (FUN_0001d7a8() == 0)  ← 解锁状态！
  │     ├─→ 修改 devinfo 缓冲区（清除字段，设置状态）
  │     └─→ 写回 devinfo 分区
  │
  ├─→ FUN_000057e8() 加载 boot 镜像 + AVB 验证
  │     │
  │     ├─→ bVar6 = FUN_00025968() → 读取 DAT_00064945
  │     │
  │     └─→ AVB 验证失败时：
  │           ├─→ bVar6=1 (解锁) → 打印 "State: Unlocked..."，继续启动 ✅
  │           └─→ bVar6=0 (锁定) → 打印 "ERROR..."，进入 fastboot ❌
```

### 7.2 关键结论

1. **devinfo 格式是小天才自定义的**：magic = `"ANDROID-BOOT!"`，不是标准高通格式
2. **解锁状态存储在 devinfo 中**：由 `FUN_0001d7a8()` 从 devinfo 读取/计算
3. **release abl 会自动写回 devinfo**：每次启动时修改 devinfo 后写回分区
4. **手动写标准 devinfo 不生效的原因**：magic 不对（我们写的是 "BOOT"/"XBCR"，应该是 "ANDROID-BOOT!"）

### 7.3 解锁的可能路径（更新版）

1. **构造正确格式的 devinfo**（magic="ANDROID-BOOT!" + 0x0D=01）
   - ❌ **已测试，未成功**：直接 dd 写入 eMMC 的 devinfo 分区，但 abl 通过 VB Protocol 读取，ReadWriteDeviceInfo 调用失败，abl 看不到写入的数据
   - 需要解决 VB Protocol ReadWriteDeviceInfo 失败的问题

2. **让 VB Protocol 读取失败（fail-open 攻击）**
   - FUN_0001d7a8 中，如果 LocateProtocol 或 ReadSecureState 失败，返回 0 → 解锁
   - 如果能让 ReadSecureState 失败，release abl 也会恒解锁
   - 需要分析 protocol 实现，找到让它失败的方法

3. **使用 UserDebug abl**（作者方案，已验证）
   - UserDebug 构建中 FUN_00016408 thunk 返回 0 → IsUnlocked 恒返回 1
   - 但需要官方签名的 UserDebug 镜像，且跨版本混刷会卡 logo

4. **找到 VB Protocol 的真正实现并分析**
   - protocol 不在 abl 里，也不在 XBL 里（已搜索 GUID，0 结果）
   - 可能在 tz/hyp/xbl_config 等其他分区，或以不同字节序存储
   - 找到后可以分析 ReadWriteDeviceInfo 为什么失败，以及 ReadSecureState 的数据来源

---

## 八、路径 A 测试记录（2026-10-07）

### 测试 1：devinfo magic 正确 + 0x0D=01
- **操作**：QMMI adb root 中 dd 写入 devinfo_unlocked.bin（magic="ANDROID-BOOT!", 0x0D=01, 0x0E=01, 0x90=01）
- **重启后 devinfo**：保持不变（magic 匹配时 ABL 跳过刷新，验证正确）
- **fastboot oem device-info**：Device unlocked: false
- **刷破坏版 boot 后**：直接进 fastboot，显示 AVB 错误
- **结论**：❌ 未解锁。devinfo[0x0D]=1 没有让 IsUnlocked 返回 1

### 测试 2：devinfo magic 错误（强制走初始化路径）
- **操作**：写入 devinfo_magic_broken.bin（magic="ANDROID-BOOT?"，最后字节 !→?）
- **QMMI 重启**：magic 未被修正（QMMI 模式不调用 FUN_00025ce8）
- **misc 清零后正常启动进系统**：magic 仍未被修正
- **结论**：❌ FUN_00025ce8 没有走初始化路径。原因是 ReadWriteDeviceInfo（VB Protocol）调用失败，函数直接返回

### 根本原因（DeepSeek 复查修正版）
- **FUN_0001cff8（+0x08 ReadWriteDeviceInfo）和 FUN_0001dbe0（+0x58 XTCReadWriteDeviceInfo）都通过 VB Protocol 操作 devinfo**
- **不是直接读 eMMC 分区！ABL 内搜不到 "devinfo" 分区名字符串**
- VB Protocol 调用失败（最可能是 LocateProtocol 失败，provider 不在设备已装载镜像中）→ FUN_00025ce8 直接返回 → 不走 memcmp → 不走初始化路径
- 直接 dd 写入 eMMC 的 devinfo 数据，abl 通过 VB Protocol 读不到

### ⚠️ 重要推理修正（DeepSeek 复查）
- **"设备锁定"与 fail-open 不矛盾**：
  - 解锁判定 `IsUnlocked()` = `devinfo_buf[0x0D]`（.data 初值 **0**，DeepSeek 实测 PE 文件 0x64938 处全 0）
  - **只有 devinfo 读成功**，FUN_00025ce8 才会走到 memcmp 与初始化路径，其中才会调用 FUN_0001d7a8（fail-open → 写入 is_unlocked=1）
  - 所以：**读失败 → 早退 → 字节保持 0 → 锁定**，且 **fail-open 永远不会触发**
  - **ReadSecureState 是否成功与设备是否锁定无关**（因为读失败时根本不会调用 ReadSecureState）
- 之前认为"ReadSecureState 成功所以设备锁定"是错误的，没有依据

---

## 九、VB Protocol 完整结构（已确认 4 个方法，DeepSeek 复查修正版）

### Protocol GUID
`{8e5eff91-21b6-47d3-af2b-c15a01e020ec}`（注意：末 4 位是 20ec，不是 0000）

### vtable 方法（DeepSeek 指令级验证）

| 偏移 | 方法名（推测） | 功能 | 调用者 | 状态 |
|---|---|---|---|---|
| `+0x08` | ReadWriteDeviceInfo | 读写 devinfo（param1: 0=读,1=写） | **FUN_0001cff8** | ✅ 已确认 |
| `+0x30` | ResetDeviceState | 重置设备状态 | FUN_0001d8a8 | ✅ 已确认 |
| `+0x38` | ReadSecureState | 读取安全状态（0=解锁） | FUN_0001d7a8 | ✅ 已确认 |
| `+0x58` | XTCReadWriteDeviceInfo | XTC 扩展 device info 读写 | **FUN_0001dbe0** | ✅ 已确认（DeepSeek 新发现） |

### ⚠️ 重要修正（DeepSeek 复查）
- **`XTCReadWriteDeviceInfo` 两条错误串的 xref 指向 FUN_0001dbe0（+0x58），不是 FUN_0001cff8（+0x08）**
- 之前的函数归属错误，已修正
- FUN_0001cff8 调用 vtable+0x08，FUN_0001dbe0 调用 vtable+0x58
- 两个函数参数相同（mode, buf, size=0xA50），但调用不同的 vtable 方法

### 关键字符串（证实命名）
- `"XTCReadWriteDeviceInfo VBRwDevice failed with: %r"` → xref 在 FUN_0001dbe0 内（0x1DC64）
- `"XTCReadWriteDeviceInfo Unable to locate VB protocol: %r"` → xref 在 FUN_0001dbe0 内（0x1DCAC）
- `"Error Reading the secure state: %r"`
- `"Error Reseting device state: %r"`
- `"Unable to locate VB protocol: %r"`

### GUID 出现情况（DeepSeek 108 文件搜索验证）
- **全项目只出现 1 次**：abl.elf @ 0x51AF0（作为 LocateProtocol 参数）
- ABL 内 5 处 xref（0x5B8C/0x1D038/0x1D7E0/0x1D91C/0x1DC20）全部是 gBS+0x140 的 LocateProtocol
- **ABL 内搜不到 "devinfo" 分区名字符串** → 没有直连 eMMC 的路径
- 108 个文件（raw + XTC 解密、LE/BE 两种字节序）搜索 → **0 命中**（除 abl.elf 外）
- XBL 的 FV 内容未压缩（排除"GUID 被压缩藏起来"）
- imagefv.elf 内部 FV 解压后（276,936 B）也无 GUID

### Protocol 实现位置（DeepSeek 复查结论）
- ❌ 不在 abl.elf 内（5 处引用全是 LocateProtocol，无 InstallProtocolInterface）
- ❌ 不在 xbl.elf 内（已搜索 GUID，0 结果；FV 内容未压缩）
- ❌ 不在 tz.mbn/hyp.mbn/xbl_config/imagefv/uefi_sec/km41 等分区（108 文件 0 结果）
- ❌ imagefv.elf 内部 FV（LZMA 解压后 276,936 B，内含字体/图像资源，无 GUID）
- ⏳ **可能在未提供文件的分区**：toolsfv（1MB，名字即"工具 FV"，最可疑）、catefv、catecontentfv、cateloader、uefivarstore、keystore、secdata
- ⏳ **或者这台量产设备上 provider 根本不存在**（→ LocateProtocol 失败 → 永远锁定）

### 完整安全架构推测
```
abl (UEFI 应用)
  └─ VB Protocol (3个方法)
       ├─ ReadWriteDeviceInfo (+0x08) → 读写 eMMC devinfo 分区（❌ 调用失败，原因待查）
       ├─ ResetDeviceState (+0x30) → 重置设备状态
       └─ ReadSecureState (+0x38) → 通过 SCM 调用 TrustZone
              └─ tz.mbn: tz_get_secure_state()
                     └─ APPS_MSA Secure state / macchiato_authenticate_device
                            └─ 安全存储（RPMB? eFuse? TrustZone NV?）
```

---

## 十、XBL 结构分析（2026-10-07）

### XBL 文件信息
- 文件：`decrypted_images/v1.0.1/xbl.elf`
- 大小：3,093,392 字节（3.0 MB）
- 格式：ELF64，AArch64（machine=0xB7）
- entry：0xC24F9F8
- 程序头：20 个，其中 11 个非空 PT_LOAD 段

### XBL 段结构（已提取到 unpacked_xbl/v1.0.1/）

| 段 | vaddr | 大小 | 类型 | 说明 |
|---|---|---|---|---|
| PH[4] | 0x0C24E000 | 0x346AC | code/data | 主代码段 |
| PH[5] | 0x0C285000 | 0x16C98 | code/data | 数据段 |
| PH[6] | 0x0C2B2000 | 0x1777C | AARCH64_CODE | 代码段 |
| PH[7] | 0x0C2D5000 | 0x1D69 | code/data | 小数据段 |
| PH[11] | 0x0C119000 | 0x27D0 | AARCH64_CODE | 代码段 |
| PH[12] | 0x0C11C000 | 0xE5C | code/data | 小数据段 |
| PH[14] | 0x5FC00000 | 0x20CA00 | code/data | **最大段（2.1MB）** |
| PH[15] | 0x0C351000 | 0x28000 | NESTED_ELF | **嵌套 ELF** |
| PH[16] | 0x45E35000 | 0x4AFF7 | AARCH64_CODE | 代码段（含 "XBLRamD"） |
| PH[17] | 0x45EA7000 | 0x5B18 | code/data | 数据段 |

### 关键发现
1. **XBL 不是标准 UEFI FV 格式**（无 _FVH 签名 + ZeroVector），是高通自定义的多组件 ELF
2. **PH[15] 是嵌套的 ELF**（开头 7F 45 4C 46），可能包含 UEFI 驱动
3. **PH[14] 是最大的代码段**（2.1MB，vaddr=0x5FC00000），可能包含主要的 XBL 逻辑
4. **XBL 中未找到 VB Protocol GUID**（搜索 16 字节，0 结果）
5. 字符串 "XBLRamDump.EDL"、"sbl1_dload_entry" 等表明 XBL 包含 EDL 下载模式逻辑

### 解包工具
- `tools/xbl_unpack.py` — 通用 UEFI FV/FFS/LZMA 扫描器（对 XBL 不适用，因为 XBL 无 FV）
- `tools/_extract_xbl_segments.py` — ELF 段提取器（已成功提取 11 个段）

---

## 十一、当前状态与下一步方向（DeepSeek 复查更新版）

### 已完成
- ✅ 固件解密算法（双重 XOR，已解密 v1.0.1/v2.8.1 全量镜像）
- ✅ abl 解包（ELF→FV→FFS→LZMA→PE32+，三个版本）
- ✅ abl 完整解锁链路逆向（7 个核心函数）
- ✅ DeepSeek 第一轮指令级交叉验证（修正 3 处错误）
- ✅ DeepSeek 第二轮 VBProtocol/TrustZone 复查（修正函数归属、推理前提、magic 来源）
- ✅ 作者解锁机制确认（UserDebug 构建 thunk 返回 0）
- ✅ VB Protocol **4 个方法**确认（+0x08/+0x30/+0x38/+0x58）
- ✅ 路径 A 测试（devinfo 构造，未成功，根本原因已定位：provider 缺失/调用失败）
- ✅ XBL 结构分析和段提取
- ✅ 108 文件 GUID 搜索（确认 provider 不在 QFIL 包提供的组件里）
- ✅ imagefv.elf 内部 FV 解压分析（确认是字体/图像资源，不是 provider）
- ✅ secure state 来源确认（TrustZone tz.mbn，含 tz_get_secure_state/macchiato_*/软件熔丝）

### 待解决
1. **VB Protocol provider 是否存在？** — 可能在未提供文件的分区（toolsfv/catefv/catecontentfv/cateloader/uefivarstore/keystore/secdata），或根本不存在
2. **LocateProtocol 失败还是方法调用失败？** — 需要 UART 日志或 fastboot 输出区分（"Unable to locate VB protocol" vs "VBRwDevice failed"）
3. **XBL 如何验证 abl？** — 决定"能否自造 abl"（很可能是 XTC 证书链验签，作者必须用原厂签名 debug 构建）
4. **TZ secure state 的存储** — RPMB？TrustZone NV？软件熔丝？（需要分析 tz.mbn 中的 tz_get_secure_state/macchiato_is_secure_state/tz_is_sw_fuse_blown_secure）

### 已验证死路（更新版）
- ❌ 手动写 eMMC devinfo 分区（ABL 不直连 eMMC，通过 VB Protocol 读取，provider 缺失时读失败）
- ❌ 标准 fastboot 解锁命令（unknown command，小天才移除了标准接口）
- ❌ AVB 重命名漏洞（直接到 bootloader）
- ❌ flags=2 vbmeta（原理上不可能，flags 在被签名区域内）
- ❌ 手动制作 Magisk boot（8 个致命缺陷）
- ❌ 方案 A（刷回原版 abl 不保留 unlocked）
- ❌ 跨版本混刷（卡 logo）
- ❌ CVE-2026-24088（ND03 无 efisp/gbl）
- ❌ 路径 A 构造 devinfo（VB Protocol 读取失败，provider 缺失）
- ❌ GUID 指令动态构造（DeepSeek 排除，EDK2 常规做法是 .rodata 存储）
- ❌ Keymaster 改 boot_state 解锁（Keymaster 是消费者，不是决定者，且是签名 TZ TA）
- ❌ 修改 tz.mbn/km41.mbn/hyp.mbn/uefi_sec.mbn（签名组件，砖机不可逆）

### 下一步方向（按优先级，DeepSeek 复查建议）

#### 优先级 1：判定 provider 是否存在（决定后续一切，最快）
在 QMMI（adb root）下 dump 这些**包内没有提供文件**的分区并搜索 GUID：
```bash
for p in toolsfv catefv catecontentfv cateloader uefivarstore keystore secdata; do
  dd if=/dev/block/by-name/$p of=/sdcard/$p.img
done
```
然后搜索 GUID（LE/BE）+ `XTC`/`DeviceInfo`/`secure`/`VBRwDevice` 串。
- 命中 ⇒ provider 找到 → 再分析它的 +0x08 方法读写哪个存储
- 0 命中 ⇒ **这台设备上 provider 缺失** → 解锁只剩 UserDebug ABL 或验证绕过

#### 优先级 2：区分 LocateProtocol vs 方法失败
- 找调用 FUN_0001d7a8 的 fastboot 命令，执行并看输出
- 有 UART/串口日志最直接——`Unable to locate VB protocol: %r` vs `XTCReadWriteDeviceInfo VBRwDevice failed with: %r` 一句话定性

#### 优先级 3：XBL 如何验证 abl（决定"能否自造 abl"）
- 在 xbl.elf 里搜/定位 `ABL`、`LoadImage`、`SecBoot`、`is_secure_boot`、`AuthenticateImage`、`hash`、`RSA`、`OEM key` 相关代码路径
- 若为 XTC 证书链验签（很可能，因为作者必须用原厂签名 debug 构建），则"改 abl 重新打包"被彻底否决

#### 优先级 4：TZ secure state 的存储
- 在 tz.mbn 里对 `tz_get_secure_state` / `macchiato_is_secure_state` / `tz_is_sw_fuse_blown_secure` 做字符串 xref
- 看它是 RPMB 读、QFPROM eFuse 还是 TZ NV 变量
- 判读要点：若带 MAC/密钥保护 ⇒ 伪造不可行

#### 优先级 5：泛化
- 把"XTC 解密 + abl 解包 + LZMA/FV 解析 + VB Protocol 方法定位"固化成脚本
- 对任意 XTC 设备先跑"provider 是否存在 / 是否有 UserDebug 构建"这两个判定

### 可行解锁路径排序（DeepSeek 复查结论）
1. **让 devinfo 读成功**（需 provider + 可写的真实存储）— 待确认 provider 是否存在
2. **UserDebug ABL**（作者路径，已由指令级证实：thunk 返回 0 → IsUnlocked 恒 1）— 但需要官方签名的 UserDebug 镜像，且跨版本混刷会卡 logo
3. **找 ABL/XBL 的镜像验证绕过**（ABL 由 XBL 加载并验签 —— 作者必须用原厂签名 debug 构建正说明这一点）
4. **不要**去破坏 TZ（签名组件，砖机且不可逆）

---

## 十二、DeepSeek 第二轮复查关键修正清单

| 之前的结论 | 修正后 | 证据 |
|---|---|---|
| XTCReadWriteDeviceInfo 属于 FUN_0001cff8（+0x08） | 属于 **FUN_0001dbe0（+0x58）** | 错误串 xref = 0x1DC64/0x1DCAC（都在 0x1DBE0 内） |
| VB Protocol 有 3 个方法 | **至少 4 个方法**（+0x08/+0x30/+0x38/+0x58） | 0x1D098/0x1D96C/0x1D834/0x1DC80 的 `ldr x8,[x0,#imm]; blr x8` |
| "ReadSecureState 成功所以设备锁定" | **前提不成立**，读失败时 ReadSecureState 根本不被调用 | devinfo_buf[0x0D] 初值 0，读失败→早退→字节保持0→锁定 |
| magic="ANDROID-BOOT!" 是小天才自创 | **是标准 lk/高通 devinfo magic**，XTC 只扩展了大小 | AOSP lk app/aboot/devinfo.h + 字段名一致 |
| GUID 可能通过指令动态构造 | **倾向排除**，EDK2 常规做法是 .rodata 存储 | 108 文件 0 命中 + XBL FV 未压缩 + imagefv 内部 FV 无 GUID |
| Keymaster 可用于解锁 | **无利用价值**，Keymaster 是 boot state 消费者 | km41 是签名 TZ TA，改动不可行 |
| provider 可能在 XBL/tz/hyp | **不在任何 QFIL 包提供的组件里** | 108 文件 LE/BE 搜索 0 命中 |
| macchiato 是设备代号 | **是 TZ 安全模块程序名**（出现 85 次） | tz.mbn 中与 generate_keys/is_secure_state/authenticate_device 绑定 |

---

## 十三、作者镜像 vs v2.8.1 原版解密镜像 对比分析（2026-10-07）

> 对比对象：`offline-files/`（作者镜像）vs `decrypted_images/v2.8.1/`（原版解密镜像）
> 作者镜像本身就是明文（作者已解密），不需要再解密

### 13.1 ABL 对比 — 确认是不同构建（UserDebug）

| 项目 | 作者 abl_a.img | 原版 abl.elf |
|---|---|---|
| 大小 | 1,048,576 B（1MB，分区镜像含填充） | 155,744 B（纯 ELF） |
| ELF 提取后大小 | 155,744 B | 155,744 B |
| SHA256（提取后） | `e3ffcbc5ebc1ac5ca43031fdc6a5790a714e2fb81fd57fe4e9a6e9cc28cd868f` | `bc6f1bb07f51d71b662b2801d54b735416a348e82df7a2baa82faa54e64dd6cd` |
| 是否相同 | ❌ **不同** | |

- 前 64 字节（ELF 头）相同
- **首个差异位置: 0x1058**
- **字节差异: 144,114 / 155,744（92.5% 的字节不同！）**
- 结论：作者 abl 是完全不同的构建（UserDebug），不是简单 patch 原版
- 作者 abl_a.img 中 ELF 头在偏移 0x0，后面是 0xFF/0x00 填充到 1MB

### 13.2 vbmeta 对比 — 就是原厂原版，只是大小对齐

| 项目 | 作者 vbmeta_a.img | 原版 vbmeta.img |
|---|---|---|
| 大小 | 65,536 B（64KB） | 8,192 B（8KB） |
| AVB magic | AVB0 | AVB0 |
| **前 8192 字节差异** | **0** | |
| 原版内容位置 | **0x0**（开头就是原版） | |

- **作者 vbmeta 的前 8KB 与原版完全相同！**
- 后面 56KB 是 0x00 填充（对齐到分区大小 64KB）
- 结论：作者 vbmeta 就是原厂签名的 v2.8.1 vbmeta，**未做任何修改**

### 13.3 vbmeta_system 对比 — 同样是原厂原版

| 项目 | 作者 vbmeta_system_a.img | 原版 vbmeta_system.img |
|---|---|---|
| 大小 | 65,536 B | 4,096 B |
| 原版内容位置 | 0x0 | |

- 前 4KB 与原版完全相同，后面是填充
- 结论：未修改

### 13.4 boot 对比 — ramdisk 被修改（Magisk）

| 项目 | 作者 boot_a.img | 原版 boot.img |
|---|---|---|
| 大小 | 96 MB（相同） | 96 MB |
| magic | ANDROID! | ANDROID! |
| kernel_size | 0x1F2E360（相同） | 0x1F2E360 |
| **ramdisk_size** | **0x167EFC** | **0x12AE14** |
| second_size | 0x0（相同） | 0x0 |
| page_size | 0x1000（相同） | 0x1000 |
| dt_size | 0x2（相同） | 0x2 |
| name | console=ttyMSM0,（相同） | |
| cmdline | 前100字符相同 | |

- **ramdisk 作者比原版大了约 250KB**（0x167EFC - 0x12AE14 = 0x3D0E8）
- kernel 未修改（大小相同）
- 结论：作者 boot 只修改了 **ramdisk**（添加 Magisk），kernel 是原版
- 注：'magisk' 明文字符串在压缩的 ramdisk 中搜索不到，需解压后确认

### 13.5 对比总结

| 镜像 | 是否修改 | 修改方式 |
|---|---|---|
| abl | ✅ 已修改 | **官方 UserDebug 构建**（92.5% 字节不同，非 patch） |
| boot | ✅ 已修改 | ramdisk 添加 Magisk（大 250KB），kernel 未动 |
| vbmeta | ❌ 未修改 | 原厂原版，仅大小对齐到分区 |
| vbmeta_system | ❌ 未修改 | 原厂原版，仅大小对齐到分区 |
| super | ⏳ 待对比 | 3.75GB，需单独分析 |
| misc | ✅ 已修改 | 13 字节 "boot-fastboot"（原版是 "ffbm-02"） |
| recovery | ✅ 已修改 | TWRP recovery（非原厂） |
| firehose | ❌ 未修改 | v1.0.1 原版 firehose（SHA256 已确认） |

### 13.6 作者完整解锁方案（对比验证版）

```
1. EDL 刷入 v2.8.1 原版固件（全量包）
2. EDL 刷入作者镜像：
   - abl_a.img = 官方 UserDebug 构建（thunk 返回 0 → IsUnlocked 恒 1）
   - boot_a.img = Magisk 修补 ramdisk（root）
   - vbmeta_a.img = 原厂原版（未修改）
   - vbmeta_system_a.img = 原厂原版（未修改）
   - misc.img = "boot-fastboot"（强制进 fastboot）
3. fastboot boot TWRP recovery.img
4. adb sideload Dm.zip（AnyKernel3 Magisk 包，安装 Magisk 到 boot）
5. 重启 → 自动重启 3 次 → 获得 root 权限
```

**关键洞察**：
- 解锁的核心是 **UserDebug abl**（不是 devinfo，不是 vbmeta）
- vbmeta 完全未修改，说明 UserDebug abl 中 AVB 验证被绕过/容忍
- boot 的 Magisk 只是为了 root，不是解锁的必要条件
- 作者方案不需要修改任何签名验证相关的分区

---

## 十四、当前工作进度记录（2026-10-07 深夜）

### 已暂停的工作
- **VB Protocol provider 搜索**：已确认不在 QFIL 包提供的 108 个文件中
- 下一步本应：QMMI 下 dump 未提供文件的分区（toolsfv/catefv/catecontentfv/cateloader/uefivarstore/keystore/secdata）搜索 GUID

### 刚完成的工作
- ✅ 作者镜像 vs v2.8.1 原版解密镜像对比（abl/vbmeta/vbmeta_system/boot）
- ✅ 确认作者完整解锁方案（UserDebug abl + Magisk boot + 原厂 vbmeta）
- ✅ DeepSeek 三份报告审核（XBL验签链/作者镜像审核/super对比）
- ✅ **XTC 解密规则修正**：从"仅文件头 32 字节"修正为"每 1MB 块头 32 字节"（DeepSeek 对照实验验证，v1.0.1 boot vs 设备 dump 0 差异/96 块）
- ✅ **全量重解密**：v1.0.1（44 文件）和 v2.8.1（45 文件）按新规则重新解密

### 待完成
- ⏳ super.img 对比（3.75GB，需单独分析）
- ✅ ~~provider 搜索（QMMI dump 未提供文件的分区）~~ → **已完成：7 个分区 GUID 0 命中**
- 🔄 **XBL 验签链分析（进行中）**：
  - ✅ XBL 结构解析（11 段，seg14=UEFI FV，5 个 FFS）
  - ✅ 验签关键字符串定位（SecFuseLib/GetSecurityState/SecurityFlag @ seg14，timestamp @ seg05）
  - ✅ UEFIExtract 提取 FFS[0] TE image（233KB 明文，AArch64，ImageBase=0x5FC01000，EntryPoint=0xBC78）
  - ✅ FFS[2] GUIDED section 原始数据提取（1.7MB，高通自定义压缩 GUID=1D301FE9-BE79-4353-91C2-D23BC959AE0C，标准 UEFITool 解压失败）
  - ✅ Ghidra 导入 FFS[0] TE image（Raw Binary, base=0x5FC01000, AARCH64）
  - ✅ 解压相关字符串定位（LzmaDecompress.c/ZlibDecompress.c/GuidedSectionExtraction.c/Decompress GetInfo/Decompress Failed）
  - ✅ gzip 格式检测函数定位（FUN_5fc1b830，检查魔数 1F 8B 08）
  - ⏳ 找高通自定义 GUID（1D301FE9）对应的解压函数（看 FUN_5fc1b8b0 GuidedSectionExtraction 驱动的反编译）
  - ⏳ Ghidra 导入 seg05，用 timestamp 字符串 xref 定位验签函数
- ⏳ TZ secure state 存储分析

### provider 搜索最终结论（2026-10-08）
- QFIL 包提供的 108 个文件：GUID 0 命中
- 设备 dump 的 7 个未提供文件分区（toolsfv/catefv/catecontentfv/cateloader/uefivarstore/keystore/secdata）：GUID 0 命中，关键词 0 命中
- **总计 115 个文件/分区搜索，0 命中**
- **结论：VB Protocol provider 极大概率不存在于这台设备上**（LocateProtocol 必然失败 → devinfo 路径彻底死）
- 剩余可能性：GUID 以极端特殊方式存储（完全动态构造/加密存储），但概率极低
- **影响：解锁只剩两条路 —— (1) UserDebug abl（内部渠道）；(2) XBL 验签绕过**

---

## 十五、DeepSeek 三份报告核心结论（2026-10-08）

### 15.1 XBL 验签链 + 作者镜像审核

#### abl 签名结构（实测解出）
- abl 的 auth 段 @ 偏移 0x25000（PH[2] type=PT_NULL, 0x25000~0x26060）
- 结构：表头(version=0, num=6) + 长度/偏移字段 + 48B SHA-384 哈希表 + 96B ECDSA-P384 签名(r||s) + 3 张 EC 证书链
- 证书 OID：id-ecPublicKey、secp384r1、ecdsa-with-SHA384 → **整条链是 EC P-384，不是 RSA**
- 48B 哈希 = SHA-384(abl[0x1000:0x25000])，精确命中
- **结论：abl 是 ECDSA-P384 签名镜像，改一个字节都无法加载，除非拿到 XTC 私钥或找到验签绕过**

#### XBL 验签链
- XBL 侧：SecFuseLib/GetSecurityState → SecurityFlag(SecBootEnableFlag=0x1) → 读 abl → 逐段哈希校验(bl_elf_segs_hash_verify) → 认证安全哈希段(bl_sec_hash_seg_auth) → EC P-384 验签 → BDS 默认启动 "LinuxLoader"(=ABL)
- XBL 自带 XBL Sec Attestation 根/子 CA 证书链（2022-10-26 签发，位于 PH[15] 嵌套 ELF 内）
- 验签实现的符号串（ecdsa/sha384/mbedtls）在 XBL 中已被剥离，需用 P-384 曲线常数或 SecFuseLib 调用者反查

#### 作者镜像审核修正
- **boot header 解析错误**：0x28 是 header_version=2（不是 dt_size）；name 字段全 0（我们的 "console=ttyMSM0," 是读错切片）
- **漏掉 recovery_dtbo 段**：作者 boot 有 695,380 字节，原版为 0
- **作者 boot 不是"只换 ramdisk"**：重打包改变了段布局（多了 recovery_dtbo，像 magiskboot/AnyKernel 重打包副产品）
- Magisk 已证到文件级：ramdisk 解压后有 .backup/.magisk、magisk32.xz、stub.xz、magiskinit
- misc="boot-fastboot" 是 **fastbootd（userspace fastboot）** 指令，不是"强制进 bootloader"
- vbmeta 结论完全正确（原厂未修改，前 8192 字节逐字节相同，其余全 0）

### 15.2 XTC 解密规则修正（重大！）

#### 旧规则（错误）
- 文件 > 32768 字节：仅前 32 字节 XOR

#### 新规则（正确，DeepSeek 对照实验验证）
- 文件 <= 32768 字节：全文 XOR KS[0:len]
- 文件 > 32768 字节：**每个 1MB (0x100000) 块的头 32 字节** XOR
- 第 k 块（k=0,1,2,...）用密钥流偏移 `KS[(64*k) mod 16384 : +32]`
- 加密器每处理一个 1MB 块，密钥流前进 64 字节（只消费 32 字节）

#### 验证
- 已知明文对：v1.0.1 加密 boot.img vs 设备 dump boot_v101.img
- 按新规则解密后，前 100663296 字节 **0 差异 / 96 块** ✅
- v1.0.1 super 分块按新规则解密后与设备 dump **0 差异 / 2.4GB** ✅
- 工具 `tools/xtc_fw_decrypt.py` 已更新，全量重解密完成（v1.0.1: 44 文件，v2.8.1: 45 文件）

#### 影响
- 之前的 `decrypted_images/*` 对所有大文件（boot/recovery/super/NON-HLOS/persist/xbl）只解密了前 32 字节，实际每个 1MB 块头都需要解密
- 之前基于旧解密结果的大文件对比（如"kernel 差 989 字节"）都是未解密的块头假差异，**已撤回**
- 后续所有大文件对比必须使用新解密结果

### 15.3 super 对比结论

#### LP 元数据
- 两边结构**完全一致**：geometry/metadata header/版本(10.2)/描述符(partitions/extents/groups/bdevs)全部相同
- 整个元数据区仅 435 字节差异（主要是两个校验和 header_checksum/tables_checksum）
- **不是"布局被重排"**

#### 内容差异
- 数据区 **97.07% 的字节不同**（24.2 亿 / 24.9 亿字节）
- 对照实验排除方法错误（v1.0.1 设备 dump vs 分块 = 0 差异）
- 两种可能：(a) 作者改写了 super 内容；(b) 作者设备的 v2.8.1 与 QFIL 包**不是同一个构建**
- **"super = 原版 + fstab 微调"的假设不成立**
- 定性方法：用 vbmeta 的 vendor/system hashtree 根摘要交叉验证

---

## 十六、关于"能否解锁 BL"的分析（2026-10-08）

### 当前已知的解锁路径

| 路径 | 可行性 | 说明 |
|---|---|---|
| **作者方案：UserDebug abl** | ✅ 已验证可行 | 官方 UserDebug 构建，thunk 返回 0 → IsUnlocked 恒 1；但需要原厂签名的 UserDebug 镜像，跨版本混刷会卡 logo |
| 手动写 devinfo | ❌ 已验证失败 | ABL 不直读 eMMC，通过 VB Protocol 读取，provider 可能缺失 |
| 标准 fastboot 解锁 | ❌ 不可行 | unknown command，小天才移除了标准接口 |
| 自造/改写 abl | ❌ 不可行 | ECDSA-P384 签名，XBL secboot 验签，改一个字节都无法加载 |
| VB Protocol fail-open | ⏳ 待确认 | provider 缺失时 ReadSecureState 不可达（读失败→早退→锁定）；需先确认 provider 是否存在 |
| XBL 验签绕过 | ⏳ 未研究 | 需在 XBL 中找验签实现的漏洞，难度极高 |
| 拿到 XTC 私钥 | ❌ 不可能 | 私钥在厂商手中，不可能获取 |

### 作者是否有 XTC 私钥和构建？

**分析：**
1. **作者 abl 是官方 UserDebug 构建**，不是手工 patch 的 release abl（92.5% 字节不同，.text 大 28KB，独有 UserDebug 路径字符串）
2. **作者 abl 有原厂签名**（ECDSA-P384 证书链与 stock 同源，Attestation CA 有效期 2025-01-10）
3. 这意味着作者要么：
   - (a) **从 XTC 内部获取了 UserDebug 构建的镜像**（不需要私钥，只需要已签名的镜像文件）
   - (b) **有能力编译 UserDebug 构建并让 XTC 签名**（需要私钥或内部关系）
   - (c) **找到了 XBL 验签绕过**，可以加载未签名/自签名镜像（但目前无证据）

**最可能的情况是 (a)**：作者从某个渠道（内部泄露、工程机提取、XTC 员工等）获得了已签名的 UserDebug 构建镜像。UserDebug 构建本身是厂商编译并签名的，作者不需要私钥，只需要拿到镜像文件。

**证据支持 (a)**：
- 作者 abl 的 Attestation CA 有效期 2025-01-10，与 stock 同源 → 是原厂签名
- UserDebug 构建通常用于内部测试/工程机，可能通过非官方渠道流出
- 作者的 firehose 是 v1.0.1 原版（未修改），说明作者没有修改底层工具的能力
- 作者的 vbmeta 完全未修改，说明作者没有能力/不需要修改签名验证相关分区

### 对 v1.0.1 的启示

- v1.0.1 版本**可能也存在对应的 UserDebug 构建**（如果厂商做过），但我们没有
- 跨版本混刷（v2.8.1 UserDebug abl + v1.0.1 system）会卡 logo，因为 abl 与 system 版本不匹配
- **如果能找到 v1.0.1 的 UserDebug abl**，就可以直接用作者的方案解锁 v1.0.1
- 或者：**在 v2.8.1 系统上使用作者的 UserDebug abl 解锁**（这是作者已经验证的方案），然后再考虑降级/升级

### 结论

**不是"完全没办法解锁"，而是：**
1. ✅ **v2.8.1 可以解锁**（用作者的 UserDebug abl + Magisk boot，作者已验证）
2. ⏳ **v1.0.1 解锁需要找到 v1.0.1 的 UserDebug abl**，或者研究其他路径（VB Protocol provider、XBL 验签绕过等）
3. ❌ **自造 abl 不可行**（ECDSA-P384 签名，XBL secboot 验签）
4. ❌ **手动写 devinfo 不可行**（ABL 通过 VB Protocol 读取，provider 可能缺失）

**作者最可能是从内部渠道获得了已签名的 UserDebug 构建镜像，而不是拥有 XTC 私钥。**

---

## 十七、XBL 解压函数分析（2026-10-08）

### 17.1 FFS[0] TE image 信息

- 文件：`unpacked_xbl/v1.0.1/ffs0_sec_core_te.bin`（233,672 字节）
- 格式：TE (Terse Executable)，签名 "VZ"
- Machine：0xAA64（AArch64）
- NumberOfSections：3
- ImageBase：0x5FC01000
- BaseOfCode：0x1000 → 代码起始 VA = 0x5FC02000
- AddressOfEntryPoint：0xBC78 → 入口点 VA = 0x5FC0CC78
- Ghidra 导入设置：Raw Binary, base=0x5FC01000, Language=AARCH64:LE:64:v8A

### 17.2 解压相关字符串定位（全部在 FFS[0] 内）

| 字符串 | VA | 说明 |
|---|---|---|
| `LzmaDecompress.c` | 0x5fc2e15c | LZMA 解压源文件名 |
| `ZlibDecompress.c` | 0x5fc2e188 | Zlib 解压源文件名 |
| `GuidedSectionExtraction.c` | 0x5fc2e125 | GUIDED section 提取驱动 |
| `Decompress GetInfo F...` | 0x5fc2e285 | GetInfo 函数日志 |
| `Decompress Failed - ...` | 0x5fc2e150 | 解压失败日志 |
| `BaseUefiDecompressLib.c` | 0x5fc2f1bf | 基础 UEFI 解压库 |
| `SourceSize >= (5 + 8)` | 0x5fc2e16d | LZMA 头部大小检查（5B属性+8B解压大小=13B） |
| `InputSection != ((void *) 0)` | 0x5fc2e13f | 输入指针非空检查 |
| `TopBit != 0"` | 0x5fc2e119 | 位操作检查 |

### 17.3 gzip 格式检测函数 FUN_5fc1b830

**反编译代码**：
```c
undefined8 FUN_5fc1b830(undefined1 param_1[16], ..., char *param_9)
{
    if ((*param_9 == 0x1F) && (param_9[1] == 0x8B) && (param_9[2] == 0x08)) {
        return 1;  // 是 gzip 格式
    } else {
        FUN_5fc158e0(..., 0x80000000, 0x5fc2e16e);
        return 0;  // 不是 gzip
    }
}
```

**分析**：
- 检查输入数据前 3 字节是否为 `1F 8B 08`（gzip 魔数 + deflate 方法）
- 如果是 gzip，返回 1（支持）
- 否则调用 `FUN_5fc158e0`，返回 0（不支持）
- 这个函数在 `LzmaDecompress.c` 文件里，是统一解压框架的格式分发函数
- **注意：这不是核心解压函数，只是格式检测**

### 17.4 相关函数地址索引

| 函数 VA | 说明 |
|---|---|
| `FUN_5fc1b830` | gzip 格式检测（检查魔数 1F 8B 08） |
| `FUN_5fc158e0` | 被 FUN_5fc1b830 调用，可能是实际解压函数 |
| `FUN_5fc1b8b0` | GuidedSectionExtraction 驱动（引用 "GuidedSectionExtraction.c"），XREF[2] |
| `FUN_5fc1bd18` | 被 FUN_5fc1b8b0 调用，可能是 GUIDED section 处理入口 |
| `FUN_5fc159d8` | 日志/断言函数（被多处调用，传入字符串和行号） |

### 17.5 FFS[2] 压缩格式分析

- FFS[2] 是 COMBINED_PEIM_DRIVER，大小 931,512 字节
- FFS[2] body 是高熵数据（熵 7.947），被压缩或加密
- GUIDED section GUID = `1D301FE9-BE79-4353-91C2-D23BC959AE0C`（高通自定义，非标准 LZMA/Tiano）
- 标准 UEFIExtract 解压失败：`decompression failed with error Unknown error 1A`
- FFS[2] GUIDED section 原始数据已提取：1.7MB（在 UEFIExtract dump 目录）

**待解决**：找到 GUID `1D301FE9` 对应的解压函数。可能的方法：
1. 分析 `FUN_5fc1b8b0`（GuidedSectionExtraction 驱动）的反编译，找 GUID 到解压函数的映射表
2. 在 Ghidra 中搜索 GUID 字节模式 `E9 1F 30 1D 79 BE 53 43 91 C2 D2 3B C9 59 AE 0C`
3. 分析 `FUN_5fc1bd18` 的反编译，看它如何处理不同 GUID

### 17.6 安全状态相关字符串

| 字符串 | VA | 所在 |
|---|---|---|
| `SecFuseLib.c` | 0x5fc2f082 | FFS[0]（XREF 指向日志函数 FUN_5fc0a450） |
| `GetSecurityState Failed!` | 0x5fc2f067 | FFS[0]（XREF[0,1]，写引用，无直接读引用） |
| `SecurityFlag = 0xC4` | 0x5fc3cca8 | **FFS[1]（uefiplat.cfg 配置文件，非代码）** |
| `SecBootEnableFlag = 0x1` | 0x5fc3ccbe | FFS[1]（配置文件） |
| `DefaultBDSBootApp = "LinuxLoader"` | 0x5fc3d056 | FFS[1]（配置文件） |

**注意**：`SecurityFlag` 和 `SecBootEnableFlag` 不在代码里，而在 FFS[1]（uefiplat.cfg）配置文件中。这是 XBL 的配置数据，不是代码逻辑。

### 17.7 解压协议初始化函数 FUN_5fc14f24（2026-10-08 深入分析）

**反编译代码核心逻辑**：
```c
// 1. 获取某个服务（可能是 DecompressProtocol / GuidedSectionExtractionProtocol）
lVar1 = FUN_5fc25a60(...);

// 2. 通过函数指针调用服务的方法，注册标准 EFI LZMA GUID
lVar1 = (**(code **)(lVar1 + 8))(
    s_DB:Support:_5fc2ce92 + 10,   // 协议 GUID
    DAT_5fc322f8,                    // 标准 EFI LZMA GUID (EE4E5898-3914-4259-9D6E-DC7BD79403CF)
    &DAT_5fc322f8                    // GUID 指针
);

// 3. 把 setter 函数地址写入函数指针变量
DAT_5fc32308 = 0x5fc14bf0;
```

**分析结论**：
- `FUN_5fc14f24` 是**解压协议初始化/注册函数**
- 它只注册了**标准 EFI LZMA GUID**（EE4E5898-...）
- **高通自定义 GUID（1D301FE9-...）没有在这里注册**
- `0x5fc14bf0` 被写入 `DAT_5fc32308`，但它只是一个 setter 函数（见 17.8）

### 17.8 GUID 表与 setter 函数分析

**GUID 数据位置（FFS[0] 内）**：

| 地址 | 内容 | 引用者 |
|---|---|---|
| `0x5fc32288` | 高通自定义 GUID（1D301FE9-BE79-4353-91C2-D23BC959AE0C） | **0 个直接引用** |
| `0x5fc322f8` | 标准 EFI LZMA GUID（EE4E5898-3914-4259-9D6E-DC7BD79403CF） | FUN_5fc14f24（XREF[2]） |
| `0x5fc32308` | 函数指针变量（被赋值为 0x5fc14bf0） | FUN_5fc14f24（写引用） |

**关键发现**：
- 高通自定义 GUID（0x5fc32288）和标准 LZMA GUID（0x5fc322f8）只相差 0x70 字节，**很可能在同一个 GUID 表/数组里**
- 但高通自定义 GUID 没有直接引用者，说明它可能通过**表索引间接访问**，或者在另一个注册函数里注册

**FUN_5fc14bf0（setter 函数）反编译**：
```c
void FUN_5fc14bf0(undefined8 param_1) {
    *(undefined8 *)(x22 + 0x28) = param_1;  // 写入某个状态变量
    return;
}
```
- 这不是解压函数，只是一个 setter/回调函数
- 被注册到 `DAT_5fc32308`，可能用于设置解压输出缓冲区或状态

### 17.9 gzip 解压函数 FUN_5fc1b8b0 完整分析

**反编译核心逻辑**：
```c
if ((((9 < param_10) && (param_9 != NULL)) && (param_11 != 0)) &&
    ((param_12 != 0 &&
      (uVar3 = FUN_5fc1b830(param_9), (uVar3 & 0xff) != 0)))) {
    // gzip 格式处理路径：
    // - 解析 gzip 头部（flags 字段 param_9[3]）
    // - 跳过 FNAME/FCOMMENT/FHCRC 可选字段
    // - 调用 FUN_5fc1bd18 / FUN_5fc1bdbc 实际解压
    // - 校验解压后大小（local_88 != uVar3 则死循环）
    ...
    return 0;
}
return 0x8000000000000002;  // 不是 gzip → 直接返回错误
```

**结论**：`FUN_5fc1b8b0` **只处理 gzip 格式**，不是处理 FFS[2]（高通自定义压缩）的函数。

### 17.10 更新后的函数地址索引

| 函数 VA | 说明 |
|---|---|
| `FUN_5fc14f24` | **解压协议初始化函数**，注册标准 EFI LZMA GUID |
| `FUN_5fc14bf0` | setter 函数（写入 x22+0x28），被注册到 DAT_5fc32308 |
| `FUN_5fc25a60` | 被 FUN_5fc14f24 调用，可能是 LocateProtocol/获取服务 |
| `FUN_5fc1b830` | gzip 格式检测（检查魔数 1F 8B 08） |
| `FUN_5fc1b880` | 读 3 字节辅助函数 |
| `FUN_5fc1b8b0` | gzip 解压处理（只处理 gzip，非 gzip 返回错误） |
| `FUN_5fc1bd18` | 被 FUN_5fc1b8b0 调用（gzip 解压路径） |
| `FUN_5fc1bdbc` | 被 FUN_5fc1b8b0 调用（gzip 解压路径，返回 uint*） |
| `FUN_5fc1d1f4` | 被 FUN_5fc1b8b0 调用（gzip 解压路径） |
| `FUN_5fc158e0` | 被多处调用，可能是实际解压/错误处理 |
| `FUN_5fc159d8` | 日志/断言函数（被多处调用，传入字符串和行号） |

### 17.11 下一步计划（更新）

1. **找高通自定义 GUID（1D301FE9）的注册函数**（P0）
   - 方法 A：找 FUN_5fc14bf0 的引用者（XREF），顺藤摸瓜
   - 方法 B：搜索其他调用 `(**(code **)(... + 8))` 模式的函数（类似注册逻辑）
   - 方法 C：搜索完整 16 字节 GUID，看有没有其他位置
2. **找到实际解压函数后，用 Python 复刻算法解压 FFS[2]**（P0）
3. **定位验签函数**（P1）— Ghidra 导入 seg05，用 timestamp 字符串 xref
4. **审计验签代码找漏洞**（P2）— 重点看 auth 段解析器的边界检查

---

## 第十八章：DeepSeek 颠覆性更正 — FFS[2] 是标准 gzip，VB provider 存在！（2026-10-08）

> **这是整个项目的转折点。** DeepSeek 独立复测完全推翻了第十七章的多个核心假设。

### 18.1 四条颠覆性更正

| # | 我们之前的结论 | DeepSeek 实测结果 |
|---|---|---|
| C1 | 外层 FV 有 **5 个 FFS**（含 COMBINED_PEIM_DRIVER、第二个 SEC_CORE） | 实际只有 **3 个文件**：Pad + SEC core + uefiplat.cfg + **Volume image**。COMBINED_PEIM_DRIVER 和第二个 SEC_CORE 是**解析假象** |
| C2 | FFS[2] 是"高通自定义压缩"，UEFIExtract 解压失败 | 它是**标准 gzip**（`1F 8B 08`），zlib 一次解压成功，得到 **4.71MB 的 DXE 固件卷（87 个模块）**。UEFIExtract 失败只是因为它的库里没有这个 section GUID |
| C3 | 明文部分找不到 SHA-384/P-384 常数 ⇒ 验签实现在别处 | SHA-384 常数表**就在 XBL 里**，在 gzip 解压后的 `HashDxe` 模块中。之前找不到是因为它们在**压缩数据内部** |
| C4 | VB Protocol provider 在 115 个文件 0 命中 ⇒ devinfo 路径彻底死亡 | **provider 存在！** 是 DXE 卷里的 `VerifiedBootDxe`（61KB），字符串明确写着 `Succeed using devinfo!` / `Succeed using rpmb!` / `XTC RWDeviceState: write_partition`。**devinfo 路径复活！** |

### 18.2 为什么我们之前解压失败？—— body.bin 是坏的！

**关键发现：我们的 `body.bin` 有 64 字节错误。**

- DeepSeek 从解密镜像重新切出的 body 和我们的 body.bin **长度相同，但 64 字节不同**
- 差异位置：`0x57BB0–0x57BCF` 和 `0x157BB0–0x157BCF`（两段 32 字节，间隔正好 1MiB）
- 换算到 xbl.elf 即 `0xFF000` 和 `0x1FF000` = **每个 1MiB 边界前 0x1000**
- 后果：gzip **CRC 校验失败**（`0xdd523cd2 != 0xe324df3f`），所以解压失败

**根因：我们的 XOR 解密在 1MiB 网格上残留了 32 字节头，网格相位比文件起点晚 0x1000。**

> ⚠️ **需要修复解密工具 `xtc_fw_decrypt.py` 的 XOR 网格相位问题，然后重新解密所有镜像。**

### 18.3 外层 FV 真实结构

FV 位于 xbl.elf 文件偏移 `0x6B000`（VA `0x5FC00000`），`FvLength = 0x20CA00`。

| # | 文件偏移 | 文件名/GUID | 类型 | 大小 |
|---|---|---|---|---|
| 0 | 0x06B048 | FFFFFFFF-…（Pad） | 0xF0 | 0xFA0 |
| 1 | 0x06BFE8 | `8AF09F13-44C5-96EC-1437-DD899CB5EE5D` | 0x03 SEC core | 0x3A018 (237,592) |
| 2 | 0x0A6000 | `DDE58710-41CD-4306-DBFB-3FA90BB1D2DD` = uefiplat.cfg | 0x02 Freeform | 0x241E (9,246) |
| 3 | 0x0A8420 | `9E21FD93-9C72-4C15-8C4B-E77F1DB2D792` | **0x0B Volume image** | 0x1A3EB5 (1,719,989) |

文件 3 内部只有一个段：
- SectionDefinitionGuid = `1D301FE9-BE79-4353-91C2-D23BC959AE0C`
- DataOffset=0x18, Attributes=0x0001 (PROCESSING_REQUIRED)
- body @0x0A8450, 长度 0x1A3E85 = 1,719,941

### 18.4 FFS[2] = 标准 gzip 压缩的 DXE 卷

**压缩算法确认：标准 gzip（DEFLATE）**

证据：
1. body 头 10 字节 = `1F 8B 08 00 00 00 00 00 00 03` ⇒ gzip 魔数 + DEFLATE + MTIME=0 + OS=3(Unix)
2. `zlib.decompress(body, 16+15)` → **4,942,664 B**，`eof=True`，`unused_data=0`
3. 熵=7.947 是 DEFLATE 输出的典型值（实测 7.9813），**不是加密的证据**
4. LZMA 方向全部排除（6 组 lc/lp/pb × 8 组 dict × 7 个偏移全部失败）

**解压后的结构**：
```
0x0000  04 00 00 19    ← 段流: RAW 段, size=4
0x0004  44 6B 4B 17    ← 段流: FV_IMAGE 段(type 0x17), size=0x4B6B44
0x0008  ..._FVH...     ← 内层固件卷起点
```

即：GUIDed 段的解压产物是一个"段流"，其中 FV_IMAGE 段的载荷才是 DXE 固件卷。

**跨版本验证**：v1.0.1 和 v2.8.1 结构完全一致，都能 gzip 解压成功（v1.0.1→4,942,664 B，v2.8.1→5,331,080 B）。这是本平台**稳定的构建约定**。

### 18.5 内层 DXE 卷（87 个模块）

解压后得到 4.71MB DXE 固件卷，包含 **87 个文件**：
- 1 Pad + 1 DxeCore + 72 DXE_RUNTIME_DRIVER + 2 APPLICATION + 11 FREEFORM

**验签链模块**：

| 模块 | GUID | 大小 | 作用 |
|---|---|---|---|
| **VerifiedBootDxe** | `A25F5839-4D55-428F-8F0B-5CE1D565F53E` | 61,512 | **VB Protocol provider**；devinfo/rpmb 读写；解锁状态判断 |
| **ASN1X509Dxe** | `C2F9A4F5-F7B4-43E7-BA99-5EA804CC103A` | 41,016 | X.509 证书解析；`rsa_from_vb_signature` |
| **HashDxe** | `3ADF8DDA-1850-44C5-8C63-BB991849BC6F` | 98,352 | SHA-256/384/512 常数表和实现 |
| **SecRSADxe** | `32C71E68-83A8-46ED-AED1-094E71B12057` | 41,012 | RSA 原语 |
| **TzDxe / ScmDxe** | `6925FAD3…` / `2D7A83E3…` | 70K/49K | TZ 和 SCM 通道 |
| **QcomBds / Ebl** | `5A50AA81…` / `3CEF354A…` | 107K/127K | BDS 启动决策，fastboot 命令表 |

**VerifiedBootDxe 关键字符串**：
- `VB: verify_algorithm_id`
- `VB: VerifyImage: Image verification done! boot state is: GREEN/ORANGE/UNDEFINED`
- `VB: DeviceInit: Device is unlocked! Skipping verification!`
- `VB: RWDeviceState: Succeed using devinfo!` / `Succeed using rpmb!`
- `VB: XTC RWDeviceState: write_partition err!`
- `VB: readSecurityState: Locate SCM Status`
- `SecurityFlag`, `devinfo`, `keymaster`, `gQcomQseecomProtocolGuid`

### 18.6 GUID 注册机制的更正

- 16 次调用 0x5FC13B30 **是真的**，但**不是**"注册 guided-section 解压处理器"
- 它是一个 **"GUID → 小块数据"的登记表**，登记的数据大小是 1/4/8/16 字节（既有函数指针，也有状态位）
- **FUN_5fc1b830/FUN_5fc1b8b0 就是处理 FFS[2] 的 gzip 解压函数！** 第十七章的判断错误
- 方法论教训：**"没有直接 xref"在本工程里不能证明"未被使用"**（它们经间接/表调用）

### 18.7 XBL 11 个非空 LOAD 段实测

| PH | VA | filesz | 熵 | 判读 |
|---|---|---|---|---|
| 4 | 0x0C24E000 | 214,700 | 6.61 | ARM64 代码 |
| 5 | 0x0C285000 | 93,336 | 3.85 | 数据（含 timestamp 字符串，**不是验签代码**） |
| 6 | 0x0C2B2000 | 96,124 | 6.60 | ARM64 代码（PBS RAM / image_verify 文案） |
| 7 | 0x0C2D5000 | 7,529 | 3.19 | 表数据 |
| 11 | 0x0C119000 | 10,192 | 6.39 | ARM64 代码 |
| 12 | 0x0C11C000 | 3,676 | 3.82 | 数据（未初始化填充图案） |
| **14** | **0x5FC00000** | **2,148,864** | 6.17 | **UEFI FV（外层，含压缩 DXE 卷）** |
| 15 | 0x0C351000 | 163,840 | 4.67 | 嵌套 ELF（证书链：XBL Sec Attestation Root CA 4 Sub CA 10） |
| 16 | 0x45E35000 | 307,191 | 6.72 | `*XBLRamD…` 头的 blob（**值得单独看**） |
| 17 | 0x45EA7000 | 23,320 | 4.35 | 数据表 |

### 18.8 小米方案的参考价值

- **概念可借鉴、实现不可抄**
- EDL/firehose 协议本身不做签名校验，"用 EDL 写标志位"技术上成立
- 卡点是**写完之后谁信这个标志** —— 现在答案是 `VerifiedBootDxe` 通过 devinfo 或 RPMB 读取
- **devinfo 写入代码路径确实存在**（`XTC RWDeviceState` 的写分支）

### 18.9 已验证死路的更新

从死路列表中**移除**：
- ~~❌ VB Protocol provider 路径（115个文件/分区 0 命中）~~ → **provider 存在，是 VerifiedBootDxe**
- ~~❌ 手动写 eMMC devinfo 分区（ABL 通过 VB Protocol 读取，provider 缺失）~~ → **需要用新信息重做**

仍然有效的死路：
- ❌ 标准 fastboot 解锁命令（unknown command，小天才移除）
- ❌ AVB 重命名漏洞（直接到 bootloader）
- ❌ flags=2 vbmeta（原理不可能）
- ❌ 手动制作 Magisk boot（8个致命缺陷）
- ❌ 方案 A（刷回原版 abl 不保留 unlocked）— **但 devinfo 路径本身复活了，需要重新评估**
- ❌ 跨版本混刷（卡 logo）
- ❌ QMMI 下写分区（AVB 校验，开不了机）
- ❌ adb root 装第三方软件（XTC 魔改系统禁用）
- ❌ switch.db 绕过（有时间限制）
- ❌ shizuku（系统禁用）
- ❌ 白名单应用签名绕过（系统验证签名）

### 18.10 下一步计划（重大更新）

#### P0 — 立即做（最高价值）

1. **修复解密工具的 XOR 网格相位问题**
   - 问题：每 1MiB 边界前 0x1000 处有 32 字节残留
   - 重新解密 xbl.elf，重新切 body，gzip 解压验证
   - 或者直接用 DeepSeek 生成的 `inner_fv.bin`（4.71MB DXE 卷）

2. **逆向 VerifiedBootDxe.pe32（61KB）**
   - 定位 devinfo 记录结构（偏移/长度/校验）
   - 找到读/写函数和 `XTC RWDeviceState` 的 op 码
   - 确认 ABL 读的是哪一位（对照 abl `FUN_00016408` 读 `devinfo[0x0D]`）

3. **按新结构重测 devinfo 写入**
   - 先完整 dump 原始 devinfo 备份
   - EDL 写入修改后的 devinfo
   - 冷启动观察是否触发 `Device is unlocked! Skipping verification!`

#### P1 — 高价值

4. **逆向 Ebl（127KB）和 QcomBds（107KB）**
   - 找 fastboot 命令表（为什么 `fastboot boot` 是 unknown command）
   - 找解锁相关 UI 和"谁能调用写状态"

5. **分析 SecurityFlag/SecBootEnableFlag 的实际读取方**

#### P2 — 中价值

6. **分析 PH16（0x45E35000，307KB，`*XBLRamD…` 头）**
7. **把 gzip 解压流程固化进工具链**

#### P3 — 低价值（暂缓）

8. 畸形 auth 段黑盒 fuzz
9. 继续找"FFS[4] SEC_CORE"（已证不存在）

### 18.11 DeepSeek 生成的产物

- `unpacked_xbl/v1.0.1/inner_fv.bin`（4,942,664 B，DXE 卷）
- `unpacked_xbl/v1.0.1/inner_fv_modules.txt`（87 模块清单）
- `unpacked_xbl/v1.0.1/VerifiedBootDxe.bin`（FFS 文件，61,512）
- `unpacked_xbl/v1.0.1/VerifiedBootDxe.pe32`（PE32 载荷，61,440，`MZ` 开头）
- `deep_check/` 目录下的分析脚本（check_ffs2deep.py, check_inner_fv.py 等）

---

## 第十九章：VerifiedBootDxe 初步分析（2026-10-08）

### 19.1 VerifiedBootDxe 文件信息

- 文件：`unpacked_xbl/v1.0.1/VerifiedBootDxe.pe32`
- 大小：61,440 字节
- 格式：PE32+ (AArch64, Machine=0xAA64)
- ImageBase：0x0
- EntryPoint：0x1000
- 3 个节区：
  - `.text`：VA=0x1000, 大小=0xC000（代码段）
  - `.data`：VA=0xD000, 大小=0x1000（数据段）
  - `.reloc`：VA=0xE000, 大小=0x1000（重定位段）

### 19.2 关键字符串（412 个 ASCII 字符串）

**解锁判断相关**：
- `VB: DeviceInit: Device is unlocked! Skipping verification!` @ 0x08C51
- `VB: VerifyImage: Image verification done! boot state is: ` @ 0x09644
- `ORANGE` @ 0x09692
- `UNDEFINED` @ 0x0969A

**RWDeviceState（标准高通版）**：
- `VB: RWDeviceState: Succeed using devinfo!` @ 0x08FA1
- `VB: RWDeviceState: Succeed using rpmb!` @ 0x08FCC
- `VB: RWDeviceState: write_partition err! status: %d` @ 0x08DE5
- `VB: RWDeviceState: read_partition err! status: %d` @ 0x08ECA
- `VB: RWDeviceState: invalid operation op = %x` @ 0x08F72

**XTC RWDeviceState（小天才定制版）**：
- `VB: XTC RWDeviceState: write_partition err! status: %d` @ 0x0981A
- `VB: XTC RWDeviceState: read_partition err! status = %x` @ 0x09853
- `VB: XTC RWDeviceState: invalid operation op = %x` @ 0x0988C
- `VB: XTC RWDeviceState: Succeed using devinfo!` @ 0x098BF

**安全状态相关**：
- `SecurityFlag` @ 0x097E0
- `VB: readSecurityState: Locate SCM Status: (0x%x)` @ 0x0A95C
- `VB: Non-secure device: Security State: (0x%x)` @ 0x0A9C5
- `VB: Is_Device_Secure: Cannot read security state` @ 0x09612

**分区名**：
- `devinfo` @ 0x08CF8
- `keymaster` @ 0x08D3C

### 19.3 函数定位

**RWDeviceState 函数**（推测 @ 0x1700 附近）：
- 包含 `Succeed using devinfo!`（@0x1814）和 `Succeed using rpmb!`（@0x1820）两个相邻分支
- 说明函数内有一个判断：优先用 devinfo，失败则用 rpmb
- 调用了 `read_partition`/`write_partition` 底层函数

**大函数 @ 0x1A10**（sub sp, #0x400）：
- 可能是 DeviceInit 或模块入口
- 引用 .data 段全局变量（0xD000）
- 有 vtable 调用（`ldr x8, [x9, #0x2C8]` → `ldr x8, [x8, #0x140]` → `blr x8`）

### 19.4 字符串引用分布

所有字符串引用集中在 0x1500-0x2A00 范围：
- 0x159C-0x19FC：RWDeviceState / Send_Milestone / Reset_State
- 0x1C90-0x1FC0：SendROT 相关
- 0x20F4-0x22D8：VerifyImage / GetCertFingerPrint
- 0x2964-0x29F0：write_partition 底层
- 0x2CE8：vb_get_image_hash

### 19.5 两套 RWDeviceState 的意义

小天才在高通 VerifiedBootDxe 基础上做了定制：
1. **标准高通版 RWDeviceState**：devinfo + rpmb 两条路径
2. **XTC 定制版 RWDeviceState**：只有 devinfo 路径（字符串里没有 rpmb）

这说明小天才可能：
- 替换或包装了高通的 RWDeviceState
- 或者添加了一个新的 XTC 专用接口
- XTC 版可能有不同的 op 码和数据结构

### 19.6 Ghidra 交互式分析结果（2026-10-08 晚）

#### 核心函数定位

| 函数 | 地址 | 功能 |
|------|------|------|
| DeviceInit | FUN_000013b0 | 初始化设备状态，设置解锁标志 |
| VerifyImage | FUN_00002034 | 验证镜像，解锁则跳过验证 |
| 标准 RWDeviceState | FUN_00001470 | 高通版读写设备状态（rpmb+devinfo） |
| XTC RWDeviceState | FUN_00002388 | 小天才版读写设备状态（仅 devinfo） |
| vb_get_image_hash | FUN_00001a10 | 计算镜像哈希 |

#### VerifiedBoot Protocol 函数指针表（@0xd160）

| 偏移 | 函数 | 功能 |
|------|------|------|
| 0xd168 | FUN_00001470 | 标准 RWDeviceState |
| 0xd170 | FUN_000013b0 | DeviceInit |
| 0xd188 | FUN_00002034 | VerifyImage |

#### DeviceInit 函数（FUN_000013b0）反编译

```c
longlong FUN_000013b0(undefined8 param_1, char *param_2)
{
  if (param_2 == NULL) return ERROR;
  lVar1 = FUN_000025d8(DAT_0000d2c8);  // 初始化 ASN1X509
  if (lVar1 == 0) {
    _DAT_0000d1e4 = *(undefined2 *)param_2;  // 保存状态前2字节
    if (*param_2 == '\0') {
      DAT_0000d158 = 0;  // 🔒 空字符串 → 锁定
    } else {
      DAT_0000d158 = 1;  // 🔓 非空字符串 → 解锁！
      FUN_00004f08(0x80000000, 0x8c51);  // "Device is unlocked!"
    }
    DAT_0000d1e0 = 1;  // 初始化完成
  }
  return lVar1;
}
```

**关键**：param_2 是设备状态字符串，第一个字节非零=解锁，零=锁定。

#### VerifyImage 函数（FUN_00002034）反编译（核心！）

```c
longlong FUN_00002034(...)
{
  if (DeviceInit未完成) DAT_0000d158 = 0xffffffff;
  else if (参数无效) DAT_0000d158 = 0xffffffff;
  else if (DAT_0000d158 == 1) {
    // 🔓 设备已解锁！直接返回成功，跳过所有验证！
    lVar4 = 0;
  } else {
    // 🔒 设备锁定，执行完整验证
    哈希验证 → 公钥验证 → 签名验证
    成功 → DAT_0000d158 = 0  // GREEN
    部分成功 → DAT_0000d158 = 2  // YELLOW
    失败 → DAT_0000d158 = 3  // ORANGE → 死机
  }
  // 打印 "VerifyImage: Image verification done! boot state is: GREEN/YELLOW/ORANGE"
}
```

#### DAT_0000d158 状态值

| 值 | 含义 | 结果 |
|---|------|------|
| 0 | GREEN（验证通过） | 正常启动 |
| **1** | **设备解锁** | **跳过验证，直接启动！** |
| 2 | YELLOW | 警告启动 |
| 3 | ORANGE（验证失败） | 死机/重启 |
| 0xffffffff | 错误 | - |

#### XTC RWDeviceState（FUN_00002388）

```c
longlong FUN_00002388(param_1, param_2, param_3, param_4)
{
  if (操作类型 == 0) {  // 读
    FUN_000026e8(auStack_a8, param_3, param_4);  // XTC 读 devinfo
  } else if (操作类型 == 1) {  // 写
    FUN_00002884(auStack_a8, param_3, param_4);  // XTC 写 devinfo
  }
}
```

**XTC 版只有 devinfo 路径，没有 rpmb！**

#### 完整验证链

```
某个驱动（BDS?）调用 RWDeviceState 读取 devinfo
  ↓
解析 devinfo 数据，得到状态字符串 param_2
  ↓
调用 DeviceInit(param_1, param_2)
  ├─ param_2[0] != 0 → DAT_0000d158 = 1（解锁）
  └─ param_2[0] == 0 → DAT_0000d158 = 0（锁定）
  ↓
调用 VerifyImage(...)
  ├─ DAT_0000d158 == 1 → 跳过验证，直接启动 ✅
  └─ DAT_0000d158 == 0 → 完整签名验证
```

### 19.7 待解决问题

1. **DeviceInit 的 param_2 从哪里来？**
   - 应该是从 devinfo 读取的数据中解析的
   - 调用者可能在 BDS/QcomBds 驱动中（不在 VerifiedBootDxe 内部）
   - 需要分析 BDS 驱动找到完整流程

2. **devinfo 的数据结构**
   - 哪个偏移是解锁标志？
   - abl 读 devinfo[0x0D]，VerifiedBootDxe 是否相同？
   - 是否有校验和？

3. **XTC 定制版 RWDeviceState 的读写函数**
   - FUN_000026e8（读）和 FUN_00002884（写）的具体实现
   - 是否有额外的加密或校验？

### 19.8 下一步

1. **分析 BDS/QcomBds 驱动**（在 inner_fv.bin 的 87 个模块中）
   - 找到调用 DeviceInit 和 RWDeviceState 的代码
   - 理解 devinfo 数据结构

2. **对照 abl 分析**
   - abl 的 FUN_00016408 读 devinfo[0x0D]
   - VerifiedBootDxe 是否使用相同的偏移？

3. **重测 devinfo 写入**
   - 理解结构后，构造正确的 devinfo
   - EDL 写入 → 冷启动观察是否触发 "Device is unlocked!"

---

## 第二十章：DeepSeek 独立验证（2026-10-08 晚）

### 20.1 验证结论速览

| 我们的结论 | DeepSeek 复核 |
|-----------|-------------|
| DeviceInit 反编译 | ✅ 正确 |
| VerifyImage 反编译 | ✅ 正确 |
| 状态值表 DAT_0000d158 | ✅ 正确 |
| 函数指针表 @0xd160 | ✅ 正确，且首8字节是 Version=0x00010003 |
| XTC RWDeviceState 只有 devinfo | ✅ 正确 |
| 标准 RWDeviceState 先 rpmb 后 devinfo | ✅ 正确 |
| 假设1：devinfo[0x0D] 是解锁位 | ✅ 偏移正确，但理由错了（在 abl 里，不在 VerifiedBootDxe） |
| 假设2：消费者是 QcomBds/Ebl | ❌ **错！消费者是 abl** |
| 假设3：devinfo 结构/校验和 | 部分正确：结构=0xA50，**无校验和**，只有 13 字节 magic |

### 20.2 重大更正

#### 更正 1：消费者是 abl，不是 QcomBds/Ebl

- **协议 GUID** = `8E5EFF91-21B6-47D3-AF2B-C15A01E020EC`（不是 A25F5839，那是 FFS 文件 GUID）
- abl 中有 5 处引用该 GUID：0x5B8C / 0x1D038 / 0x1D7E0 / 0x1D91C / 0x1DC20
- inner_fv.bin（87 模块）中只有 VerifiedBootDxe 自己引用，**没有其他消费者**
- QcomBds.pe32 和 Ebl.pe32 中 0 处引用

**完整调用链**：
```
abl（AndroidBootLoader）
  ↓ LocateProtocol(8E5EFF91)
  ↓
VerifiedBootDxe（provider，在 XBL DXE 阶段装载）
```

#### 更正 2：协议 vtable 完整结构

| 偏移 | 函数 | 功能 | abl 侧使用者 |
|------|------|------|------------|
| +0x00 | `0x000000010003` | **Version**（消费者校验 >=0x00010002） | - |
| +0x08 | 0x1470 | 标准 RWDeviceState | abl FUN_1CFF8 |
| +0x10 | 0x13B0 | DeviceInit | abl 0x21DC（版本门控后） |
| +0x18 | 0x1C0C | （5 参数） | abl 0x213C |
| +0x20 | 0x1844 | | abl 0x2250 |
| +0x28 | 0x2034 | VerifyImage | abl 0x9C74 |
| +0x30 | 0x1954 | | |
| **+0x38** | **0x1FD0** | **readSecurityState（SCM/TZ 安全世界）** | **abl FUN_1D7A8（解锁状态权威来源）** |
| +0x40 | 0x2218 | | |
| +0x48 | 0x2280 | | |
| +0x50 | 0x2304 | | |
| **+0x58** | **0x2388** | **XTC RWDeviceState（仅 devinfo）** | **abl FUN_1DBE0** |
| +0x60/+0x68 | NULL | | |

#### 更正 3：devinfo[0x0D] 只是安全状态的缓存

- devinfo[0x0D]/[0x0E] 是 **+0x38 readSecurityState（SCM/TZ）的缓存副本**
- 不是唯一权威来源
- abl 初始化路径：读 +0x38 安全状态 → 写入 devinfo[0x0D]/[0x0E] → 写回分区

### 20.3 devinfo 完整结构（实测确认）

| 偏移 | 长度 | 含义 | 证据 |
|------|------|------|------|
| 0x00 | 13 | magic `"ANDROID-BOOT!"` | abl 0x25D08 `movz w2,#0xD` |
| **0x0D** | 1 | **is_unlocked** | `strb w8,[x19,#0x0D]` |
| **0x0E** | 1 | **is_unlock_critical** | `strb w8,[x19,#0x0E]` |
| 0x0F | 1 | charger_screen_enabled | `strb w31,[x19,#0x0F]` |
| 0x90 | 1 | 初始化标志 (=1) | `strb w9,[x19,#0x90]` |
| 0x94 | 4 | =0 | `str w31,[x19,#0x94]` |
| 0x98 | 0x800 | 清零数组区 | `SetMem(+0x98,0x800,0)` |
| 0x898 | 0x100 | 清零区 | `SetMem(+0x898,0x100,0)` |
| **总长** | **0xA50** | **2640 字节** | `movz w20,#0xA50` |

**无校验和**：全流程只有 13 字节 magic 的 strncmp，没有 CRC/哈希。

### 20.4 之前测试失败的真正原因

```
abl 启动流程（0x25CE8 起）：
  1. 读 devinfo 分区（0xA50 字节）
  2. 检查 offset 0 的 13 字节 magic
  3. ❌ magic 不匹配 → 整块 SetMem(0xA50, 0) 清零！
     → 我们写的 0x0D=1 被抹掉！
     → 读 +0x38 安全状态（返回 0=锁定）
     → 重写 0x0D=0, 0x0E=0
     → 写回分区
  4. ✅ magic 匹配 → 直接返回，不改写
```

**我们之前的测试 magic 不对，所以写的解锁位被 abl 自动清零了！**

### 20.5 现有 devinfo dump 的问题

- `v1.0.1_dump/devinfo.img` 前 0x9A0 字节**全是 0**，没有 magic
- 只有 0x9A0..0xA4F 有 44 个非零字节（尾段）
- 这与"初始化路径会写 magic"矛盾
- 三种可能：
  1. 写回失败（provider 的 write_partition 返回错误）
  2. dump 不是 devinfo 分区（需按 LBA 1373184 重 dump）
  3. 另有代码在启动后清零（可能性最低）
- rawprogram0.xml 里 devinfo 的 filename=""，即**刷机包不提供 devinfo，出厂分区全 0**

### 20.6 后续方向（DeepSeek 建议）

#### P0（立即做）

1. **重新 dump devinfo**：按 start_sector=1373184、8 扇区重新 dump，hexdump 确认 offset 0 是否真的是 0
2. **在 abl 里找解锁判断的读者**：
   - 定位 `0x64938`（标准 devinfo 缓存，0xA50）和 `0x65388`（XTC devinfo 缓存，0xA50）的读者
   - 确认解锁判断到底读 devinfo 缓存还是直接读 +0x38 安全状态
   - 对 FUN_1D7A8（readSecurityState）的调用者一并列出

#### P1

3. **用完全正确的 devinfo 测试**：
   - magic = "ANDROID-BOOT!"
   - 0x0D = 1, 0x0E = 1
   - 整块 0xA50，其余保持原机内容
   - **配合失配 boot 镜像**（作者那份 Magisk boot）才能观察到解锁效果
4. **关注 XTC 通道**：XTC RWDeviceState (+0x58) 与第二份缓存 0x65388 的关系

#### P2

5. 逆向 +0x38 readSecurityState（SCM 调用），确认安全状态的 RPMB/TZ 依赖

### 20.7 核心问题

**abl 的解锁判断是读 devinfo 缓存，还是直接读 SCM/TZ 安全状态？**

- 如果读 devinfo 缓存 → 写 devinfo（magic 正确）就能解锁
- 如果直接读 SCM/TZ → 写 devinfo 无效，必须攻破安全世界

---

## 第二十一章：Ghidra Headless 批量分析 + DeepSeek 代码审查（2026-10-08 晚）

### 21.1 Ghidra Headless 模式

使用 `analyzeHeadless.bat` + Java 脚本自动分析 abl：
- 脚本1：`find_devinfo_readers.java` — 查找 devinfo 缓存的所有读者
- 脚本2：`analyze_unlock_check.java` — 深入分析解锁检查函数链
- 无需手动操作 Ghidra GUI，AI 可直接调用

### 21.2 解锁检查函数链（完全确认）

#### FUN_00016408（桩函数）

```asm
00016408  mov w0,#0x1    ; 永远返回 1
0001640c  ret
```

只有 8 字节，永远返回 1。同一张"桩表"还有 9 个兄弟函数。

#### FUN_00025968（解锁检查）

```c
undefined1 FUN_00025968(void) {
    uVar2 = FUN_00016408();  // 永远返回 1
    uVar1 = devinfo[0x0D];   // 读解锁位
    if ((uVar2 & 0xff) == 0) {  // 永远为假
        uVar1 = 1;  // fail-open 钩子
    }
    return uVar1;  // 直接返回 devinfo[0x0D]！
}
```

**关键**：`csinc w0,w8,wzr,ne` 的 else 分支返回 1（不是 0），是 fail-open 钩子。但因为桩恒为 1，NE 条件永远成立，所以恒等于 devinfo[0x0D]。

### 21.3 devinfo 初始化函数 FUN_00025ce8

```
1. 检查全局初始化标志 [0x65DD8]
2. 未初始化 → 读标准 devinfo (0x64938) + 读 XTC devinfo (0x65388)
3. 检查 magic "ANDROID-BOOT!" (13字节)
4. ✅ magic 匹配 → 直接返回，不改写！
5. ❌ magic 不匹配 → 整块清零 → 重写 magic → 调用 readSecurityState
   → is_unlocked = (state==0)?1:0 → 写回分区
```

**赋值方向纠正**：`cset w8, eq` 即 `is_unlocked = (readSecurityState()==0)?1:0`

### 21.4 标准 devinfo 缓存 (0x64938) 的读者

找到 33 个引用，14 个函数：

| 函数 | 读取偏移 | 功能 |
|------|---------|------|
| **FUN_00025968** | **0x0D** | **读 is_unlocked** |
| FUN_00025990 | 0x0E | 读 is_unlock_critical |
| FUN_000259b0 | 0x0F | 读 charger_screen_enabled |
| FUN_000259a0 | 0x90 | 读初始化标志 |
| FUN_00025ce8 | 多个 | devinfo 初始化 |

### 21.5 XTC devinfo 缓存 (0x65388)

- 是同一 0xA50 结构的第二份副本
- 走 XTC 专用通道（provider +0x58）
- **所有解锁判定只读标准缓存 0x64938**
- XTC 副本不参与解锁判定

### 21.6 🔴 决定性发现：AVB 载入函数直接用 devinfo[0x0D]

DeepSeek 代码审查确认：

**FUN_000057E8 = Android AVB 载入函数**，内部字符串：
- `LoadImageAndAuth`
- `LoadImageAndAuthVB2`
- `VB2: boot state: %a(%d)`
- **`Slot: %a, allow verification error: %a`** ← 关键！
- `No bootable slots found enter fastboot mode`

在 0x5A54 和 0x6020 直接调用 FUN_25968（读 devinfo[0x0D]）。

**这意味着：devinfo[0x0D]=1 会让 AVB 载入函数设置 `allow verification error`，失配镜像被允许启动！**

### 21.7 解锁检查的 8 个调用者

| 函数 | 身份 | 与解锁的关系 |
|------|------|------------|
| **FUN_000057E8** | **Android AVB 载入** | ★★ 直接用 devinfo[0x0D] 作为 `allow verification error` |
| FUN_0000E094 | `GetUnlockState(UINT8*)` API | 对外暴露解锁状态 |
| FUN_00030F3C | fastboot 协议初始化 | 启动时读一次解锁状态 |
| **FUN_00032BE0** | **fastboot getvar/device-info** | ★ 同时读 0x0D/0x0E/0x0F/0x90（字段语义铁证） |
| FUN_00032E90 | fastboot snapshot-update | 锁状态下拒绝某些命令 |
| FUN_0003D940 | fastboot 菜单 UI | 界面显示状态 |

### 21.8 FUN_000247A0（桩的另一个调用者）

- 身份：`HandleActiveSlotUnbootable`（AB 槽位不可启动处理）
- 桩的调用是死代码（因为桩恒为 1）

### 21.9 完整解锁路径（已确认）

```
1. EDL 写入 devinfo：
   - magic = "ANDROID-BOOT!" (偏移 0x00, 13字节精确匹配)
   - devinfo[0x0D] = 1 (is_unlocked)
   - devinfo[0x0E] = 1 (is_unlock_critical)
   - 保留原机 0x9A0..0xA4F 的 44 字节
   - 整块 0xA50 字节

2. 冷启动：
   - abl 读 devinfo → 检查 magic → magic 匹配 → 直接返回，不清零！
   - abl 调用 FUN_00025968 → 返回 devinfo[0x0D] = 1
   - AVB 载入函数 FUN_000057E8 看到 is_unlocked=1
   → 设置 allow verification error
   → 失配镜像被允许启动！

3. 结果：
   - fastboot getvar 显示 Device unlocked: yes
   - secure=no
   - 可以刷入任意镜像
```

### 21.10 之前测试失败的原因

1. ❌ magic 不正确 → abl 整块清零 → 重写 devinfo[0x0D]=0
2. ❌ 没有配合失配 boot 镜像测试（原厂 boot 本来就能通过验证）
3. ❌ 标准通道可能有 QSEE/keymaster(RPMB) 路径参与
4. ❌ 原机 dump 的 0x9A0..0xA4F 有 44 个非零字节，不能清零

### 21.11 后续方向

1. **P0-1**：重新 dump devinfo 确认当前内容
2. **P0-2**：构造正确的 devinfo（magic 精确匹配，保留原机尾段数据）
3. **P1-1**：EDL 写入测试，观察 fastboot getvar
4. **P1-2**：刷入失配 boot 镜像测试
5. **P2（可选）**：补全 DeviceInit 链路（ResetRuntimeDxe 的 A022155A 协议）

---

## 第二十二章：RPMB 路径分析 + 作者 abl 真正秘密（2026-10-08 晚）

### 22.1 实验发现：写 devinfo 不生效

**实验**：
- EDL 写入 devinfo：magic="ANDROID-BOOT!", [0x0D]=1, [0x0E]=1
- 重新 dump 确认：写入成功，magic 和 [0x0D]=1 都保留了
- 但 fastboot getvar 显示：`unlocked:no`, `secure:yes`, `Device unlocked: false`

**结论**：分区里是 1，但 abl 读到的是 0。中间有一层覆盖了我们写的值。

### 22.2 VerifiedBootDxe 完整调用链

#### FUN_00003544 = readSecurityState（TrustZone SCM SysCall）

```c
uint readSecurityState(void) {
    // Locate SCM Status protocol
    // SCM SysCall ID: 0x2000604
    // 从 TrustZone 获取安全状态
    // 失败返回 0xffffffff
}
```

#### FUN_00003650 = 检查是否走 RPMB

```c
void check_rpmb_flag(uint8_t *flag) {
    uint state = readSecurityState();
    *flag = 0;  // 默认不走 RPMB
    if ((state & 0x743) == 0x40) {
        *flag = 1;  // ★ 走 RPMB！
    } else {
        // "VB: Non-secure device: Security State: (0x%x)"
    }
}
```

- 掩码 0x743 = 0b11101000011
- 目标值 0x40 = 0b01000000（第 6 位）
- 还有一个兄弟函数 0x35EC，掩码是 0x763

#### FUN_00001470 = 标准 RWDeviceState

```c
RWDeviceState(op, buf, size) {
    check_rpmb_flag(local_b0);
    
    if (op == 0) {  // 读
        if (local_b0[0] != 0) {
            // RPMB 读路径
            // ★ RPMB 结果覆盖调用者缓冲区（0x179C-0x17AC，0x1000字节）
            // "Succeed using rpmb!"
        } else {
            // 直接读 devinfo 分区
            // "Succeed using devinfo!"
        }
    }
}
```

#### FUN_00002388 = XTC RWDeviceState

**纯 devinfo 路径，没有 RPMB！**

### 22.3 为什么写 devinfo 不生效（机制闭环）

1. ✅ 写入确实生效，magic 命中，没被 abl 改写
2. ❌ 但 abl 的 `IsUnlocked()` 读的是**标准缓存 0x64938**
3. ❌ 标准缓存用**标准通道 FUN_1CFF8** 填充，secure=yes 时走 RPMB
4. ❌ RPMB 应答覆盖调用者缓冲区（0x1000字节），所以 0x64938 里是 RPMB 的 locked=0
5. ❌ XTC 缓存 0x65388 里确实是我们写的 1，但**没有任何解锁判定读它**
6. 结论：**在原版 abl 上，靠写 devinfo 无法影响解锁**

### 22.4 🔴 作者 abl 的真正秘密（DeepSeek 验证）

**猜想 A（patch 初始化函数改用 XTC 读）：❌ 不成立**
- 作者版初始化结构与原版完全一致

**猜想 B（UserDebug 构建）：✅ 成立，而且更进一步**

| 镜像 | 构建 workspace | 策略桩 | 桩返回 | `IsUnlocked()` 行为 |
|------|---------------|--------|--------|-------------------|
| v1.0.1 原版 | `SW5100_System_HLOS_User` | `movz w0,#1; ret` | 1 | = devinfo[0x0D] |
| v2.8.1 原版 | `SW5100_System_HLOS_User` | `movz w0,#1; ret` | 1 | = devinfo[0x0D] |
| **作者版** | `ND08_System_HLOS_UserDebug` | `mov w0,xzr; ret` | **0** | **恒为 1（永远解锁）** |

`IsUnlocked()` 的写法：
```c
if (策略桩 == 0) return 1;  // fail-open 钩子
else return devinfo[0x0D];
```

**作者版策略桩返回 0 → IsUnlocked() 恒为 1 → 天然永久解锁！**

作者版桩被调用 5 处（原版只有 2 处），包括 fastboot 命令处理等，多处锁检查被整体跳过。

### 22.5 不可行的路线

| 路线 | 判断 | 原因 |
|------|------|------|
| 自己 patch 原版 abl | ❌ 不可行 | abl 有 ECDSA-P384 签名，改一字节即验签失败 |
| 直接写 RPMB | ❌ 概率极低 | 需要 SoC 内熔断的 RPMB key 与 TEE 命令，EDL 拿不到 |
| 用原版 abl 解锁 | ❌ 实质关闭 | 唯一杠杆是 TZ 安全状态，EDL 无法影响 |

### 22.6 推荐路线

#### D1：证实 RPMB 分支（零风险）
- dump logfs（2MB）和 logdump（65MB）
- 搜索 `Succeed using rpmb!` / `Succeed using devinfo!`

#### D2：用作者的 UserDebug abl（已经有了！）
- 作者的 abl 就是厂商签名的 FORCE-UNLOCKED 构建

#### D3：作者 abl + 原厂 v1.0.1 镜像组合测试（关键！）
- 之前刷作者 abl 卡 logo，更可能是**版本/镜像不匹配**，不是解锁失败
- 组合：作者 abl + v1.0.1 原厂 super/boot/vbmeta
- 因为 `IsUnlocked()≡1`，AVB 会容忍校验错误

### 22.7 关键提醒

- `secure:` 与 `unlocked:` 是两个独立来源（TZ vs devinfo 缓存）
- 解锁后 `secure:` 仍会是 yes
- 作者没有用任何漏洞或 hack，只是拿到了厂商内部的 UserDebug 构建

---

*笔记持续更新中...*
