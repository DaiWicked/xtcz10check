# PILDxe 与 imagefv 装载机制分析笔记

> 分析时间：2026-10-08（DeepSeek 复核后更新）
> 分析对象：ND03 v1.0.1 XBL DXE 卷中的 PILDxe 模块
> 目标：确认 imagefv_a 的装载时机、验签机制、是否可被利用

---

## ⚠️ 重要修正（DeepSeek 复核后）

### 修正 1：uefipil.cfg 的 [RETAIL] 是名单，不是类型定义

**我们之前的误读**：以为 [RETAIL] 段里包含 Type=elf_fv 等类型定义
**正确理解**：[RETAIL] 只是白名单（列出允许加载的镜像名），Type=... 属于后面的独立段

### 修正 2：ImageFv 在 [RETAIL] 白名单里

**之前的错误结论**："imagefv_a 不在 [RETAIL] 白名单"
**正确结论**：ImageFv **在** [RETAIL] 白名单里，零售模式允许加载

### 修正 3：imagefv 不会开机自动加载

**之前的错误结论**："imagefv 会被 XBL 自动加载"
**正确结论**：[AUTO] 只有 ABL，imagefv **不在**自动加载列表
- imagefv 由 `FUN_18F4(name="ImageFv")` 按名加载 API 触发
- 0x1550 处的包装是 PIL 协议的 LoadImage 方法
- **触发者待查**（这是关键问题）

### 修正 4：ND03 有 UEFI 装载能力（在 XBL/DXE 层）

**之前的错误结论**："ND03 无 UEFI 装载能力"
**正确结论**：
- abl 层确实没有 UEFI 载荷路径（fastboot boot 不支持）
- 但 **XBL/DXE 层有 LoadImage×7、StartImage×2、FvSimpleFileSystem×6**
- abl 里有 `uefi`、`kernel.uefi.%ld` 字符串
- ⇒ 可能存在由 XBL 触发的 UEFI 启动路径，值得查清

---

## 一、PILDxe 模块基本信息

| 项目 | 值 |
|------|-----|
| 模块位置 | inner_fv.bin 0x42AD18 - 0x445D60 |
| 模块大小 | 110,664 bytes |
| PE 头偏移 | 0x42AD4C（MZ） |
| 机器类型 | 0xAA64 (ARM64/AARCH64) |
| 提取文件 | `unpacked_xbl/v1.0.1/PILDxe.pe32` (110,612 bytes) |
| 构建路径 | `/data1/integration/workspace/SW5100_System_Non-HLOS/boot_images/Build/AthertonLAA/Core/RELEASE_CLANG100LINUX/AARCH64/QcomPkg/Drivers/PILDxe/PILDxe/DEBUG/PILDxe.dll` |

---

## 二、uefipil.cfg 完整配置（DeepSeek 逐字节读出）

```ini
[PIL]
CfgVersion = 1

[IMAGE_LOAD_INFO_REGION]
ImageLoadInfoBase = 0x0C12594C
ImageLoadInfoSize = 200

[RETAIL]                  ; 白名单：允许在零售模式加载的镜像
ABL
ImageFv                   ; ★ ImageFv 在白名单里！
SPSS

[AUTO]                    ; 自动加载列表：开机默认加载的镜像
ABL
##SPSS                    ; 被注释掉了

[CORE_MODEM] Type=elf_split  PartiLabel=core_nhlos  SubsysID=4
[CORE_ADSP]  Type=elf_split  PartiLabel=core_nhlos  SubsysID=1
[SPSS]       Type=elf_split  PartiGuid=EBD0A0A2...  SubsysID=14
[ABL]        Type=elf_fv     PartiGuid=BD6928A1...  SubsysID=21  Unlock=Yes
[ImageFv]    Type=elf_fv     PartiGuid=17911177...  SubsysID=20  Unlock=Yes
```

**要点**：
- [RETAIL] = 白名单（名字列表），[AUTO] = 默认装载列表，两个概念完全不同
- **ABL 与 ImageFv 都带 `Unlock = Yes`**
- ImageFv 用 PartiGuid 定位（不是 PartiLabel，`#PartiLabel = imagefv_a` 被注释掉了）

---

## 三、PILDxe 关键函数

| 函数 | 地址 | 大小 | 功能 |
|------|------|------|------|
| FUN_000013f4 | 0x13f4 | 340 | 初始化：解析 RETAIL/AUTO 配置，遍历 AUTO 列表加载 |
| FUN_000015a0 | 0x15a0 | 852 | 单镜像加载主函数（含零售门槛+PAS认证） |
| FUN_000018f4 | 0x18f4 | 104 | **按名加载 API**：LoadImage(name) |
| FUN_00001560 | 0x1560 | 24 | 包装函数：bl 0x18F4; bl 0x1590; ret（PIL 协议入口） |

### 3.1 FUN_000015a0 加载流程（DeepSeek 逐指令复核）

```
0x167C bl 0x2FBC          ; 解析配置 → 得到配置结构体
0x1690 cmp w19,#0xA       ; ★ 零售门槛：不在白名单 → "pil-%s not supported in retail"
       b.ne 0x16F8
0x16A0 ldr w3,[x22,#0x8]  ; Type 字段
0x16B4 cmp w3,#2          ; ★ type 2 = elf_fv
       b.ne 0x17B4
0x1750 bl 0x57C0          ; 按 PartiGuid 挂载分区
0x1770 ldr x8,[x24,#0x8]  ; ★ LoadMetaData 指针（type2 ops 表 @0x11068）
0x1790 ldr x8,[x24,#0x10] ; ★ ValidateMetaData 指针
0x17E4 ldr x8,[x24,#0x18] ; ★ AuthAndReset 指针（PAS 认证）
```

**结论**：elf_fv (type 2) **不是免认证类型**，同样要经过 LoadMetaData → ValidateMetaData → AuthAndReset(PAS)

### 3.2 按类型的 ops 表（.data 段）

| 类型 | ops 表地址 | 说明 |
|------|-----------|------|
| type 1 | 0x110E8 | elf_split? |
| type 2 | 0x11068 | **elf_fv**（imagefv 和 abl 用这个） |
| type 3 | 0x110A8 | 未知 |

每个 ops 表偏移 +0x8/+0x10/+0x18 分别是 LoadMetaData/ValidateMetaData/AuthAndReset

### 3.3 调用 FUN_000015a0 的函数

| 调用者 | 调用点 | 说明 |
|--------|--------|------|
| FUN_000013f4 | 0x1464 | 白名单初始化，遍历 AUTO 列表加载 |
| FUN_000018f4 | 0x192c | 按名加载 API（LoadImage(name)） |
| FUN_00001560 | 0x1568 | PIL 协议入口包装 |

---

## 四、`Unlock = Yes` 字段（最关键的未知项）

### 4.1 PILDxe 内的情况

- 配置解析器在偏移 +0x331 写入 Unlock 字段
- **PILDxe 整个 .text 段内只找到"写"没有"读"**
- 说明 Unlock 字段被**间接消费**

### 4.2 ⭐ 重大发现：Unlock 字段被传递给 TrustZone

通过深入反编译 AuthAndReset 和 PAS authenticate 函数，确认：

**AuthAndReset (FUN_00001e70)**：
```c
ulonglong FUN_00001e70(longlong *param_1) {
    // param_1 = 配置结构体指针（包含 Unlock 字段 @ +0x331）
    if (param_1 == NULL) panic();
    if (*param_1 != 0 && param_1[1] != 0) {
        uVar1 = FUN_00001a88(param_1, *(param_1[1] + 0x30));
        if (uVar1 == 0) {
            // ★ 调用 SCM SysCall 0x2000201 = AuthAndReset
            lVar2 = FUN_00001cc8(param_1, 0x2000201, 0x82);
            // param_1（含 Unlock 字段）被整体传递给 TrustZone!
        }
    }
}
```

**PAS authenticate (FUN_00002a90)**：
```c
undefined8 FUN_00002a90(longlong *param_1) {
    // 准备参数
    FUN_00003cc0(param_1, 2, &local_30);
    // ★ 调用 SCM SysCall 0x2000205 = PAS authenticate
    lVar1 = FUN_00001cc8(param_1, 0x2000205, 1);
    if (lVar1 < 0) {
        // 打印 "pil-%s Failed to PAS authenticate and reset subsys %r"
    }
}
```

**FUN_00001cc8 = SCM SysCall 包装函数**：
- 参数1：配置结构体指针（含 Unlock 字段）
- 参数2：SysCall 号
  - `0x2000201` = AuthAndReset
  - `0x2000205` = PAS authenticate
- 参数3：标志

### 4.3 ⭐ SCM 调用号解码（来自 Linux 内核开源代码）

从 Linux 内核 `drivers/firmware/qcom_scm.h` 中找到 SCM 调用格式：

```c
#define SCM_SMC_FNID(s, c)  ((((s) & 0xFF) << 8) | ((c) & 0xFF))
#define QCOM_SCM_SVC_PIL     0x02
#define QCOM_SCM_PIL_PAS_INIT_IMAGE      0x01
#define QCOM_SCM_PIL_PAS_MEM_SETUP       0x02
#define QCOM_SCM_PIL_PAS_AUTH_AND_RESET  0x05
#define QCOM_SCM_PIL_PAS_SHUTDOWN        0x06
```

**解码结果**：

| PILDxe 调用 | FNID | 解码 | 含义 |
|------------|------|------|------|
| `FUN_00001cc8(param_1, 0x2000201, 0x82)` | 0x201 | (0x02<<8)\|0x01 | **PIL PAS_INIT_IMAGE** |
| `FUN_00001cc8(param_1, 0x2000205, 1)` | 0x205 | (0x02<<8)\|0x05 | **PIL PAS_AUTH_AND_RESET** |

**PAS 三步认证流程**（标准高通流程）：
1. `PAS_INIT_IMAGE` (0x201) - 初始化镜像，传递 metadata
2. `PAS_MEM_SETUP` (0x202) - 设置内存区域
3. `PAS_AUTH_AND_RESET` (0x205) - 认证并重置子系统

**参数分析**：
- `0x82` = arginfo = 2个参数，第一个是 VAL，第二个是 RW
- param_1 = 配置结构体指针（包含 Unlock 字段 @ +0x331）
- 配置结构体被整体传递给 TrustZone

### 4.4 imagefv 的真实用途

从搜索结果确认：
> **imagefv = Image File Verification image**
> 包含用于验证其他镜像完整性的签名和证书！

这解释了为什么 imagefv 有 XTC 证书链——它是**验证根**，用于验证其他镜像的签名。

### 4.5 结论

**Unlock 字段的消费在 TrustZone 内部**，PILDxe 只是把配置结构体整体通过 SCM SysCall 传递给 TrustZone。

这意味着：
- ✅ 我们无法在 PILDxe 里看到 Unlock 字段的读取逻辑
- ❓ TrustZone 里的 PAS 认证是否检查 Unlock 字段？
- ❓ 如果 Unlock=Yes，TrustZone 是否会跳过认证？
- ❓ 这需要分析 TrustZone 固件（tz.img）或通过实验验证

### 4.6 验证方法

**方法 A：实验验证**
- 修改 imagefv 分区内容（破坏签名）
- 看是否能通过 PAS 认证
- 如果能通过 → Unlock=Yes 确实免认证
- 如果不能通过 → Unlock=Yes 有其他含义

**方法 B：分析 TrustZone 固件**
- 解包 tz.img
- 搜索 0x201 / 0x205 SCM 命令处理函数
- 看是否读取配置结构体的 +0x331 偏移

**方法 C：搜索高通 PIL 开源代码**
- 高通 PIL (Peripheral Image Loader) 有部分开源
- Linux 内核驱动确认了 SCM 调用格式
- 但 TrustZone 内部的 PAS 实现是闭源的

---

## 五、imagefv.elf 结构分析

### 5.1 ELF 基本信息

| 属性 | 值 |
|------|-----|
| 文件大小 | 20,480 bytes (20KB) |
| 类型 | 32位 ARM ELF (e_machine=40/EM_ARM) |
| e_type | 2 (ET_EXEC) |
| 入口点 | 0x34 |

### 5.2 程序头

| PH | 类型 | 偏移 | 文件大小 | 标志 |
|----|------|------|----------|------|
| 0 | PT_NULL | 0x0 | 0x94 | - |
| 1 | PT_NULL | 0x1000 | 0x1060 | - |
| 2 | **PT_LOAD** | **0x3000** | **0x2000** | **0x7 (RWE)** |

**关键**：PT_LOAD 段从 0x3000 开始，大小 0x2000 (8KB)，FV 内容在这里。

### 5.3 FV Header

- 位置：偏移 0x3028（PT_LOAD 段内）
- 签名：`_FVH` (5F 46 56 48)
- FV GUID：8AE62B07-C06E-09B2-9B83-276F017EBEAA

### 5.4 ⚠️ 包含 X509 签名证书

字符串搜索发现 imagefv.elf 里嵌入了多个 X509 证书：

| 证书字段 | 值 |
|----------|-----|
| 根证书 | "Generated Commercial Root CA1"（高通） |
| 认证证书 | "Generated Commercial Attestation CA1"（高通） |
| **签名密钥** | **"General Use XTC Key 1"（小天才 XTC 密钥！）** |
| 组织 | "CDMA Technologies"（高通） |
| 地点 | "DongGuan"（东莞，小天才总部） |
| 工具 | "SecTools 1" |
| 有效期 | 2023-12-21 至 2043-12-16 |

**结论**：imagefv.elf 是签名容器，里面的 FV 镜像使用高通 + XTC（小天才）双重证书链签名。

---

## 六、DeepSeek 评估的四条路径

| 路径 | 可行性 | 依据 |
|------|--------|------|
| **A. 改 imagefv 分区植入自定义 DXE** | **取决于 Unlock 语义**：若免 PAS→高；否则→低 | 加载路径存在、ImageFv 在零售白名单、但 type2 走 AuthAndReset |
| **B. 找认证前的解析漏洞**（FV/MDT/ELF 解析） | **中** | 0x57C0 挂载、0x2FBC 解析、配置解析都在认证之前 |
| **C. 改 uefipil.cfg** | **不可能** | cfg 在 XBL 内，XBL 由 PBL 验签 |
| **D. 照搬小米方案** | **需修正**：abl 层无 UEFI 路径，但 XBL/DXE 层有 LoadImage/StartImage | 可能存在 XBL 触发的 UEFI 启动路径 |

**最有希望的路径**：先解决 `Unlock = Yes` 语义这一个问题——它是 A 与 B 的分水岭。

---

## 七、下一步计划（按 DeepSeek 建议，全部可静态完成）

### P0-1：找 0x1550 的调用者（谁触发 imagefv 加载）
- 0x1550 是 PIL 协议 LoadImage 方法的包装
- 确认**谁**在什么条件下请求 `"ImageFv"`
- 这决定 imagefv 在我们的设备上是否真会被装

### P0-2：追 `Unlock` 字段的消费路径
- 把配置结构体指针沿 0x1770→0x1790→0x17E4→**auth 实现（0x22xx~0x2Cxx）** 一路跟下去
- 看 +0x330/+0x331 是否进入认证判定
- 若 PILDxe 内不读，则看是否被整体拷贝给 TZ/PAS 描述符

### P0-3：确认 XBL 的 LoadImage/StartImage 路径
- 谁 mount + start FvSimpleFileSystem 暴露的 FV
- abl 里 `uefi`/`kernel.uefi.%ld` 是被谁读写
- 很可能是**触发 imagefv 装载的那个键**

### P1：只有 P0 指向"可写且不验签"时，才构造 FV
- 用 imagefv.elf 做模板，替换 FV 载荷

---

## 八、可能忽略的点（DeepSeek 提醒）

1. **`.mdt` 机制**：elf_split 的 metadata 来自独立分区文件，PIL 会读"镜像之外的元数据"——若这条读取路径存在可控的标签/长度，属于认证前攻击面
2. **`Unlock = Yes` 同时挂在 ABL 上**：如果语义真是"免认证"，那 abl 的二次认证也可能被设计成可跳过
3. **`ProxyGuid` 键**：PIL 配置里还有 ProxyGuid，高通 proxy 机制允许把镜像装载委托给另一个子系统——历史上这类"代理"路径是边界问题高发区
4. **`IMAGE_LOAD_INFO_REGION`（IMEM 0x0C12594C，200B）**：装载信息会写进 IMEM，是"谁装载了什么、成功与否"的现成取证点

---

## 九、已验证死路（更新）

- ❌ 标准 fastboot 解锁命令（原版 abl 无此命令）
- ❌ devinfo[0x0D]=1 写入（RPMB 覆盖，无效）
- ❌ 自己 patch 原版 abl（ECDSA-P384 签名）
- ❌ 直接写 RPMB（需要 SoC 熔断 key）
- ❌ 方案 E/E2（作者 abl 解锁持久化）：刷回原版后回到 locked
- ❌ "imagefv 开机自动加载"（不在 AUTO 列表）
- ❌ "imagefv 不在零售白名单"（实际在白名单里）
- ❌ **"Unlock 字段被传递给 TrustZone"（DeepSeek 复核推翻，实参只有 metadata+pas_id）**
- ❌ **"imagefv = 验证其他镜像的镜像"（实际是 splash/logo 图片的 UEFI FV）**
- ❌ **"改 imagefv 植入自定义 DXE"（三种类型都要过 PAS，需要 XTC 私钥）**

---

## 十、P0-1 分析结果：imagefv 装载触发者定位（2026-10-09）

### 10.1 调用链追踪结果

**FUN_195C（SubsysID=20=ImageFv 装载路径）**：
- 大小：272 字节
- 确认：`*(undefined4 *)(lVar2 + 0xec) = 0x14;` — SubsysID=20 (ImageFv)
- 调用流程：FUN_24ac (metadata) → FUN_1e70 (PAS_INIT) → FUN_1f50 → FUN_2a90 (PAS_AUTH)
- 错误信息："pil-%s Failed to load metadata" / "Failed to validate metadata" / "Failed to setup memory range" / "Failed to bring proc out of reset"

**FUN_195C 的调用者**：
- **FUN_1578**（24字节包装函数）
- 调用点：@0x1580 `bl 0x195c`

**FUN_18F4（按名加载 API LoadImage(name)）**：
- 大小：104 字节
- 流程：PIL_Lock → FUN_3184(name) 查找配置 → FUN_15A0(加载主函数) → PIL_Unlock
- 调用者：**FUN_1548**（24字节包装函数）

**FUN_1560（PIL 协议入口包装）**：
- 大小：24 字节
- 流程：`bl 0x15A0; bl 0x1590; ret`
- **无直接调用者**（通过函数指针表调用）

**FUN_15A0（加载主函数）的调用者**：
1. FUN_13F4（初始化函数，@0x1464）— AUTO 列表自动加载
2. FUN_18F4（按名加载 API，@0x192c）
3. FUN_1560（PIL 协议入口，@0x1568）

### 10.2 关键发现

1. **"ImageFv" 字符串在 PILDxe 代码中无直接引用者**
   - 只在 uefipil.cfg 配置文件里出现
   - PILDxe 通过配置解析器按名查找，不硬编码字符串

2. **FUN_1578 / FUN_1548 / FUN_1560 都是 24 字节的包装函数**
   - 极可能是 **EFI PIL 协议的方法表**中的函数指针
   - 通过协议接口被其他 DXE 模块调用
   - 所以没有直接的 bl 调用者

3. **imagefv 的触发加载者在 PILDxe 外部**
   - 可能是其他 DXE 模块（如 BDS、DisplayDxe、SplashScreenDxe）
   - 可能是 abl 层
   - 需要在整个 XBL DXE 卷（inner_fv.bin，86个模块）中搜索

### 10.3 下一步：在整个 DXE 卷中搜索触发者

需要在 inner_fv.bin（4.9MB，86个模块）中搜索：
1. 谁安装/使用了 PIL 协议（GUID 查找）
2. 谁调用了 PIL_LoadImage("ImageFv")
3. 搜索 "ImageFv" 字符串在其他模块中的引用
4. 搜索 splash/logo 相关模块（DisplayDxe、SplashScreen 等）

### 10.4 分析脚本

- 脚本：`tools/find_imagefv_trigger.java`
- 输出：`tools/imagefv_trigger_output.txt`（44KB）

---

## 十一、P0-1 扩展：在整个 DXE 卷中搜索 imagefv 触发者（2026-10-09）

### 11.1 字符串搜索结果（inner_fv.bin，4.9MB，86个模块）

| 字符串 | 数量 | 偏移范围 | 所属模块 |
|--------|------|----------|----------|
| Splash | 6 | 0x2FBCF7-0x2FD99C | 第54个模块（0x2D7568-0x311648） |
| logo/Logo | 4 | 0x2FD8EA-0x2FD9AD | 第54个模块 |
| MountFv | 7 | 0x43FC56, 0x4AFCDA-0x4AFD58 | PILDxe + 第75个模块后 |
| LoadImage | 7 | 0x1F474-0x2D3127 | 多个模块 |
| StartImage | 2 | 0x1F4E9, 0x4AFC66 | 第21个模块 + 第75个模块后 |
| **ImageFv/imagefv** | **0** | — | **整个 DXE 卷中无此字符串！** |

### 11.2 第54个模块 = DisplayDxe（关键发现！）

- 位置：inner_fv.bin 0x2D7568-0x311648，大小 237,790 字节
- GUID：4138022F-06C7-4F79-9C94-7E33B511A4E7
- PE32 头：偏移 0xC4
- 提取文件：`unpacked_xbl/v1.0.1/module54_splash.pe32`
- 函数数量：973 个

**关键字符串**：
- `Display_Utils_GetContinuousSplashInfo failed.` @ FUN_000071a0
- `Display_Utils_RenderSplashScreen: OEM Logo1 Successfully Loaded` @ FUN_0000c9e4
- `EnablePlatPartition` @ FUN_0000b924
- `MDPSystem: MDP_SetDisplayBootConfig failed.`
- `MDPSystem: Failed to update UEFI Environment variable (UEFIDisplayInfo)!`

**关键函数**：
- FUN_000071a0：GetContinuousSplashInfo（获取连续 splash 信息）
- FUN_0000c9e4：RenderSplashScreen（渲染 splash 屏幕，加载 OEM Logo1）
- FUN_0000b924：EnablePlatPartition（启用平台分区！）
- FUN_00007d70：最大函数（4384字节），可能是主显示初始化
- FUN_0000e0fc：第二大函数（3964字节）

### 11.3 重要结论

1. **"ImageFv" 字符串在整个 DXE 卷中不存在！**
   - 只在 PILDxe 内嵌的 uefipil.cfg 配置文件里出现
   - 其他模块不直接引用 "ImageFv" 字符串
   - 说明 imagefv 的加载不是通过按名调用 PIL_LoadImage("ImageFv")

2. **DisplayDxe 负责 splash 屏幕显示**
   - 有 GetContinuousSplashInfo、RenderSplashScreen、OEM Logo1 等函数
   - 有 EnablePlatPartition 函数（可能启用 imagefv 分区）
   - 但 DisplayDxe 中没有 "pil" 或 "ImageFv" 字符串

3. **imagefv 的加载机制可能是**：
   - 通过 FvSimpleFileSystem / MountFv 直接挂载分区（不经过 PIL/PAS）
   - 或通过其他协议（如 EFI_BLOCK_IO、EFI_SIMPLE_FILE_SYSTEM）
   - DisplayDxe 的 EnablePlatPartition 可能是关键

4. **MountFv 字符串在第75个模块后（0x4AFCDA-0x4AFD58）**
   - 第75个模块：0x454DA0-0x45DDE8
   - 后面还有多个小模块（0x45DDE8-0x4B6B40）
   - 可能有专门的 FvLoader 或 MountFv 模块

### 11.4 下一步方向

1. **分析 EnablePlatPartition 函数**（FUN_0000b924）— 看它是否启用 imagefv 分区
2. **分析 MountFv 相关模块**（第75个模块后）— 看是否有非交互的 FV 挂载路径
3. **搜索 "PlatPartition" 或 "partition" 在其他模块中的引用**
4. **确认 imagefv 的加载是否经过 PIL/PAS** — 如果通过 MountFv 直接挂载，可能不验签！

### 11.5 分析脚本

- 脚本：`tools/analyze_displaydxe.java`
- 输出：`tools/displaydxe_output.txt`（97KB）

---

## 十二、DeepSeek 复核报告（重大反转 + 新发现）（2026-10-09）

### 12.1 重大反转（推翻我们的猜想）

| 我们的猜想 | DeepSeek 复核结果 |
|-----------|------------------|
| A：imagefv 走 FvSimpleFileSystem/MountFv | ❌ **不成立**：PartiGuid/FV GUID 在 XBL 全域、abl、tz.mbn 中均为 0 处 |
| B：EnablePlatPartition 是关键函数 | ❌ **看错了**：这是**设备树属性字符串**，不是函数 |
| imagefv 里可能有可执行代码 | ❌ **只有一张 1-bit 位图**（LZMA 解开 276,936 B），无 MZ/无 VZ |
| DisplayDxe 从 imagefv 取 logo | ❌ **logo 来自 DXE FV 内的 `logo1.bmp`**（0x45E930，195,818 B） |
| "DXE 卷中 ImageFv 0 处" | ⚠️ **不准确**：cfg 里有 3 处（代码模块里确实没有） |

### 12.2 ★ 重大新发现 1：Ebl = 不经 PAS 的"加载并执行"通道

- **Ebl**（Embedded Boot Loader），GUID 3CEF354A-3B7A-4519-AD70-72A134698311，127,016 B
- PDB 路径：`.../AARCH64/EmbeddedPkg/Ebl/Ebl/DEBUG/Ebl.dll`
- 模块类型：**APPLICATION**（DXE 会派发它）
- 位置：inner_fv.bin 0x497B18-0x4B6B40（最后一个模块）

**Ebl 自带命令集**：
```
Embedded Boot Loader (Ebl) commands
  help [cmd]            ; Help on cmd
  exit                  ; Exit Ebl
  connect / device      ; Connect all EFI devices / show boot devices
  dir / ls              ; directory listing of a device
  copy / compare / dump ; 文件操作
  loadfv  devname       ; ★ Load PI FV from device
  mountfv partitionlabel ; ★ Mounts a FV from partition
  start   path          ; ★ EFI Boot Device:filepath
```

**关键意义**：
- `loadfv`/`mountfv`/`start` 都**不经过 PIL/PAS**（用 gBS->LoadImage/StartImage）
- 这是一条**独立于 PIL 的引导期代码执行通道**

### 12.3 ★ 重大新发现 2：BDS 菜单有"关闭 Secure Boot / 开 Debug Policy"

- `BDS_Menu.cfg`（FFS 文件 @0x45DDE8，2,883 B）
- 完整菜单项：
  ```
  "Exit BDS Menu"           → Exit
  "Enable Secure Boot"      → SecurityToggleApp    /SecureBootEnable
  "Disable Secure Boot"     → SecurityToggleApp    /SecureBootDisable
  "Enable Debug Policy"     → DebugPolicyToggleApp /DebugPolicyEnable
  "Disable Debug Policy"    → DebugPolicyToggleApp /DebugPolicyDisable
  "Config PPI display"      → DebugPolicyToggleApp /ConfigPpiDisplay
  "Provision RPMB"          → RPMBProvision
  ```

**关键推论**：
1. 这些 App（SecurityToggleApp/DebugPolicyToggleApp/RPMBProvision）**不在 DXE FV 里**
2. DXE FV 只有两个 APPLICATION：`QcomChargerApp`、`Ebl`
3. ⇒ 这些 App 本应从**分区 FV（很可能是空的 toolsfv）**装载
4. **这就是平台自带的"工程模式开关"设计！**

### 12.4 ★ 重大新发现 3：UEFI 变量存储（新高价值方向）

- SecurityToggleApp/DebugPolicyToggleApp 写的是 **UEFI 变量**
- DXE 里有 `VariableDxe`
- 变量存储分区 `uefivarstore`(512KB) **在本机是 0**
- **"能否用 EDL 直接种入 Debug Policy/SecureBoot 变量"** 成为新方向

### 12.5 空分区清单（潜在的工具装载位置）

| 分区 | 大小 | 状态 | 刷机包 |
|------|------|------|--------|
| toolsfv | 1 MB | 全 0 | filename=""（不刷） |
| catefv | 512 KB | 全 0 | filename=""（不刷） |
| catecontentfv | 1 MB | 全 0 | filename=""（不刷） |
| cateloader | 2 MB | 全 0 | filename=""（不刷） |
| uefivarstore | 512 KB | 全 0 | — |

**这些分区都不在 AVB 覆盖范围！**

### 12.6 利用路径评估（更新后）

| 路径 | 评估 | 说明 |
|------|------|------|
| 改 imagefv 植入 DXE | ❌ 低（方向错误） | 只有位图，无消费者 |
| imagefv 解析漏洞 | ❌ 低 | 解析器在签名侧，且要先过 PAS |
| **Ebl 命令行通道** | 🟡 中 | 不经 PAS，但需要能喂命令/进菜单 |
| **BDS 菜单 + toolsfv 空分区** | 🟢 **中高（当前最值得查）** | 平台自带工程模式开关 |
| **UEFI 变量存储（uefivarstore）** | 🟢 **中高（新）** | EDL 直接种变量可能改策略 |

### 12.7 下一步方向（DeepSeek 建议，按优先级）

1. **查 BDS 菜单是否可达、由什么门控**
   - 搜 `BDS_Menu`、`Display menu is not enabled`、`BdsMenuEnable` 配置/DT 属性
   - 设备实测：按键进菜单、fastboot 菜单

2. **查这些 App 期望从哪里装载**
   - Ebl 的 `start`/`loadfv` 目标怎么解析（`fv1:`/`fs1:` 设备分配）
   - `toolsfv`/`catefv` 是否会被自动挂载

3. **查 UEFI 变量的落盘位置**
   - VariableDxe 的存储后端（uefivarstore 分区？还是 RPMB？）
   - DebugPolicy/SecureBoot(PK) 变量的消费者（谁读它决定验证行为）

4. **imagefv 方向可以停止投入了**

### 12.8 已验证死路（新增）

- ❌ "改 imagefv 植入自定义 DXE"（内容只有位图，无消费者，且要过 PAS）
- ❌ "imagefv 位图解析漏洞（LogoFAIL 类）"（解析器在签名侧，且要先过 PAS）
- ❌ "EnablePlatPartition 是关键函数"（实际是 DT 属性字符串）
- ❌ "DisplayDxe 从 imagefv 取 logo"（实际来自 DXE FV 内的 logo1.bmp）

---

## 十三、Ebl + BDS 菜单分析（重大新方向）（2026-10-09）

### 13.1 BDS_Menu.cfg 完整内容（已提取）

文件：`unpacked_xbl/v1.0.1/BDS_Menu.cfg`（2,883 字节）

**完整菜单项**：
```
Exit BDS Menu           → Exit
Enable Secure Boot      → SecurityToggleApp    /SecureBootEnable
Disable Secure Boot     → SecurityToggleApp    /SecureBootDisable
Enable Debug Policy     → DebugPolicyToggleApp /DebugPolicyEnable
Disable Debug Policy    → DebugPolicyToggleApp /DebugPolicyDisable
Config PPI display      → DebugPolicyToggleApp /ConfigPpiDisplay
Provision RPMB          → RPMBProvision        -Prompt
Enter Shell             → Shell                -nomap -nostartup
Boot USB First          → Cmd                  BootUSBFirst
MassStorage             → UsbfnMsdApp          MassStorage
Reboot                  → Cmd                  Reboot
CLOCK Menu              → Menu                 Clock_Menu.cfg
EDL Mode                → Cmd                  edl
USB Menu                → Menu                 Usb_Menu.cfg
PMIC Menu               → Menu                 Pmic_Menu.cfg
Launch CATE             → Cmd                  LaunchCATE
UEFI Menu               → Menu                 Uefi_Menu.cfg
```

**关键发现**：
- 有 **"Disable Secure Boot"** 选项（写 Clear PK UEFI 变量）
- 有 **"Enable Debug Policy"** 选项（写 Debug policy 变量，启用 HLOS debug）
- 有 **"Enter Shell"** 选项（UEFI Shell）
- 有 **"MassStorage"** 选项（USB 大容量存储模式）
- 有 **"EDL Mode"** 选项
- 这些 App（SecurityToggleApp 等）**不在 DXE FV 里**，本应从分区 FV（toolsfv）装载

### 13.2 Ebl 模块分析（已提取）

- 文件：`unpacked_xbl/v1.0.1/Ebl.pe32`（126,976 字节）
- GUID：3CEF354A-3B7A-4519-AD70-72A134698311
- PDB：`.../AARCH64/EmbeddedPkg/Ebl/Ebl/DEBUG/Ebl.dll`
- 函数数量：614 个
- 模块类型：APPLICATION（DXE 会派发它）

**Ebl 命令集**：
```
help [cmd]            ; Help on cmd
exit                  ; Exit Ebl
connect / device      ; Connect all EFI devices / show boot devices
dir / ls              ; directory listing
copy / compare / dump ; 文件操作
loadfv  devname       ; ★ Load PI FV from device
mountfv partitionlabel ; ★ Mounts a FV from partition (eg: MountFv toolsfv)
start   path          ; ★ EFI Boot Device:filepath (eg: fs1:\EFI\BOOT.EFI)
```

**关键函数**：
- **FUN_0000f22c**：MountFv 命令实现（引用 "MountFv toolsfv"、"MountFv -g GUID"、"MountFv -f filepath"）
- **FUN_00010114**：start 命令帮助（引用 "start fv1:\fastboot"、"start fv2:\Shell"、"start fv1:\menu"、"start fv3:\mptest"）

**start 命令示例（帮助文本中）**：
- `start fv1:\fastboot` — fastboot 从 fv1 启动
- `start fv1:\menu` — 菜单从 fv1 启动
- `start fv2:\Shell` — Shell 从 fv2 启动
- `start fv1:\LinuxFdtLoader`
- `start fv3:\mptest`

### 13.3 关键推论

1. **fv1/fv2/fv3 是挂载的 FV 设备**：
   - fv1 可能是 DXE FV 本身（含 fastboot、menu）
   - fv2/fv3 可能是其他分区（如 toolsfv、catefv）挂载的 FV
   - `mountfv toolsfv` 可以把 toolsfv 分区挂载为 FV 设备

2. **Ebl 提供不经 PAS 的引导期代码执行通道**：
   - `mountfv toolsfv` 挂载分区 FV（不经过 PIL/PAS）
   - `start fv2:\OurApp` 启动我们的 EFI 应用（用 gBS->LoadImage/StartImage）
   - 前提：能进入 Ebl 并执行命令

3. **BDS 菜单是工程模式入口**：
   - 菜单可达性是关键（由什么门控？）
   - 菜单里的 App 从分区 FV 装载（toolsfv 是空的！）
   - 如果我们能把 SecurityToggleApp 放进 toolsfv，就能从菜单运行它关闭 Secure Boot

### 13.4 下一步方向

1. **查 BDS 菜单可达性**：
   - 搜索 `BDS_Menu`、`Display menu is not enabled`、`BdsMenuEnable` 的读取者
   - 分析 QcomBds 模块（BDS 启动决策）
   - 设备实测：按键组合进菜单

2. **查 Ebl 的非交互调用路径**：
   - 是否有启动脚本/配置自动执行 mountfv + start
   - Ebl 是否由 BDS 自动启动

3. **查 toolsfv 挂载机制**：
   - Ebl 的 mountfv 实现细节
   - fv2/fv3 设备分配逻辑

4. **UEFI 变量存储分析**：
   - VariableDxe 的存储后端（uefivarstore 分区？还是 RPMB？）
   - DebugPolicy/SecureBoot 变量的消费者

### 13.5 分析脚本和输出

- 脚本：`tools/analyze_ebl.java`
- 输出：`tools/ebl_output.txt`（61KB）
- BDS 菜单：`unpacked_xbl/v1.0.1/BDS_Menu.cfg`
- Ebl 模块：`unpacked_xbl/v1.0.1/Ebl.pe32`

---

## 十四、QcomBds 模块分析（BDS 菜单可达性）（2026-10-09）

### 14.1 QcomBds 模块提取

- 文件：`unpacked_xbl/v1.0.1/QcomBds.pe32`（106,496 字节）
- 位置：inner_fv.bin 0x410D00
- PDB：`.../AARCH64/QcomPkg/Drivers/QcomBds/QcomBds/DEBUG/QcomBds.dll`
- 函数数量：650 个
- 包含：QcomBds.c、BdsBoot.c、BdsMisc.c、BdsConsole.c、PlatformBdsLib.c、QcomBdsLibFilePath.c

### 14.2 关键函数

| 函数 | 大小 | 说明 |
|------|------|------|
| FUN_00008a80 | 4904 | 最大函数，可能是 BDS 主循环/菜单处理 |
| FUN_00005ef4 | 3964 | 第二大函数 |
| FUN_0000fba0 | 1264 | **DefaultBDSBootApp**（默认 BDS 启动应用） |
| FUN_00001ad4 | 664 | QcomBds.c 主函数（引用 BootNextSize） |
| FUN_00001d6c | — | [QcomBds] Removable boot path |
| FUN_0000fa48 | — | **UEFI NV tables VOLATILE 检查** |
| FUN_000101b4 | — | EnableUefiSecAppDebugLogDump |
| FUN_0000f514 | 608 | BootDeviceBaseAddr/BootConfigRegVal 变量设置 |
| FUN_000105b8 | — | Failed to Get Shared Imem Boot Device type |

### 14.3 ★ 重要发现：UEFI NV 表是 VOLATILE 的

字符串：
- `"INFO: UEFI NV tables are enabled as VOLATILE!"`
- `"ERROR: UEFI NV tables are enabled as VOLATILE!"`

**含义**：
- UEFI 变量存储（NV = Non-Volatile）被配置为 **VOLATILE（易失性）**
- 这意味着 **UEFI 变量在重启后不会持久化**！
- 这解释了为什么 uefivarstore 分区全 0 —— 因为变量根本不写到这个分区
- **重大影响**：即使我们能写入 DebugPolicy/SecureBoot 变量，重启后也会丢失！
- 需要进一步确认：是所有变量都 VOLATILE，还是只有部分？

### 14.4 BDS 启动流程

1. QcomBds 入口（FUN_00001ad4）：
   - 检查 BootNext 变量
   - 处理启动选项
   - 调用 DefaultBDSBootApp（FUN_0000fba0）

2. DefaultBDSBootApp（FUN_0000fba0）：
   - 查找可启动句柄
   - 加载并启动默认启动项
   - 可能包含 BDS 菜单逻辑

3. BDS 菜单：
   - 由 BDS_Menu.cfg 配置文件驱动
   - 菜单项的 App（SecurityToggleApp 等）不在 DXE FV 里
   - 需要从分区 FV（toolsfv）装载

### 14.5 下一步方向

1. **深入分析 FUN_0000fba0（DefaultBDSBootApp）**：
   - 是否有菜单显示逻辑？
   - 菜单由什么门控（按键/变量/超时）？

2. **分析 FUN_00008a80（最大函数）**：
   - 可能是 BDS 菜单处理循环
   - 搜索按键输入、菜单显示相关代码

3. **确认 UEFI 变量 VOLATILE 的范围**：
   - 是所有变量还是部分？
   - DebugPolicy/SecureBoot 变量是否也 VOLATILE？

4. **设备实测**：
   - 启动时按特定按键看是否能进 BDS 菜单
   - fastboot 模式下是否有隐藏菜单入口

### 14.6 分析脚本和输出

- 提取脚本：`tools/extract_qcombds3.py`
- 分析脚本：`tools/analyze_qcombds.java`
- 输出：`tools/qcombds_output_v2.txt`（53KB）

---

## 十五、BDS 菜单门控机制深入分析（2026-10-09）

### 15.1 DefaultBDSBootApp (FUN_0000fba0) 完整流程

**调用链**：
1. 显示初始化：`FUN_0000c72c("DispInit",...)` → `FUN_0000f1a0()` → `FUN_000047b8()`
2. `FUN_0000fa48()` — UEFI NV 表检查（见 15.2）
3. 加载 "DefaultChargerApp"（充电模式应用）
4. 加载 "DefaultBDSBootApp"
5. **`FUN_0000f148()`** — ⭐ 可能是 BDS 菜单入口！
6. `FUN_000106d8()` — 启动选项处理
7. `FUN_0000f428()` — 实际启动镜像
8. **按键读取循环**：
   - `FUN_000030e8((short *)local_120, 3)` — 读取按键，参数 3 = 等待时间（秒？）
   - 超时检查：`999999 < local_120[0]`，`local_120[0] / 1000000`（微秒转秒）
   - `uVar2 = (short)local_120[0] == 2` — **按键值 2 有特殊处理**
9. 挂载 "Efi System Partition"

**关键发现**：
- BDS 启动过程中有**按键读取和超时机制**
- 按键值 2 触发特殊流程（可能是进入 BDS 菜单）
- `FUN_0000f148()` 是最可能的 BDS 菜单显示函数

### 15.2 UEFI NV VOLATILE 检查 (FUN_0000fa48)

**关键变量**：`"EnableVolatileBootOptions"`

**流程**：
1. 获取协议句柄，检查某个条件
2. `FUN_00010194(DAT_00018700)` — 读取某个 UEFI 变量
3. 如果变量存在且条件满足：
   - `FUN_000101b4()` — EnableUefiSecAppDebugLogDump
   - `FUN_00010150(DAT_00018700)` — 设置变量
4. 否则：
   - **`FUN_00010184(DAT_00018700, L"EnableVolatileBootOptions", &DAT_00018058)`** — 设置 "EnableVolatileBootOptions" 变量！

**含义**：
- UEFI 变量可以配置为 VOLATILE（易失性）
- "EnableVolatileBootOptions" 变量控制启动选项是否易失
- 这解释了为什么 uefivarstore 分区全 0
- **需要进一步确认**：是所有变量都 VOLATILE，还是只有启动选项？

### 15.3 按键读取机制

- 函数：`FUN_000030e8(short *output, int timeout)`
- 参数 2 = 超时时间（可能是秒）
- 返回值：按键代码（2 = 特殊按键）
- 没有找到 "key"、"button"、"press" 等字符串
- 按键读取可能通过 UEFI 协议（SimpleTextInputEx）或硬件直接访问

### 15.4 下一步方向

1. **分析 FUN_0000f148()** — 确认是否是 BDS 菜单入口
2. **分析 FUN_000030e8()** — 按键读取实现，确认按键值 2 对应什么按键
3. **设备实测**：
   - 启动时按住某个按键（音量+/-、电源、HOME）看是否能进 BDS 菜单
   - fastboot 模式下是否有隐藏菜单入口
4. **确认 "EnableVolatileBootOptions" 变量的影响范围**

### 15.5 分析脚本和输出

- 脚本：`tools/analyze_bds_menu.java`
- 输出：`tools/bds_menu_output.txt`（51KB）

---

## 十六、BDS 菜单触发方式分析（手表单按键问题）（2026-10-09）

### 16.1 FUN_0000f148 不是 BDS 菜单入口

只有 88 字节，是简单的初始化函数：
```c
void FUN_0000f148(void) {
    FUN_00007e9c(&DAT_00018178);
    FUN_000047b8();
    FUN_00006f00(0x80000000, 0x16dc3);
    FUN_0000f1a0();
}
```
调用者：FUN_000016a8、FUN_0000fba0

### 16.2 ★ 按键读取使用 UEFI SimpleTextInput 协议

FUN_000030e8 (292字节) 反编译关键部分：
```c
void FUN_000030e8(short *output, uint flags) {
    if ((flags & 1) == 0) {
        do {
            event = *(DAT_000186d0 + 0x30);  // WaitForKey 事件
            status = (*(DAT_000186d8 + 0x60))(1, &event, &result);  // WaitForEvent
            if (status != 0) return;
        } while (result != 0);
    }
    status = (*(DAT_000186d8 + 0x98))(con_in, &key_data, &key);  // ReadKeyStroke
    if (status == 0) {
        FUN_0000353c(&key_code, 0xc);  // 处理按键码
        ...
        *output = key_code;
        if (特殊组合键) *output = 5;  // 特殊按键值 5
    }
}
```

**关键发现**：
- 使用 **UEFI SimpleTextInput 协议**（WaitForEvent + ReadKeyStroke）
- 不是直接读硬件 GPIO
- `flags` 参数：bit0 = 是否等待，bit1 = 是否重置
- 特殊按键值 5 是一个组合键

### 16.3 手表单按键的触发方式分析

小天才 Z10 只有一个电源键，但 BDS 菜单需要按键值 2 触发。可能的触发方式：

| 方式 | 可能性 | 说明 |
|------|--------|------|
| **快速按多次电源键** | 🟡 中 | 3秒内按2-3次，驱动可能转换成特殊按键码 |
| **长按电源键** | 🟡 中 | 长按可能进入特殊模式，发送不同按键码 |
| **USB连接时按电源键** | 🟡 中 | USB 连接状态可能改变按键行为 |
| **UART串口发送按键** | 🟢 高 | SimpleTextInput 支持串口输入，发送 ESC/F2 等 |
| **UEFI变量触发** | 🟡 中 | 设置 BootNext 或其他变量后重启 |
| **fastboot命令触发** | 🟡 中 | `fastboot oem menu` 或类似命令 |
| **触摸屏手势** | 🔴 低 | UEFI 阶段触摸屏可能未初始化 |

**最可能的方式**：
1. **UART 串口** — SimpleTextInput 协议天然支持串口，发送 ESC (0x1B) 或 F2 可能触发
2. **快速按电源键** — 电源键驱动可能检测快速连击，转换成特殊按键码
3. **USB 键盘** — 如果支持 USB OTG，连接 USB 键盘按 F2/ESC

### 16.4 其他发现

- "USB path found" → FUN_0000154c（USB 启动路径检测）
- "BdsConsole.c" → FUN_0000e074（BDS 控制台初始化）
- "Console != ((void *) 0)" → 控制台检查
- 没有找到 "BootMenu"、"MenuEnable" 等控制变量
- BootNext 变量存在（"BootNextSize == sizeof(UINT16)"）

### 16.5 下一步方向

1. **分析 FUN_000016a8** — FUN_0000f148 的另一个调用者，可能是 BDS 菜单真正入口
2. **分析电源键驱动** — 在 XBL 或其他 DXE 模块中找 GPIO/PMIC 按键驱动
3. **设备实测**：
   - 启动时快速按电源键 3 次
   - 启动时长按电源键 10 秒
   - USB 连接时按电源键
4. **查找 UART 串口** — 手表主板上是否有串口测试点

### 16.6 分析脚本和输出

- 脚本：`tools/analyze_bds_trigger.java`
- 输出：`tools/bds_trigger_output.txt`（15KB）

---

## 十七、BDS 菜单真正入口分析（2026-10-09）

### 17.1 FUN_000016a8 是启动选项处理循环，不是菜单入口

260字节，反编译关键部分：
```c
undefined8 FUN_000016a8(param1, param2, param3) {
    FUN_00001f54();
    lVar3 = FUN_00004ae0();
    do {
        if (FUN_00001f40()) return EFI_NOT_FOUND;  // 0x800000000000000e
        if (thunk_FUN_0000d3fc() & 0xff == 0) {
            FUN_000014b4(...);  // 非 USB 路径
        } else {
            FUN_00007a6c();
            FUN_0000f148();  // 初始化
            FUN_0000142c(...);  // 加载启动选项
            FUN_0000154c(...);  // "USB path found"
            FUN_0000200c(...);  // 启动镜像
        }
        FUN_00004b18();
    } while(true);
}
```

调用者：FUN_00001a54、FUN_00001ad4（QcomBds.c 主函数）

### 17.2 ★ 重大发现：QcomBds 中没有 BDS 菜单显示逻辑

搜索结果：
- ❌ 没有 "menu" 相关字符串
- ❌ 没有电源键/PMIC/GPIO/按键相关字符串
- ❌ 没有 BDS_Menu.cfg 的引用
- ✅ 有 28 个函数引用 SimpleTextInput 协议（按键读取）

**结论**：
- BDS 菜单的显示逻辑**不在 QcomBds 模块中**
- BDS 菜单可能由另一个模块处理（如 BdsDxe、UiApp、FrontPage）
- 电源键驱动在**其他 DXE 模块**中
- BDS_Menu.cfg 可能由 Ebl 或其他模块读取

### 17.3 SimpleTextInput 相关函数（28个）

关键函数：
- FUN_000030e8 — 按键读取（WaitForEvent + ReadKeyStroke）
- FUN_0000154c — USB 启动路径（"USB path found"）
- FUN_0000e074 — BdsConsole.c（控制台初始化）
- FUN_0000d3fc — 可能是检查启动设备类型

### 17.4 下一步方向

1. **在 inner_fv.bin 中搜索 BdsDxe/UiApp/FrontPage 模块** — BDS 菜单可能在这些模块中
2. **搜索电源键驱动** — 在其他 DXE 模块中找 PMIC/GPIO 按键处理
3. **分析 Ebl 模块** — Ebl 可能有菜单处理逻辑（BDS_Menu.cfg 可能由 Ebl 读取）
4. **设备实测**：
   - 启动时快速按电源键 3 次
   - 启动时长按电源键 10 秒

### 17.5 分析脚本和输出

- 脚本：`tools/analyze_bds_menu_entry.java`
- 输出：`tools/bds_menu_entry_output.txt`（17KB）

---

## 十八、DeepSeek 复核结论（重大修正）（2026-10-09）

### 18.1 决定性发现：BDS_Menu.cfg 是死配置

**86个DXE模块 + V1.0.1/V2.8.1/作者abl 全部扫描结果**：
- `[BDS Menu]`、`FirstRow`、`DefaultSelect`、`SecurityToggleApp`、`DebugPolicyToggleApp`、`LaunchCATE`、`Exit BDS Menu` 等关键字 → **只有 BDS_Menu.cfg 自己有**
- `BdsMenu`、`FrontPage`、`UiApp` → **全固件 0 处**
- `RPMBProvision` → 只有 cfg，SdccDxe 里是日志文本
- `EnableVolatileBootOptions` → **0 处**（之前分析有误）

**结论**：BDS 菜单在本机**根本不会被渲染**，不是"按键不够"的问题，是菜单代码被 XTC 裁掉了。

### 18.2 我的分析错误更正

| 原判断 | 更正 |
|--------|------|
| FUN_0000353c = 按键处理 | ❌ 是 `SetMem(&key, 0xC, 0)`（清空12字节key结构） |
| 按键值2 = 特殊按键/ESC/F2 | ❌ 是 `ScanCode==2 == SCAN_DOWN`（下方向键） |
| 有"3秒进菜单窗口" | ❌ 0xF448是阻塞式等按键，与菜单无关 |
| EnableVolatileBootOptions 变量存在 | ❌ 镜像里0处 |

### 18.3 我的分析正确的部分

- ✅ FUN_000030e8 = UEFI SimpleTextInput 按键读取（WaitForEvent + ReadKeyStroke）
- ✅ QcomBds 中没有菜单显示逻辑
- ✅ 按键读取不是直接读硬件GPIO

### 18.4 新发现（有价值的模块）

| 模块 | 位置 | 作用 |
|------|------|------|
| **ButtonsDxe** | 0x3196B0 | 物理按键驱动，PMIC GPIO/PON→扫描码，有 `InitializeKeyMap()` |
| **SimpleTextInOutSerial** | 0xD5920 | ★ 串口控制台输入，UART接通就能操作UEFI控制台 |
| ConPlatformDxe | — | 控制台平台层 |
| ConSplitterDxe | — | 控制台汇聚层（合并多来源输入） |

**ButtonsDxe 字符串**：
- `ButtonsInit: failed to locate PmicGpioProtocol/PmicPONProtocol/PlatformInfo Protocol`
- `ConfigureButtonGPIOs: EnableInput failed for VOL+ button`
- `InitializeKeyMap() failed`
- `PollPowerKey: ReadRealTimeIRQStatus failed for Power Button`
- `PollButtonArray`、`ReadGpioStatus`、`ButtonsLib.c`

**没有 UsbKbDxe** → OTG键盘在UEFI阶段不可用。

### 18.5 调整后的研究方向

| 优先级 | 方向 | 理由 |
|--------|------|------|
| **P0** | **UART/串口测试点** | SimpleTextInOutSerial已证明串口是控制台输入源，找到测试点就能看日志+敲键盘+进Ebl shell |
| P1 | ButtonsDxe 的 key map | 确认电源键短按/长按/连击产出哪些扫描码 |
| P1 | Ebl 的命令通道 | 确认Ebl输入来源，是否有非交互触发 |
| P1 | 变量存储落盘位置 | VariableDxe后端 + DebugPolicy/SecureBoot变量消费者 |
| ❌ 放弃 | BDS菜单触发 | 无解析者，死配置 |
| ❌ 放弃 | imagefv植入 | 无代码+无消费者+要过PAS |
| ❌ 放弃 | OTG键盘 | 无UsbKb驱动 |

### 18.6 风险提醒

- `Provision RPMB` 一旦预置不可更改、可能变砖，即使将来真能到达菜单也不要碰
- SecurityToggleApp/DebugPolicyToggleApp 不在DXE FV，也不在任何分区镜像里（toolsfv/catefv全0）

### 18.7 复核报告

- `reports/分析报告_BDS菜单触发机制复核_DeepSeek.md`

---

## 十九、ButtonsDxe 按键映射分析（2026-10-09）

### 19.1 模块信息

- 文件：`unpacked_xbl/v1.0.1/ButtonsDxe.pe32`（36,864 字节）
- 位置：inner_fv.bin @ 0x319718
- 功能：物理按键驱动，PMIC GPIO/PON → UEFI SimpleTextInput 扫描码

### 19.2 三个物理按键

| 按键 | 读取方式 | 函数 |
|------|----------|------|
| **Power（电源键）** | PmicPON ReadRealTimeIRQStatus | FUN_000039d4 (PollPowerKey) |
| **VOL+** | PmicGpio ReadGpioStatus | FUN_00003894 |
| **VOL-** | PmicPON ReadRealTimeIRQStatus | FUN_00003830(1, ...) |

**PollButtonArray (FUN_00003920)** 输出：
- param_1[0] = Power 状态
- param_1[1] = VOL+ 状态
- param_1[2] = VOL- 状态

### 19.3 ★ 按键组合检测（FUN_00003320）

读取 6 个按键状态，检测组合：

| 组合 | 扫描码 | 含义 |
|------|--------|------|
| uVar1 + uVar2 | 5 | INSERT? |
| uVar1 + uVar3 | 8 | DELETE? |
| uVar2 | 5 或 1 | INSERT 或 UP |
| uVar3 | 2 或 8 | DOWN 或 DELETE |
| uVar6 | 0x102 | 特殊 |
| **uVar2 + uVar3** | **0x17** | **★ ESC！** |

**关键发现：同时按两个键可以产生 ESC (0x17) 扫描码！**

### 19.4 InitializeKeyMap (FUN_00003528)

根据平台类型选择 key map 表：
- 平台类型 1 → DAT_000071a8
- 平台类型 3/8/0x24/0x22 → DAT_000071bc
- 平台类型 0xb → DAT_000071e4
- 平台类型 0x19 → DAT_000071d0
- 平台类型 0x1d → DAT_000071f8

每个 key map 表 5 个条目（0x14 字节），每条目 4 字节（u16 ScanCode + u16 Unicode）。

平台类型=1 的 key map（DAT_000071a8）：
- 条目0: ScanCode=0x0001 (UP), Unicode=0x0000
- 条目1: ScanCode=0x0002 (DOWN), Unicode=0x0000
- 条目2: ScanCode=0x0003 (RIGHT), Unicode=0x0000
- 条目3: ScanCode=0x0007 (INSERT), Unicode=0x0000
- 条目4: ScanCode=0x0000 (空), Unicode=0x0000

### 19.5 按键状态变化检测（FUN_00001864）

- 比较当前按键状态和上一次状态
- DAT_00007210 = 1 表示有按键变化
- 检测按下/释放事件

### 19.6 对用户的意义

用户的 6 点式触点数据线上有一个按钮，长按电源键+数据线按钮进入 9008。
**这个数据线按钮很可能就是 VOL+ 或 VOL-！**

如果数据线按钮 = VOL+ 或 VOL-，那么：
- 电源键 + 数据线按钮 = 两个键同时按 = 可能产生 ESC (0x17)
- ESC 在 UEFI 中通常用于中断启动流程或进入菜单

### 19.7 设备实测结果（2026-10-09）

**实测命令**：`adb shell getevent -l`

| 操作 | 设备 | 事件 | MSC_SCAN | MSC_SERIAL |
|------|------|------|----------|------------|
| 电源键轻按 | event0 + event9 | `EV_KEY KEY_POWER` + `EV_MSC` | 0x164 (356) | 0x00010000 |
| 电源键重按 | event0 + event9 | `EV_KEY KEY_POWER` + `EV_MSC` | 0x173 (371) | 0x00010000 |
| 电源键长按 | event0 + event9 | `EV_KEY KEY_POWER` + `EV_MSC` | 0x17b, 0x17c | 0x00020000, 0x00010000 |
| 电源键连按3下 | event0 + event9 | `EV_KEY KEY_POWER` + `EV_MSC` | 0x18b (395) | 0x00010000 |
| **数据线按钮3下** | **event9 only** | **`EV_MSC` only** | **0x1b1 (433), 0x1b2 (434)** | **0x00010000, 0x00020000** |

**完整 MSC_SCAN 数据**：

| 操作 | MSC_SCAN | 范围 |
|------|----------|------|
| 电源键轻按 | 0x164 (356) | **电源键: 0x164~0x18b** |
| 电源键重按 | 0x173 (371) | |
| 电源键长按 | 0x17b, 0x17c | |
| 电源键连按3下 | 0x18b (395) | |
| 数据线按钮3下 | 0x1b1, 0x1b2 | **数据线: 0x1b1~0x1d7** |
| 开机时点击数据线 | 0x1c6, 0x1c9 | |
| 长按数据线按钮 | 0x1d7 (471) | |

**关键观察**：
1. 两个独立通道：电源键 (0x164~0x18b) 和数据线按钮 (0x1b1~0x1d7) 范围完全不重叠
2. MSC_SCAN 不是固定扫描码，同一按键不同按法值不同，可能包含时长/次数编码
3. 数据线按钮只走 MSC 通道（event9），不产生 EV_KEY，Android 不把它当键盘
4. 电源键走双通道：event0 (KEY_POWER) + event9 (MSC)
5. Android 下电源键+数据线按钮组合无效果（Android 不处理数据线 MSC 事件）

**结论**：
1. 数据线按钮连接到特殊输入通道，在 Android 下通过 MSC 事件上报（非标准按键）
2. 在 UEFI 阶段，ButtonsDxe 直接读 PMIC GPIO/PON，**可能会把数据线按钮识别为 VOL+ 或 VOL-**
3. 需要在真正的 UEFI 阶段（logo 出现前）测试数据线按钮效果
4. Android 下的组合键无效果不代表 UEFI 下也无效果

### 19.8 输入设备列表分析（2026-10-09）

`cat /proc/bus/input/devices` 结果：

| 设备 | 名称 | 类型 |
|------|------|------|
| event0 | qpnp_pon | PMIC 电源键（KEY=140000） |
| event1-8 | Bbd 传感器 | 加速度/陀螺仪/心率/温度/血氧/佩戴/PPG/计步 |
| **event9** | **Bbd Motion_state Sensor** | **运动状态传感器（非按键！）** |
| event10-26 | Bbd 传感器 | 抬手唤醒/开始停止/卡路里/气压/方向等 |
| event27 | qcom-hv-haptics | 线性马达 |
| event28 | hall_sensor | 霍尔传感器 |
| event29 | raydium_ts | 触摸屏 |
| **event30** | **gpio-keys** | **GPIO 按键（KEY=80000）** |

**重大更正**：
1. event9 = 运动状态传感器，不是按键！之前的 MSC_SCAN 是传感器数据
2. 数据线按钮在 Android 下不产生 EV_KEY 事件
3. **gpio-keys (event30)** 是独立的 GPIO 按键设备，可能对应 VOL+/VOL-
4. 数据线按钮很可能是 EDL 触发引脚，只在 bootloader 阶段生效

### 19.9 设备实测最终结论（2026-10-09）

**关键测试**：关机后按住数据线按钮不放 + 按电源键开机 → **直接进入 9008 (EDL)**

**结论**：
1. ✅ 数据线按钮 = **FORCE_EDL 触发引脚**（test point），不是 VOL+/VOL-
2. ❌ 无法通过数据线按钮触发组合键产生 ESC
3. ⚠️ ButtonsDxe 的 VOL+/VOL- 代码是硬件预留，手表本体无物理按键
4. 🔧 主板上可能有 VOL+/VOL- 测试点，但需要拆机

**输入设备最终确认**：
- event0 = qpnp_pon（电源键）
- event9 = 运动状态传感器（之前的 MSC 事件是传感器数据，非按键）
- event30 = gpio-keys（无输出，预留未使用）
- 数据线按钮 = EDL 触发，不经过 Linux 输入子系统

### 19.10 下一步方向

1. **利用 EDL 访问能力**：用户已可通过数据线按钮进入 9008，可尝试：
   - 用 QFIL/其他工具读取分区（之前读取失败，可换工具/方法）
   - 在 EDL 下刷入修改后的镜像
   - 分析 firehose 协议的限制

2. **寻找 VOL+/VOL- 测试点**：需要拆机看主板，或找维修图纸

3. **转向其他研究方向**：
   - Ebl 命令通道（不经 PIL/PAS 的加载执行通道）
   - UEFI 变量存储（uefivarstore 空分区）
   - toolsfv 等空分区的利用

4. **分析 gpio-keys 设备树**：确认 VOL+/VOL- 对应的 GPIO 引脚

### 19.11 🔴 重大发现：QMMI 表冠测试项目（2026-10-09 晚）

用户在 QMMI 测试模式中发现**"表冠"测试项目**，测试内容为**向上和向下**，但手表本体没有该硬件。

**关键意义**：
1. **表冠（crown）= VOL+/VOL- 的物理载体**
   - 旋转表冠向上 → 产生 VOL+ 事件
   - 旋转表冠向下 → 产生 VOL- 事件
2. **解释了 ButtonsDxe 的 VOL+/VOL- 代码**：固件支持表冠，只是 Z10 这款型号未焊接
3. **主板上有表冠的测试点/引脚**：QMMI 测试项目存在说明驱动已就绪
4. **如果能短接表冠测试点**：
   - 可以模拟 VOL+/VOL- 按键
   - 配合电源键产生组合键 → ESC (0x17)
   - 可能在 UEFI 阶段触发特殊模式（Ebl shell/工程模式）

### 19.12 🔴 VOL+ 设备树配置完整定位（2026-10-09 晚）

**gpio_keys/vol_up 配置**：

| 属性 | 值 | 含义 |
|------|-----|------|
| label | `volume_up` | 音量加键 |
| linux,code | `0x73` = 115 | **KEY_VOLUMEUP** |
| linux,input-type | `0x01` | EV_KEY |
| gpios | phandle=0x5e, pin=9, flags=1 | GPIO 控制器 #94 的 pin 9 |
| debounce-interval | 15ms | 去抖时间 |
| gpio-key,wakeup | 存在 | 可唤醒系统 |
| linux,can-disable | 存在 | 可禁用 |

**PMIC pinctrl@8800 下的 key_vol_up 配置**：
- 路径：`/soc/qcom,spmi@1c40000/qcom,pm5100@0/pinctrl@8800/key_vol_up/key_vol_up_default/`
- 说明 VOL+ 连接到 **PMIC (pm5100) 的 GPIO**，不是主 TLMM GPIO
- pinctrl@8800 的 phandle 待确认是否为 0x5e

**VOL- 配置位置**：
- 应该在 `pon_hlos@1300`（PMIC PON 驱动）里，与电源键同一个驱动
- 路径：`/soc/qcom,spmi@1c40000/qcom,pm5100@0/pon_hlos@1300/qcom,pon_1/` 和 `qcom,pon_2/`
- 待确认具体配置

**输入设备确认**：
- event0 = qpnp_pon（电源键 + 可能的 VOL-）
- event30 = gpio-keys（VOL+，但无物理连接所以无输出）
- event9 = 运动状态传感器（之前误判为按键）

**结论**：
1. VOL+ = PMIC GPIO pin 9（通过 gpio-keys 驱动，event30）
2. VOL- = PMIC PON（通过 qpnp_pon 驱动，event0，与电源键同驱动）
3. 手表本体未焊接表冠硬件，所以 VOL+/VOL- 无物理输入
4. **需要拆机找 PMIC GPIO pin 9 和 PON 的测试点才能短接触发**

### 19.13 下一步方向（无需拆机的软件方向）

用户没有拆机工具，需要寻找**不需要硬件操作**的替代方案：

1. **软件模拟 VOL+/VOL-**
   - Linux 输入子系统允许通过 uinput 或 /dev/uinput 模拟按键事件
   - 但这只能在 Android 系统下生效，UEFI 阶段无法模拟
   - 可以尝试 `sendevent` 或 `input keyevent` 命令

2. **直接写 PMIC 寄存器触发 VOL+/VOL-**
   - 在 Android root 下，可以通过 i2c/spmi 工具直接写 PMIC 寄存器
   - 模拟按键按下/释放
   - 但这也只能在 Android 下生效

3. **利用 EDL 能力做更多**
   - 用户已有 EDL 访问（数据线按钮+电源键）
   - 可以尝试在 EDL 下读取/写入更多分区
   - 可以尝试修改 UEFI 变量存储（uefivarstore）

4. **寻找进入 Ebl/工程模式的软件方式**
   - 分析 QcomBds 的启动流程，看是否有软件触发条件
   - 分析 fastboot OEM 命令，看是否有隐藏命令
   - 分析 UEFI 变量，看是否有控制启动模式的变量

5. **向 XTC/小天才申请源码或工程模式**
   - service@okii.com
   - GPL 源码申请（内核源码已开源，但 abl/XBL 是 Qualcomm 专有）

### 19.14 下一步

1. 写 DeepSeek 提示词，询问无需拆机的替代方案
2. 确认 VOL- 的设备树配置
3. 分析 Ebl 模块的进入条件

### 19.8 分析脚本和输出

- 提取脚本：`tools/extract_buttonsdxe2.py`
- 分析脚本：`tools/analyze_buttonsdxe.java`、`tools/analyze_buttonsdxe2.java`、`tools/analyze_keymap.java`
- 输出：`tools/buttonsdxe_output.txt`、`tools/buttonsdxe_output3.txt`、`tools/keymap_output.txt`

### 19.15 ✅ 补充验证（DeepSeek）：19.11 的"表冠机型共用固件"假设——已证实，并纠正一处误判

对 19.11 的假设（"Z10 固件是同一平台其他型号，如带表冠手表，共用的固件"）做了全镜像流式扫描核查，**假设成立**，且找到了比猜测更硬的证据；同时纠正此前一处误判。完整报告见 `reports/分析报告_同平台机型核查_ND01_ND03_ND07与OPPO_DeepSeek.md`。

**新增硬证据（均为本机 v1.0.1 镜像内直接可见）**：

1. **一个 AP 镜像装三款机型**：`super_3.img` 0x018D3AD73 起的资源名字符串池连续出现 `ND01` / `ND01_HK_*` / `ND01_SN_*` / `ND01_aod_default_*` / `ND03` / `ND03_charge_default_0..3` / `ND03_charges_preset_*` / `ND07` / `ND07_charges_preset_*` ⇒ **ND01、ND03、ND07 三款机型的 AOD/充电预设资源在同一镜像里**，且含 **HK / SN 区域 SKU**（香港/新加坡变体）。
2. **XTC 与 imoo 共用同一镜像**：同镜像含用户可见文案 `"...permissions through imoo Watch Phone..."`（含印尼语等多语言）与 `img_motion_imoo_pk*` 系列资源 ⇒ imoo（BBK 海外儿童表品牌）与小天才共用该平台固件。
3. **平台标识全链路一致**：`xbl.elf`/`prog_firehose_ddr.elf` 含 `Atherton` / `AthertonLAA` / `AthertonPkgLAA`，`tz.mbn` 含 `Atherton_register_se…`，`super_2.img` 含 `IsAthertonWearableLimitedCap`（W5 非 Plus 版本判定）。公开佐证：WOA-Project 仓库标题即 "Platform drivers for Snapdragon W5+ (\"Atherton\") devices" ⇒ **Atherton = 骁龙 W5/W5+ Gen 1 穿戴平台代号**，多 OEM 共用同代芯片。
4. **ND08 与本机同密钥**：作者 abl 的构建工作区为 `ND08_System_HLOS_UserDebug` / `ND08_System_HLOS_User`，而本机是 ND03 ⇒ 同族机型签名密钥互通，这是"可借用其他型号固件"的实锤。

**⚠️ 纠正**：此前把 `super_4`/`super_5` 里的 `oppo`×26 / `OPPO`×1 / `OnePlus` / `imoo` / `crown` 当作"多品牌共用证据"是**误判**。逐条打印上下文后确认全部是通用字符串巧合：`opposite`/`opportunity`/`oppositeendian`、`ALIGN_OPPOSITE`、广告过滤 URL 列表（`oneplus.in/#` 与 `autotrader.co.uk/#…` 并列）、爱沙尼亚语 `nteesimootorit`、商户类别词表里的 `crown`、词典串 `incrowned`、C++ 符号 `_Z10get_stringPKc`。**多机型结论改用上面 1–4 的证据，与这些巧合无关。**

**关于表冠**：AP 镜像层面找不到"表冠硬件"证据（旋转输入代码是 AOSP 通用的 `RotaryEncoderInputMapper` / `SOURCE_ROTARY_ENCODER`，任何 Android 都有）。表冠的真实证据仍只有 **QMMI 工厂测试的"表冠 向上/向下"测试项**——它与 19.12/19.13 的结论（VOL+ = PMIC GPIO pin 9 / gpio-keys event30；VOL− = PMIC PON）组合起来的推论是：**表冠机型把表冠旋转接到 VOL+/VOL− 输入上，Z10 未焊该硬件但固件保留全套代码路径**。所以 19.11 第 2 条判断正确。

**对方案的影响**：跨 OEM（OPPO Watch X = 骁龙 W5 Gen 1，已核实）的 abl/XBL **不可刷**——本机证书链为 "General Use XTC Key 1"，PIL 在 TZ 内经 `PAS_AUTH_AND_RESET`（SMC 0x42000205）验签，别人的密钥必然失败；板级配置（PMIC/面板/设备树）与 99 分区 A/B 布局也不同。OPPO 固件只能作为**同平台参考实现**阅读。可复用的"其他型号"应锁定 **BBK 同族（ND01/ND03/ND07/ND08 + imoo）**，用 `deep_check/check_abl_unlock_stub.py` 秒级筛查其 abl 的解锁面（构建类型 / IsUnlocked 桩 / 是否带 `flash:`、`erase:`、`flashing unlock`）。
