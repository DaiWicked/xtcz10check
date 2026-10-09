# 会话概括：PILDxe + TrustZone 分析进展

> 日期：2026-10-09
> 主题：imagefv 路线深入分析 — PILDxe 完整逆向 + SCM 调用号解码 + TrustZone 分析开始 + DeepSeek 复核 + P0-1 触发者定位

---

## 一、本次会话完成的工作

### 1. P0-2：追踪 Unlock 字段消费路径 ✅
- 运行了两个 Ghidra Headless 脚本
- 发现：PILDxe 内 Unlock 只写不读，配置结构体被整体通过 SCM 传递给 TrustZone

### 2. 方案 C：搜索高通 PIL 开源代码 ✅
- **重大突破 — SCM 调用号解码**：
  - 0x2000201 → PIL PAS_INIT_IMAGE
  - 0x2000205 → PIL PAS_AUTH_AND_RESET
- imagefv 真实用途：Image File Verification image，包含签名和证书

### 3. 方案 B：TrustZone 固件分析（开始）🔄
- tz.mbn 是 64位 ARM ELF（2.8 MB）
- 关键字符串：PAS(7次), pil_(6次), SCM(1次), QSEE(11次), qsee(723次)
- 未找到 "Unlock" 字符串

### 4. DeepSeek 复核报告（重大更正）🔴
- ❌ **"Unlock 字段被传递给 TrustZone"不成立**：实参只有 metadata+pas_id，Unlock 是死配置键
- ❌ **"imagefv = 验证其他镜像的镜像"用途搞错了**：实际是 splash/logo 图片的 UEFI FV
- ✅ SCM 调用号解码正确，精确化为 0x42000201/0x42000205
- ✅ 三种类型都要过 PAS，无免认证分支
- 🟢 **新线索：FUN_195C 极可能是 imagefv（SubsysID=20）的装载路径**

### 5. P0-1：imagefv 装载触发者定位 ✅
- **FUN_195C 的调用者是 FUN_1578**（24字节包装函数）
- **FUN_18F4 的调用者是 FUN_1548**（24字节包装函数）
- **FUN_1560 无直接调用者**（通过函数指针表调用）
- "ImageFv" 字符串在 PILDxe 代码中无直接引用者（只在配置文件里）

### 6. P0-1 扩展：整个 DXE 卷搜索 ✅
- **"ImageFv"/"imagefv" 字符串在整个 DXE 卷中 0 处！**
- Splash/logo 字符串都在第54个模块 = **DisplayDxe**
- DisplayDxe 有关键函数：EnablePlatPartition、GetContinuousSplashInfo、RenderSplashScreen
- MountFv 字符串在第75个模块后
- **猜想：imagefv 可能不通过 PIL 协议加载，而是通过 MountFv/FvSimpleFileSystem 直接挂载（可能不验签！）**

### 7. DeepSeek 复核提示词 ✅
- 创建了 `reports/提示词_imagefv触发者与DisplayDxe分析_DeepSeek.md`
- 包含 5 个核心问题、3 个猜想、已验证死路清单

### 8. 文档更新 ✅
- 更新了分析笔记（加入 P0-1 扩展结果）
- 更新了项目状态快照
- 更新了会话概括（本文件）

---

## 二、当前核心结论

### 已确认 ✅
1. **PILDxe 完整结构**：uefipil.cfg 正确版本，ImageFv 在零售白名单但不在 AUTO 列表
2. **SCM 调用号解码**：0x201=PAS_INIT_IMAGE, 0x205=PAS_AUTH_AND_RESET（完整ID=0x42xxxxxx）
3. **Unlock 字段是死配置键**：PILDxe 内只写不读，不跨 SCM 边界传给 TZ
4. **imagefv 真实用途**：splash/logo 图片的 UEFI FV（不是验证根）
5. **三种类型都要过 PAS**：elf_fv、elf_split、single 都含 PAS_INIT+PAS_AUTH
6. **FUN_195C 是 imagefv 装载路径**：SubsysID=20，调用 PAS_INIT→PAS_AUTH
7. **imagefv 触发者在 PILDxe 外部**：需要在整个 DXE 卷（86个模块）中搜索

### 未解决 ❓
1. **谁在什么条件下触发 imagefv 加载？**（需要搜索整个 DXE 卷）
2. **MountFv 是否存在非交互调用路径？**（第二条独立通道，不经过 PIL/PAS）
3. **imagefv 的 JPEG 解析器是否有可利用漏洞？**（类似 LogoFAIL）
4. **TrustZone 的 PAS 认证是否在 unlocked 状态下放宽？**

---

## 三、下一步计划（按优先级）

### P0：在整个 DXE 卷中搜索 imagefv 触发者（零风险）
1. 在 inner_fv.bin（4.9MB，86个模块）中搜索 PIL 协议使用者
2. 搜索 "ImageFv" 字符串在其他模块中的引用
3. 搜索 splash/logo 相关模块（DisplayDxe、SplashScreen 等）

### P0：路径 B — imagefv 解析漏洞审计（当前最现实）
4. imagefv 里是 JPEG 图片，解析器与 LogoFAIL 类问题同族
5. 静态审计 FV/JPEG 解析器，成本低、有历史先例

### P0：MountFv 通道（第二条独立路径）
6. XBL DXE 有 MountFv，可以把分区里的 FV 挂进 DXE 文件系统
7. 若存在非交互调用路径，不经过 PIL/PAS

### P1：TrustZone 分析（限定范围）
8. 只看 PAS auth 分支是否读 QFPROM 熔丝或 RPMB/device state
9. 按完整 function ID 0x42000201/0x42000205 检索

---

## 四、关键文件速查

| 文件 | 路径 | 说明 |
|------|------|------|
| PILDxe PE32 | `unpacked_xbl/v1.0.1/PILDxe.pe32` | 110,612 bytes，ARM64 |
| TrustZone | `decrypted_images/v1.0.1/tz.mbn` | 2.8 MB，64位 ARM ELF |
| DXE 卷 | `unpacked_xbl/v1.0.1/inner_fv.bin` | 4.9MB，86个模块 |
| 分析笔记 | `reports/分析笔记_PILDxe与imagefv装载机制.md` | 完整分析记录（含 DeepSeek 更正） |
| DeepSeek 复核 | `reports/分析报告_PILDxe与TrustZone复核_DeepSeek.md` | 重大更正报告 |
| 项目状态 | `项目状态快照.md` | 完整项目状态 |
| Ghidra 脚本 | `tools/find_imagefv_trigger.java` | imagefv 触发者追踪 |
| 分析输出 | `tools/imagefv_trigger_output.txt` | 44KB，P0-1 结果 |

---

## 五、快速恢复指令

下次会话开始时：
1. 读取本文件（30秒）
2. 读取 `项目状态快照.md`（1分钟）
3. 如需细节，读取 `reports/分析笔记_PILDxe与imagefv装载机制.md`
4. 开始 P0：在整个 DXE 卷中搜索 imagefv 触发者

**预计恢复时间：2分钟**
