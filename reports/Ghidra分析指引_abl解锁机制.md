# Ghidra 分析指引：小天才 Z10 (ND03) abl 解锁机制

> 目标：通过代码级反汇编分析，回答以下核心问题：
> 1. `read_is_device_unlocked` 从哪里读取解锁状态？
> 2. devinfo 结构的字段偏移和 magic 是什么？
> 3. `XTCWriteDevInfo` 的 "user key" 是什么？
> 4. UserDebug 构建和 User 构建在解锁判定上有什么差异？
> 5. 是否存在其他进入 unlocked 状态的路径？

---

## 一、环境信息

| 项目 | 值 |
|---|---|
| Ghidra 版本 | 12.1.4 PUBLIC (20260921) |
| JDK | Zulu 21.0.12.1 LTS (OpenJDK) |
| JAVA_HOME | `C:\Program Files\Zulu\zulu-21` |
| Ghidra 目录 | `H:\xtcz10check\ghidra_12.1.4_PUBLIC\` |
| 启动脚本 | `H:\xtcz10check\ghidra_12.1.4_PUBLIC\ghidraRun.bat` |

### 待分析文件

| 文件 | 路径 | 大小 | 说明 |
|---|---|---|---|
| v1.0.1 release abl | `H:\xtcz10check\unpacked_abl\v1.0.1\abl_pe32.bin` | 454856 B | 目标版本，需要解锁 |
| v2.8.1 release abl | `H:\xtcz10check\unpacked_abl\v2.8.1\abl_pe32.bin` | 454856 B | 对比用 |
| 作者 UserDebug abl | `H:\xtcz10check\unpacked_abl\author\abl_a_pe32.bin` | 487624 B | 关键对比，已解锁 |

### 文件格式

- **格式**：PE32+ (ARM64 AArch64)
- **ImageBase**：`0x0`（VA = 文件偏移，非常方便！）
- **EntryPoint**：`0x1000`
- **段表**：.text (VA=0x1000), .data (VA=0x59000), .reloc (VA=0x76000)

---

## 二、启动 Ghidra

### 方式 1：双击启动
直接双击 `H:\xtcz10check\ghidra_12.1.4_PUBLIC\ghidraRun.bat`

### 方式 2：命令行启动
```cmd
cd H:\xtcz10check\ghidra_12.1.4_PUBLIC
ghidraRun.bat
```

### 首次启动
- 会弹出 "Ghidra Help" 欢迎窗口，关闭即可
- 主界面是 "Ghidra Project Window"

---

## 三、创建项目并导入文件

### 步骤 1：创建新项目
1. `File` → `New Project...`
2. 选择 `Non-Shared Project` → Next
3. Project Directory: `H:\xtcz10check\ghidra_projects\`（新建目录）
4. Project Name: `ND03_abl_analysis`
5. Finish

### 步骤 2：导入三个 abl 文件
1. 在项目窗口中，`File` → `Import File...`
2. 依次导入：
   - `H:\xtcz10check\unpacked_abl\v1.0.1\abl_pe32.bin`
   - `H:\xtcz10check\unpacked_abl\v2.8.1\abl_pe32.bin`
   - `H:\xtcz10check\unpacked_abl\author\abl_a_pe32.bin`
3. 导入时会弹出 "Import" 对话框：
   - **Language**: 点击右侧图标，选择 `AARCH64` → `little endian` → `default` → `PE`
   - 或者直接让 Ghidra 自动检测（PE32+ ARM64 应该能自动识别）
   - 确认 Format 是 `Portable Executable (PE)`
   - 点击 OK

### 步骤 3：打开 CodeBrowser
1. 双击项目中的 `abl_pe32.bin`（v1.0.1）
2. 弹出 "Want to analyze?" 对话框 → **Yes**
3. 分析选项保持默认，点击 **Analyze**
4. 等待分析完成（约 1-2 分钟，454KB 的 ARM64 二进制）

---

## 四、关键分析步骤（按优先级）

### 优先级 1：定位 "State: Unlocked" 字符串引用

这是解锁机制的核心分支。找到这个字符串被谁引用，就能找到解锁判定函数。

1. 在 CodeBrowser 中，按 `G` 键（Go to），或者 `Navigation` → `Go To...`
2. 切换到 "Strings" 窗口（如果没有，`Window` → `Strings`）
3. 搜索 `Unlocked`（不区分大小写）
4. 找到字符串 `"State: Unlocked, AvbSlotVerify returned %a, continue boot"`
5. **右键 → References → Find references to "..."**（或按 `Ctrl+Shift+F`）
6. 这会列出所有引用这个字符串的代码位置
7. 双击跳转到引用处，这就是解锁判定函数的核心位置

**需要记录的信息**：
- 引用这个字符串的函数地址（函数名）
- 这个函数的调用者（谁调用了它）
- 函数内的条件分支逻辑（什么条件下打印 "State: Unlocked"）

### 优先级 2：定位 `read_is_device_unlocked` 函数

字符串 `"assert fail: ops->read_is_device_unlocked != NULL"` 表明这是一个函数指针协议。

1. 在 Strings 窗口搜索 `read_is_device`
2. 找到 `"assert fail: ops->read_is_device_unlocked != NULL"`
3. 查找引用（`Ctrl+Shift+F`）
4. 跳转到引用处，分析：
   - `ops` 是什么结构体？
   - `read_is_device_unlocked` 函数指针在哪里被赋值？
   - 实际的 `read_is_device_unlocked` 实现函数在哪里？

**追踪方法**：
- 在引用处，找到 `ops->read_is_device_unlocked` 的调用
- 追溯 `ops` 结构体的来源（参数？全局变量？）
- 找到 `read_is_device_unlocked` 被赋值的位置（通常在某个初始化函数中）
- 跳转到实际的实现函数

**需要回答的问题**：
- 这个函数从哪里读取解锁状态？（devinfo 分区？eMMC 某个偏移？寄存器？）
- 读取的数据结构是什么？（magic？字段偏移？）
- 返回值是什么？（0=locked, 1=unlocked?）

### 优先级 3：定位 `XTCWriteDevInfo` 函数

字符串 `"--- XTCWriteDevInfo user key is not null , so we need clear it !"` 和 `"--- XTCWriteDevInfo Unable to Write Device Info: %r"`。

1. 在 Strings 窗口搜索 `XTCWriteDevInfo`
2. 找到两个相关字符串
3. 查找引用，跳转到 `XTCWriteDevInfo` 函数
4. 分析：
   - "user key" 是什么？（签名？序列号？某个密钥？）
   - 函数写入的目标分区是哪里？（devinfo?）
   - 写入的数据结构是什么？
   - 什么条件下会 "clear user key"？

### 优先级 4：定位 devinfo 读取/解析逻辑

搜索与 devinfo 相关的字符串：
- `"BootLinux: pDevInfo is NULL!"`
- `"device info: pDevInfo->boot_into_linux[sotre_index] = %d"`
- `"VBRwDeviceState DevInfo.verity_mode=%d:"`

这些字符串能帮助定位 devinfo 结构体的解析代码。

1. 搜索 `pDevInfo`
2. 找到引用，跳转到 devinfo 解析函数
3. 分析结构体字段偏移：
   - `boot_into_linux` 在哪个偏移？
   - `verity_mode` 在哪个偏移？
   - `is_unlocked` 可能在哪个偏移？
   - 是否有 magic 字段？

### 优先级 5：对比 release vs UserDebug 解锁逻辑

使用 Ghidra 的 "Version Tracking" 或手动对比：

1. 同时打开 v1.0.1 release 和 author UserDebug 的 CodeBrowser
2. 在两个版本中都定位到 `read_is_device_unlocked` 的实现
3. 对比函数逻辑：
   - UserDebug 版本是否直接返回 1（unlocked）？
   - UserDebug 版本是否跳过了某些校验？
   - 函数大小和指令差异
4. 对比 `XTCWriteDevInfo` 函数
5. 对比解锁判定主函数（引用 "State: Unlocked" 的函数）

**快速对比方法**：
- 在两个 CodeBrowser 中都跳转到同一个函数
- 对比函数的指令列表（Listing 窗口）
- 注意 UserDebug 版本多出的 32KB 代码在哪里

---

## 五、关键搜索词清单

在 Strings 窗口中搜索以下关键词（按优先级排序）：

### 解锁状态相关
- `Unlocked`
- `is_unlocked`
- `read_is_device`
- `Device unlocked`
- `Device State`
- `secure`
- `is_secure`

### devinfo 相关
- `pDevInfo`
- `DevInfo`
- `devinfo`
- `boot_into_linux`
- `verity_mode`
- `VBRwDeviceState`
- `XTCWriteDevInfo`
- `user key`

### AVB / 启动相关
- `AvbSlotVerify`
- `AvbSlotVerify returned`
- `continue boot`
- `No bootable slots`
- `BootLinux`

### fastboot 相关
- `Unsupport unlock`
- `fastboot`
- `flashing`
- `oem`

### UserDebug 独有（仅在作者版本中搜索）
- `UserDebug`
- `ND08_System`
- `DEBUG`
- `assert`

---

## 六、预期发现（假设）

基于字符串分析，我们预期会发现：

### 假设 A：devinfo 格式不是标准高通格式
- 标准高通 devinfo：magic="BOOT"|"XBCR"，is_unlocked 在偏移 0x10
- 小天才可能自定义了 magic 和字段偏移
- 我们手动写标准 devinfo 不生效，因为 magic 不对
- **验证方法**：在 Ghidra 中找到 devinfo 解析代码，看它比较的 magic 是什么

### 假设 B：devinfo 有签名/校验
- `XTCWriteDevInfo` 提到 "user key"，可能 devinfo 有签名校验
- 只有用正确的 "user key" 签名的 devinfo 才被接受
- **验证方法**：分析 `XTCWriteDevInfo` 和 devinfo 读取函数，看是否有签名验证

### 假设 C：UserDebug abl 默认返回 unlocked
- UserDebug 构建的 `read_is_device_unlocked` 可能直接返回 1
- 或者跳过了 devinfo 读取，硬编码为 unlocked
- **验证方法**：对比两个版本的 `read_is_device_unlocked` 实现

### 假设 D：解锁状态存在其他位置
- 可能不在 devinfo 分区，而在某个其他分区（如 xtcinfo, persist）
- 或者在某个寄存器/eFuse 中
- **验证方法**：追踪 `read_is_device_unlocked` 的读取目标

---

## 七、输出记录模板

分析过程中，请记录以下信息（可以写在 `H:\xtcz10check\ghidra_analysis_notes.md`）：

```
## 函数：<函数名或地址>
- 地址范围：0xXXXX - 0xXXXX
- 功能描述：...
- 关键字符串引用：...
- 调用者：...
- 被调用函数：...
- 关键逻辑：
  - if (条件) { ... }
  - else { ... }
- 与 UserDebug 版本的差异：...
```

---

## 八、常见问题

### Q: Ghidra 启动报错 "Could not find javaw.exe"
A: 确认 JAVA_HOME 已设置为 `C:\Program Files\Zulu\zulu-21`，并且 `%JAVA_HOME%\bin` 在 PATH 中。重启命令行后再启动。

### Q: 导入文件时 Language 怎么选？
A: PE32+ ARM64 应该能自动检测。如果没有，手动选：`AARCH64` → `little endian` → `default` → `PE`。

### Q: 分析后 Strings 窗口是空的？
A: 确保分析时勾选了 "ASCII Strings" 和 "Unicode Strings" 分析器。可以重新分析（`Analysis` → `Auto Analyze...`）。

### Q: 怎么看函数的调用图？
- `Window` → `Function Graph`（函数流程图）
- `Window` → `Call Tree`（调用树）
- 右键函数 → `References` → `Find references to/from`

### Q: 怎么对比两个二进制？
A: Ghidra 有 "Version Tracking" 工具（`Tools` → `Version Tracking`），但手动对比两个 CodeBrowser 窗口更简单。

---

## 九、下一步

完成 Ghidra 分析后，我们将能够：
1. 构造正确格式的 devinfo（如果是格式问题）
2. 理解 "user key" 签名机制（如果有签名）
3. 决定是用 release abl + 正确 devinfo 解锁，还是必须用 UserDebug abl
4. 制作 v1.0.1 版本的完整解锁方案

**分析优先级**：先做优先级 1（"State: Unlocked" 引用），这会直接指向解锁判定函数，然后顺着调用链往下挖。
