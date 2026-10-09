# scripts/ 目录说明

本目录包含小天才 Z10 (ND03) 逆向项目的所有 Python 脚本。

---

## 一、固件解密相关

| 脚本 | 功能 | 状态 |
|------|------|------|
| `xtc_decrypt.py` | 小天才手表 XML 解密工具（主工具），来源 MIO-KITCHEN 的 xtc_recovery_helper.py | ✅ 可用 |
| `decrypt_correct.py` | 基于源码修正的 XTC XML 解密算法 | ✅ 可用 |
| `decrypt_v101.py` | 解密 v1.0.1 固件 XML 文件 | ✅ 可用 |
| `test_decrypt.py` | 暴力测试 XTC XML 解密算法 | 🔧 测试用 |
| `test_decrypt2.py` | 深入分析：搜索明文 XML，测试更多 XOR 变体 | 🔧 测试用 |
| `known_plaintext.py` | 已知明文攻击：从 `<?xml` 推导 key 字节 | 🔧 分析用 |

---

## 二、PyInstaller 逆向相关（分析 MIO-KITCHEN tool.exe）

| 脚本 | 功能 | 状态 |
|------|------|------|
| `extract_pyinstaller.py` | PyInstaller 解包器，从 tool.exe 提取 pyc 文件 | ✅ 可用 |
| `extract_pyz.py` | 解包 PYZ.pyz 归档，查找 xtc 相关模块 | ✅ 可用 |
| `extract_pyz2.py` | 解包 PYZ.pyz，列出 TOC 格式 | ✅ 可用 |
| `extract_key.py` | 提取完整 key_table，重建解密算法 | ✅ 可用 |
| `disasm_xtc.py` | 反汇编 xtc_recovery_helper 和 ofp_qc_decrypt | 🔧 分析用 |
| `disasm312.py` | 使用 opcode 模块精确反汇编 Python 3.12 字节码 | 🔧 分析用 |
| `analyze_xtc.py` | 手动分析 xtc_recovery_helper 字节码 | 🔧 分析用 |
| `search_tool.py` | 在 tool.exe 中搜索特定模式 | 🔧 分析用 |

---

## 三、switch.db 数据库分析相关

| 脚本 | 功能 | 状态 |
|------|------|------|
| `analyze_db.py` | 分析 switch.db 数据库，列出所有表和视图 | ✅ 可用 |
| `dump_db.py` | dump switch.db 所有表内容为 JSON | ✅ 可用 |
| `dump_extra.py` | dump module_switch 表中 extra 字段非空的行 | ✅ 可用 |
| `generate_analysis.py` | 生成 switch.db 模块功能分析 Excel 报告 | ✅ 可用 |

---

## 四、Bootloader 解锁相关（2026-10-09 新增）

| 脚本 | 功能 | 状态 |
|------|------|------|
| `frp_tool.py` | FRP 分区分析与授权位修改工具（analyze/set/dump） | ✅ 可用 |
| `make_misc_bcb.py` | misc 分区 BCB 生成工具（控制启动模式：boot-fastboot/boot-recovery/ffbm-02） | ✅ 可用 |

### frp_tool.py 用法
```bash
# 分析 FRP 分区内容，寻找 IsAllowUnlock 候选偏移
python frp_tool.py analyze <frp.img>

# 设置指定偏移的值（用于打开授权位）
python frp_tool.py set <input.img> <output.img> <offset> <value>
# 示例：python frp_tool.py set frp_backup.img frp_allow1.img 0x08 1

# 十六进制 dump
python frp_tool.py dump <frp.img> [offset] [length]
```

### make_misc_bcb.py 用法
```bash
# 生成进入 fastboot 的 misc 镜像（基于备份修改，避免短写粘连）
python make_misc_bcb.py boot-fastboot <output.img> --from <backup.img>

# 生成正常启动的 misc
python make_misc_bcb.py boot-normal <output.img> --from <backup.img>

# 分析现有 misc 分区
python make_misc_bcb.py analyze <misc.img>
```

---

## 五、使用说明

### 固件解密
```bash
python xtc_decrypt.py <加密文件或目录> [输出目录]
```

### 数据库分析
```bash
python analyze_db.py
python dump_db.py
```

### PyInstaller 逆向
```bash
python extract_pyinstaller.py
python extract_pyz.py
```

---

## 六、注意事项

1. 部分脚本包含硬编码路径（如 `D:\gc\MIO-KITCHEN-4.1.8-win\tool.exe`），使用前需修改为实际路径
2. `generate_analysis.py` 需要安装 `openpyxl` 库
3. 测试用脚本（test_*）可能包含实验性代码，不保证可用性
4. 解密算法核心是 256 字节固定查找表（key_table）+ XOR 运算

---

## 七、相关文档

- 固件解密算法说明：`../reports/小天才XML解密算法说明.md`
- 项目状态：`../项目状态快照.md`
