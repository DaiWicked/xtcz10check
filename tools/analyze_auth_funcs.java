// Ghidra Headless 脚本：深入分析 AuthAndReset 和 ValidateMetaData
// 目标：确认 Unlock 字段是否被读取，以及配置结构体如何传递给 TZ/PAS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_auth_funcs extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== AuthAndReset / ValidateMetaData 深入分析 ===");
        
        // 1. 反编译 AuthAndReset (FUN_00001e70)
        println("\n=== 1. AuthAndReset = FUN_00001e70 (size=224) ===");
        decompileAndAnalyze("00001e70", "AuthAndReset");
        
        // 2. 反编译 ValidateMetaData (FUN_000026a4)
        println("\n=== 2. ValidateMetaData = FUN_000026a4 (size=452) ===");
        decompileAndAnalyze("000026a4", "ValidateMetaData");
        
        // 3. 反编译 FUN_00002a90 (PAS authenticate 打印)
        println("\n=== 3. FUN_00002a90 (PAS authenticate 字符串引用者, size=200) ===");
        decompileAndAnalyze("00002a90", "PAS_authenticate_printer");
        
        // 4. 反编译 FUN_000024ac (可能是 PAS 主流程)
        println("\n=== 4. FUN_000024ac (size=504) ===");
        decompileAndAnalyze("000024ac", "candidate_PAS_main");
        
        // 5. 反编译 FUN_00002868 (可能是 PAS 主流程)
        println("\n=== 5. FUN_00002868 (size=552) ===");
        decompileAndAnalyze("00002868", "candidate_PAS_main2");
        
        // 6. 反编译 FUN_00002b58 (可能是 PAS 主流程)
        println("\n=== 6. FUN_00002b58 (size=596) ===");
        decompileAndAnalyze("00002b58", "candidate_PAS_main3");
        
        // 7. 搜索 SCM/SysCall/TZ 相关字符串
        println("\n=== 7. 搜索 TZ/SCM/SysCall 相关字符串 ===");
        String[] tzStrings = {"SCM", "SysCall", "TZ", "tz_", "qsee", "QSEE", "smc", "SMC", 
                              "0x2000604", "0x80000000", "scm_call", "syscall"};
        
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    String s = readNullTerminatedString(addr, 200);
                    if (s != null) {
                        for (String kw : tzStrings) {
                            if (s.contains(kw)) {
                                println("  '" + s + "' @ " + addr);
                                // 找引用者
                                Reference[] refs = getReferencesTo(addr);
                                for (Reference ref : refs) {
                                    Function func = getFunctionContaining(ref.getFromAddress());
                                    if (func != null) {
                                        println("    → " + func.getName() + " @ " + func.getEntryPoint());
                                    }
                                }
                                break;
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        // 8. 搜索 0x330/0x331 在所有函数中的访问（更广泛的搜索）
        println("\n=== 8. 搜索所有函数中对 0x330/0x331 偏移的访问 ===");
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            if (func.getEntryPoint().getOffset() > 0x4000) continue;
            
            InstructionIterator instIter = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                String rep = inst.toString();
                // 搜索各种形式的 0x330/0x331 访问
                if (rep.contains("#0x330") || rep.contains("#0x331") ||
                    rep.contains("#0x330,") || rep.contains("#0x331,") ||
                    rep.contains("0x330]") || rep.contains("0x331]")) {
                    println("  " + func.getName() + " @ " + inst.getAddress() + ": " + rep);
                }
            }
        }
        
        println("\n=== 分析完成 ===");
    }
    
    private void decompileAndAnalyze(String addrStr, String name) {
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            Function func = getFunctionAt(addr);
            if (func == null) {
                func = createFunction(addr, name);
            }
            if (func == null) {
                println("  无法创建函数 @ " + addrStr);
                return;
            }
            
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                
                println("  函数签名: " + lines[0].trim());
                
                // 搜索关键模式
                boolean hasUnlock = false;
                boolean hasTZ = false;
                boolean hasSCM = false;
                boolean hasMemcpy = false;
                boolean hasStructPass = false;
                
                for (String line : lines) {
                    String trimmed = line.trim();
                    if (trimmed.contains("0x330") || trimmed.contains("0x331")) hasUnlock = true;
                    if (trimmed.contains("TZ") || trimmed.contains("tz_")) hasTZ = true;
                    if (trimmed.contains("SCM") || trimmed.contains("scm")) hasSCM = true;
                    if (trimmed.contains("memcpy") || trimmed.contains("CopyMem")) hasMemcpy = true;
                    // 检查是否把整个结构体传给其他函数
                    if (trimmed.contains("param_1") && trimmed.contains("bl ")) hasStructPass = true;
                }
                
                println("  访问 0x330/0x331: " + (hasUnlock ? "★ 是" : "否"));
                println("  包含 TZ: " + (hasTZ ? "是" : "否"));
                println("  包含 SCM: " + (hasSCM ? "是" : "否"));
                println("  包含 memcpy: " + (hasMemcpy ? "是" : "否"));
                println("  传递结构体: " + (hasStructPass ? "是" : "否"));
                
                // 打印完整反编译（前 80 行）
                println("  --- 反编译 ---");
                int maxLines = Math.min(lines.length, 80);
                for (int i = 0; i < maxLines; i++) {
                    println("  " + lines[i]);
                }
                if (lines.length > 80) {
                    println("  ... (共 " + lines.length + " 行，已截断)");
                }
            } else {
                println("  反编译失败: " + results.getErrorMessage());
            }
            decompiler.dispose();
        } catch (Exception e) {
            println("  异常: " + e.getMessage());
        }
    }
    
    private String readNullTerminatedString(Address addr, int maxLen) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxLen; i++) {
                byte b = getByte(addr.add(i));
                if (b == 0) break;
                if (b < 32 || b > 126) {
                    if (sb.length() < 4) return null;
                    break;
                }
                sb.append((char) b);
            }
            return sb.length() >= 4 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
