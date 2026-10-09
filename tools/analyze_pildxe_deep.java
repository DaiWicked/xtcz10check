// Ghidra Headless 脚本：深入分析 PILDxe 关键函数
// 目标：找到 RETAIL 白名单检查、PAS 认证、elf_fv 处理的具体逻辑

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_pildxe_deep extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== PILDxe 深入分析开始 ===");
        
        // 1. 找到所有关键字符串的精确地址
        println("\n=== 1. 关键字符串精确地址 ===");
        
        Map<String, Address> keyStrings = new HashMap<>();
        String[] searchStrings = {
            "not supported in retail",
            "PAS authenticate",
            "process FV image",
            "Failed to validate metadata",
            "Mount partition return",
            "Failed to load ELF file",
            "AuthAndReset cannot be NULL",
            "ValidateMetaData cannot be NULL",
            "AuthenticationStatus",
            "EfiHash2Protocol",
            "elf_fv",
            "SubsysID",
            "PartiLabel",
            "PartiGuid",
            "FwName",
            "pil-%s %r is not supported",
            "Failed to initiate retail list",
            "Failed to initiate auto list"
        };
        
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    String s = readNullTerminatedString(addr, 200);
                    if (s != null && s.length() >= 6) {
                        for (String kw : searchStrings) {
                            if (s.equals(kw) || (s.contains(kw) && !keyStrings.containsKey(kw))) {
                                keyStrings.put(kw, addr);
                                println("  '" + kw + "' @ " + addr);
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        // 2. 找到每个字符串的引用者和所在函数
        println("\n=== 2. 字符串引用者分析 ===");
        
        for (Map.Entry<String, Address> entry : keyStrings.entrySet()) {
            String kw = entry.getKey();
            Address strAddr = entry.getValue();
            
            println("\n--- '" + kw + "' @ " + strAddr + " ---");
            
            Reference[] refs = getReferencesTo(strAddr);
            if (refs.length == 0) {
                println("  无引用（可能通过 adrp+add 间接引用）");
                // 搜索附近的 adrp 指令
                searchAdrpReferences(strAddr);
                continue;
            }
            
            for (Reference ref : refs) {
                Address fromAddr = ref.getFromAddress();
                println("  直接引用 @ " + fromAddr);
                
                Function func = getFunctionContaining(fromAddr);
                if (func != null) {
                    println("    函数: " + func.getName() + " @ " + func.getEntryPoint() + 
                        " (size=" + func.getBody().getNumAddresses() + ")");
                    
                    // 反编译这个函数
                    decompileFunction(func, kw);
                }
            }
        }
        
        // 3. 专门分析 FUN_000015a0（加载主函数）
        println("\n=== 3. FUN_000015a0 完整反编译 ===");
        Address funcAddr = currentProgram.getAddressFactory().getAddress("000015a0");
        Function mainFunc = getFunctionAt(funcAddr);
        if (mainFunc != null) {
            decompileFunction(mainFunc, "FUN_000015a0");
        } else {
            println("  函数不存在，尝试创建...");
            mainFunc = createFunction(funcAddr, "PIL_LoadImage");
            if (mainFunc != null) {
                decompileFunction(mainFunc, "PIL_LoadImage");
            }
        }
        
        // 4. 专门分析 FUN_000013f4（白名单初始化）
        println("\n=== 4. FUN_000013f4 完整反编译 ===");
        Address initAddr = currentProgram.getAddressFactory().getAddress("000013f4");
        Function initFunc = getFunctionAt(initAddr);
        if (initFunc != null) {
            decompileFunction(initFunc, "FUN_000013f4");
        }
        
        // 5. 列出所有调用 FUN_000015a0 的函数
        println("\n=== 5. 调用 FUN_000015a0 的函数 ===");
        if (mainFunc != null) {
            Reference[] callRefs = getReferencesTo(mainFunc.getEntryPoint());
            for (Reference ref : callRefs) {
                if (ref.getReferenceType().isCall()) {
                    Address callerAddr = ref.getFromAddress();
                    Function caller = getFunctionContaining(callerAddr);
                    if (caller != null) {
                        println("  " + caller.getName() + " @ " + caller.getEntryPoint() + 
                            " (调用点 @ " + callerAddr + ")");
                    } else {
                        println("  调用点 @ " + callerAddr + "（不在函数内）");
                    }
                }
            }
        }
        
        println("\n=== PILDxe 深入分析完成 ===");
    }
    
    private void searchAdrpReferences(Address strAddr) {
        // 搜索可能引用该字符串的 adrp 指令
        long targetPage = strAddr.getOffset() & ~0xFFFL;
        
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.getName().contains("text")) continue;
            
            Address start = block.getStart();
            long size = block.getSize();
            
            for (long offset = 0; offset < size; offset += 4) {
                try {
                    Address instAddr = start.add(offset);
                    int inst = getInt(instAddr);
                    
                    // ADRP 指令: 1  immlo  10000  immhi  Rd
                    if ((inst & 0x9F000000) == 0x90000000) {
                        int immlo = (inst >> 29) & 0x3;
                        int immhi = (inst >> 5) & 0x7FFFF;
                        long imm = ((immhi << 2) | immlo) << 12;
                        long page = (instAddr.getOffset() & ~0xFFFL) + (imm << 0);
                        // 符号扩展
                        if ((imm & 0x100000000L) != 0) imm |= ~0xFFFFFFFFL;
                        page = (instAddr.getOffset() & ~0xFFFL) + (imm << 12);
                        
                        if (page == targetPage) {
                            // 检查下一条指令是否是 add（加载字符串地址）
                            int nextInst = getInt(instAddr.add(4));
                            if ((nextInst & 0xFF800000) == 0x91000000) { // ADD immediate
                                println("    可能的 adrp+add 引用 @ " + instAddr);
                                
                                Function func = getFunctionContaining(instAddr);
                                if (func != null) {
                                    println("      函数: " + func.getName() + " @ " + func.getEntryPoint());
                                }
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
    }
    
    private void decompileFunction(Function func, String label) {
        try {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                println("  [" + label + "] 反编译结果:");
                // 只打印前 100 行
                String[] lines = code.split("\n");
                int maxLines = Math.min(lines.length, 100);
                for (int i = 0; i < maxLines; i++) {
                    println("    " + lines[i]);
                }
                if (lines.length > 100) {
                    println("    ... (共 " + lines.length + " 行，已截断)");
                }
            } else {
                println("  [" + label + "] 反编译失败: " + results.getErrorMessage());
            }
            
            decompiler.dispose();
        } catch (Exception e) {
            println("  [" + label + "] 反编译异常: " + e.getMessage());
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
