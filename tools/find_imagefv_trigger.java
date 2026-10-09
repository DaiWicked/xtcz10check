// Ghidra Headless 脚本：定位 imagefv 装载触发者
// 目标：找到谁调用了 FUN_195C（SubsysID=20 装载路径）、FUN_18F4（按名加载 API）、FUN_1560（PIL 协议入口）

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class find_imagefv_trigger extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== imagefv 装载触发者追踪开始 ===");
        
        // 目标函数列表
        long[] targetAddrs = {
            0x195c,  // FUN_195C - SubsysID=20 装载路径
            0x18f4,  // FUN_18F4 - 按名加载 API LoadImage(name)
            0x1560,  // FUN_1560 - PIL 协议入口包装
            0x15a0,  // FUN_15A0 - 单镜像加载主函数
            0x13f4   // FUN_13F4 - 初始化函数
        };
        
        String[] targetNames = {
            "FUN_195C (SubsysID=20=ImageFv 装载路径)",
            "FUN_18F4 (按名加载 API)",
            "FUN_1560 (PIL 协议入口)",
            "FUN_15A0 (加载主函数)",
            "FUN_13F4 (初始化函数)"
        };
        
        for (int i = 0; i < targetAddrs.length; i++) {
            long addr = targetAddrs[i];
            String name = targetNames[i];
            
            println("\n========================================");
            println("目标: " + name + " @ 0x" + Long.toHexString(addr));
            println("========================================");
            
            Address funcAddr = currentProgram.getAddressFactory().getAddress(
                String.format("%08x", addr));
            Function func = getFunctionAt(funcAddr);
            
            if (func == null) {
                // 尝试创建函数
                func = createFunction(funcAddr, "FUN_" + Long.toHexString(addr));
                if (func == null) {
                    println("  无法创建函数 @ 0x" + Long.toHexString(addr));
                    continue;
                }
            }
            
            println("  函数名: " + func.getName());
            println("  大小: " + func.getBody().getNumAddresses() + " 字节");
            
            // 1. 找调用者（References to this function）
            println("\n  --- 调用者 (References to this function) ---");
            Reference[] refs = getReferencesTo(funcAddr);
            List<Function> callers = new ArrayList<>();
            
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    Address fromAddr = ref.getFromAddress();
                    Function caller = getFunctionContaining(fromAddr);
                    if (caller != null && !callers.contains(caller)) {
                        callers.add(caller);
                    }
                }
            }
            
            if (callers.isEmpty()) {
                println("  无直接调用者");
            } else {
                for (Function caller : callers) {
                    println("  → " + caller.getName() + " @ " + caller.getEntryPoint() + 
                        " (size=" + caller.getBody().getNumAddresses() + ")");
                    
                    // 找调用点
                    InstructionIterator instIter = currentProgram.getListing().getInstructions(caller.getBody(), true);
                    while (instIter.hasNext()) {
                        Instruction inst = instIter.next();
                        if (inst.getMnemonicString().equals("bl")) {
                            Object[] opObjects = inst.getOpObjects(0);
                            if (opObjects.length > 0) {
                                String target = opObjects[0].toString();
                                if (target.contains(Long.toHexString(addr)) || 
                                    target.contains(func.getName())) {
                                    println("    调用点 @ " + inst.getAddress() + ": " + inst);
                                }
                            }
                        }
                    }
                }
            }
            
            // 2. 反编译函数，看它做了什么
            println("\n  --- 函数反编译（前 60 行） ---");
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                int maxLines = Math.min(lines.length, 60);
                for (int j = 0; j < maxLines; j++) {
                    println("  " + lines[j]);
                }
                if (lines.length > 60) {
                    println("  ... (共 " + lines.length + " 行，已截断)");
                }
                
                // 搜索关键字符串
                println("\n  --- 关键字符串引用 ---");
                for (int j = 0; j < lines.length; j++) {
                    String line = lines[j];
                    if (line.contains("ImageFv") || line.contains("imagefv") ||
                        line.contains("SubsysID") || line.contains("subsys") ||
                        line.contains("0x14") || line.contains("0x20") ||
                        line.contains("pil-") || line.contains("PAS")) {
                        println("    行 " + j + ": " + line.trim());
                    }
                }
            } else {
                println("  反编译失败: " + results.getErrorMessage());
            }
            decompiler.dispose();
        }
        
        // 3. 搜索 "ImageFv" 字符串的引用者
        println("\n========================================");
        println("搜索 \"ImageFv\" 字符串的引用者");
        println("========================================");
        
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    String s = readNullTerminatedString(addr, 100);
                    if (s != null && (s.equals("ImageFv") || s.contains("ImageFv"))) {
                        println("\n  字符串 \"" + s + "\" @ " + addr);
                        Reference[] strRefs = getReferencesTo(addr);
                        for (Reference ref : strRefs) {
                            Function caller = getFunctionContaining(ref.getFromAddress());
                            if (caller != null) {
                                println("    → 引用者: " + caller.getName() + " @ " + caller.getEntryPoint() +
                                    " (调用点 @ " + ref.getFromAddress() + ")");
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        // 4. 搜索 "pil-" 字符串（PIL 日志前缀）
        println("\n========================================");
        println("搜索 \"pil-\" 字符串的引用者（PIL 日志）");
        println("========================================");
        
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    String s = readNullTerminatedString(addr, 100);
                    if (s != null && s.startsWith("pil-")) {
                        println("\n  字符串 \"" + s + "\" @ " + addr);
                        Reference[] strRefs = getReferencesTo(addr);
                        for (Reference ref : strRefs) {
                            Function caller = getFunctionContaining(ref.getFromAddress());
                            if (caller != null) {
                                println("    → " + caller.getName() + " @ " + caller.getEntryPoint());
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        println("\n=== imagefv 装载触发者追踪完成 ===");
    }
    
    private String readNullTerminatedString(Address addr, int maxLen) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxLen; i++) {
                byte b = getByte(addr.add(i));
                if (b == 0) break;
                if (b < 32 || b > 126) {
                    if (sb.length() < 3) return null;
                    break;
                }
                sb.append((char) b);
            }
            return sb.length() >= 3 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
