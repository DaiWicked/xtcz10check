// Ghidra Headless 脚本：分析 PILDxe 的关键函数
// 目标：找到 RETAIL 白名单检查、PAS 认证、elf_fv 处理函数

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class analyze_pildxe extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== PILDxe 分析开始 ===");
        println("程序: " + currentProgram.getName());
        
        // 1. 搜索关键字符串
        println("\n=== 1. 搜索关键字符串 ===");
        
        String[] keywords = {
            "not supported in retail",
            "PAS authenticate",
            "process FV image",
            "Failed to validate metadata",
            "AuthAndReset",
            "ValidateMetaData",
            "AuthenticationStatus",
            "EfiHash2Protocol",
            "Mount partition",
            "elf_fv",
            "imagefv",
            "SubsysID",
            "PartiLabel",
            "PartiGuid",
            "retail list",
            "auto list"
        };
        
        Map<String, Address> stringAddresses = new HashMap<>();
        
        Memory mem = currentProgram.getMemory();
        AddressIterator addrIter = mem.getAddresses(true);
        
        // 遍历所有内存块搜索字符串
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            
            Address start = block.getStart();
            long size = block.getSize();
            
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    // 尝试读取字符串
                    String s = readNullTerminatedString(addr, 200);
                    if (s != null && s.length() >= 6) {
                        for (String kw : keywords) {
                            if (s.toLowerCase().contains(kw.toLowerCase())) {
                                if (!stringAddresses.containsKey(kw) || 
                                    stringAddresses.get(kw).getOffset() > addr.getOffset()) {
                                    stringAddresses.put(kw, addr);
                                }
                                println("  找到 '" + kw + "' @ " + addr + ": " + 
                                    (s.length() > 80 ? s.substring(0, 80) + "..." : s));
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
                    // 忽略读取错误
                }
            }
        }
        
        // 2. 找到字符串的引用者（XREF）
        println("\n=== 2. 查找字符串的引用者（XREF）===");
        
        for (Map.Entry<String, Address> entry : stringAddresses.entrySet()) {
            String kw = entry.getKey();
            Address strAddr = entry.getValue();
            
            println("\n--- '" + kw + "' @ " + strAddr + " ---");
            
            // 获取引用
            Reference[] refs = getReferencesTo(strAddr);
            if (refs.length == 0) {
                println("  无引用");
                continue;
            }
            
            for (Reference ref : refs) {
                Address fromAddr = ref.getFromAddress();
                println("  引用 @ " + fromAddr);
                
                // 找到包含该地址的函数
                Function func = getFunctionContaining(fromAddr);
                if (func != null) {
                    println("    函数: " + func.getName() + " @ " + func.getEntryPoint());
                    
                    // 打印函数的前 30 条指令
                    println("    函数指令（前30条）:");
                    InstructionIterator instIter = currentProgram.getListing().getInstructions(func.getBody(), true);
                    int count = 0;
                    while (instIter.hasNext() && count < 30) {
                        Instruction inst = instIter.next();
                        println("      " + inst.getAddress() + ": " + inst.toString());
                        count++;
                    }
                } else {
                    // 打印附近的指令
                    println("    附近指令:");
                    try {
                        for (int i = -5; i < 10; i++) {
                            Address instAddr = fromAddr.add(i * 4);
                            Instruction inst = getInstructionAt(instAddr);
                            if (inst != null) {
                                println("      " + instAddr + ": " + inst.toString());
                            }
                        }
                    } catch (Exception e) {}
                }
            }
        }
        
        // 3. 列出所有函数
        println("\n=== 3. 所有函数列表 ===");
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0;
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            funcCount++;
            if (funcCount <= 50) {  // 只打印前 50 个
                println("  " + func.getEntryPoint() + ": " + func.getName() + 
                    " (size=" + func.getBody().getNumAddresses() + ")");
            }
        }
        println("  ... 共 " + funcCount + " 个函数");
        
        println("\n=== PILDxe 分析完成 ===");
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
