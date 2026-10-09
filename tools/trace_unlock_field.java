// Ghidra Headless 脚本：追踪 Unlock 字段消费路径
// 目标：确认 Unlock=Yes 是否等于跳过 PAS 认证

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class trace_unlock_field extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("=== Unlock 字段消费路径追踪开始 ===");
        
        // 1. 找到 AuthAndReset 的实际实现
        println("\n=== 1. 查找 AuthAndReset 实现 ===");
        
        // type2 ops 表在 0x11068，+0x18 是 AuthAndReset 指针
        // 先读取 ops 表内容
        Address opsTable = currentProgram.getAddressFactory().getAddress("00011068");
        println("type2 ops 表 @ " + opsTable);
        
        for (int i = 0; i < 4; i++) {
            Address ptrAddr = opsTable.add(i * 8);
            try {
                long val = getLong(ptrAddr);
                println("  +0x" + (i*8) + " = 0x" + Long.toHexString(val));
                if (val != 0 && val < 0x20000) {
                    // 可能是函数指针
                    Address funcAddr = currentProgram.getAddressFactory().getAddress(
                        String.format("%08x", val));
                    Function func = getFunctionAt(funcAddr);
                    if (func != null) {
                        println("    → 函数: " + func.getName() + " (size=" + func.getBody().getNumAddresses() + ")");
                    } else {
                        // 尝试创建函数
                        func = createFunction(funcAddr, "AuthAndReset_type2");
                        if (func != null) {
                            println("    → 创建函数: " + func.getName());
                        }
                    }
                }
            } catch (Exception e) {
                println("  +0x" + (i*8) + " 读取失败: " + e.getMessage());
            }
        }
        
        // 2. 搜索 PAS authenticate 相关字符串的引用者
        println("\n=== 2. PAS 认证相关字符串引用者 ===");
        
        String[] pasStrings = {
            "PAS authenticate",
            "Failed to PAS authenticate",
            "AuthAndReset",
            "AuthenticationStatus",
            "pil-%s Failed to PAS"
        };
        
        Map<String, Address> stringAddrs = new HashMap<>();
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
                        for (String kw : pasStrings) {
                            if (s.contains(kw) && !stringAddrs.containsKey(kw)) {
                                stringAddrs.put(kw, addr);
                                println("  '" + kw + "' @ " + addr);
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        // 找到引用者
        for (Map.Entry<String, Address> entry : stringAddrs.entrySet()) {
            String kw = entry.getKey();
            Address strAddr = entry.getValue();
            println("\n  --- '" + kw + "' 的引用者 ---");
            Reference[] refs = getReferencesTo(strAddr);
            for (Reference ref : refs) {
                Address fromAddr = ref.getFromAddress();
                Function func = getFunctionContaining(fromAddr);
                if (func != null) {
                    println("    " + func.getName() + " @ " + func.getEntryPoint() + 
                        " (调用点 @ " + fromAddr + ", size=" + func.getBody().getNumAddresses() + ")");
                }
            }
        }
        
        // 3. 分析 0x2200-0x2D00 范围内的函数（auth 实现可能在这里）
        println("\n=== 3. 0x2200-0x2D00 范围内的函数（auth 实现候选） ===");
        
        Address rangeStart = currentProgram.getAddressFactory().getAddress("00002200");
        Address rangeEnd = currentProgram.getAddressFactory().getAddress("00002d00");
        
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(rangeStart, true);
        List<Function> authFuncs = new ArrayList<>();
        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (func.getEntryPoint().compareTo(rangeEnd) > 0) break;
            authFuncs.add(func);
            println("  " + func.getName() + " @ " + func.getEntryPoint() + 
                " (size=" + func.getBody().getNumAddresses() + ")");
        }
        
        // 4. 反编译 auth 候选函数，搜索对配置结构体的访问
        println("\n=== 4. 反编译 auth 候选函数，搜索 +0x330/+0x331 访问 ===");
        
        for (Function func : authFuncs) {
            if (func.getBody().getNumAddresses() < 20) continue; // 跳过太小的函数
            
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                
                // 搜索 0x330, 0x331, 0x330, 331 等模式
                boolean hasUnlockAccess = false;
                String[] patterns = {"0x330", "0x331", "816", "817", "+0x330", "+0x331"};
                for (String pat : patterns) {
                    if (code.contains(pat)) {
                        hasUnlockAccess = true;
                        break;
                    }
                }
                
                if (hasUnlockAccess) {
                    println("\n  ★ " + func.getName() + " 可能访问 Unlock 字段!");
                    // 打印相关行
                    String[] lines = code.split("\n");
                    for (int i = 0; i < lines.length; i++) {
                        for (String pat : patterns) {
                            if (lines[i].contains(pat)) {
                                println("    行 " + i + ": " + lines[i].trim());
                                break;
                            }
                        }
                    }
                }
            }
            decompiler.dispose();
        }
        
        // 5. 反编译 FUN_000015a0，看配置结构体如何传递给 auth
        println("\n=== 5. FUN_000015a0 中配置结构体的传递 ===");
        
        Address loadFuncAddr = currentProgram.getAddressFactory().getAddress("000015a0");
        Function loadFunc = getFunctionAt(loadFuncAddr);
        if (loadFunc != null) {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(loadFunc, 30, monitor);
            
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                
                // 搜索 AuthAndReset 调用和结构体传递
                println("  搜索 AuthAndReset 调用和结构体传递:");
                for (int i = 0; i < lines.length; i++) {
                    String line = lines[i].trim();
                    if (line.contains("AuthAndReset") || 
                        line.contains("0x18") ||
                        line.contains("auth") ||
                        line.contains("PAS") ||
                        (line.contains("param") && line.contains("+0x3"))) {
                        println("    行 " + i + ": " + line);
                    }
                }
                
                // 打印函数签名和前 50 行
                println("\n  函数前 50 行:");
                int maxLines = Math.min(lines.length, 50);
                for (int i = 0; i < maxLines; i++) {
                    println("    " + lines[i]);
                }
            }
            decompiler.dispose();
        }
        
        // 6. 搜索 memcpy / 结构体整体拷贝
        println("\n=== 6. 搜索 memcpy / 结构体整体拷贝 ===");
        
        // 搜索调用 memcpy 的函数
        for (Function func : authFuncs) {
            InstructionIterator instIter = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                String mnemonic = inst.getMnemonicString();
                if (mnemonic.equals("bl") || mnemonic.equals("blx")) {
                    Object[] opObjects = inst.getOpObjects(0);
                    if (opObjects.length > 0) {
                        String target = opObjects[0].toString();
                        if (target.contains("memcpy") || target.contains("CopyMem") || 
                            target.contains("copy") || target.contains("0x")) {
                            println("  " + func.getName() + " @ " + inst.getAddress() + 
                                " 调用 " + target);
                        }
                    }
                }
            }
        }
        
        // 7. 搜索 0x330/0x331 的直接内存访问（ldrb/strb 指令）
        println("\n=== 7. 搜索 +0x330/+0x331 的直接内存访问 ===");
        
        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            if (func.getEntryPoint().getOffset() > 0x3000) continue; // 只看前 0x3000
            
            InstructionIterator instIter = currentProgram.getListing().getInstructions(func.getBody(), true);
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                String mnemonic = inst.getMnemonicString();
                
                // ldrb/strb 带 0x330/0x331 偏移
                if (mnemonic.equals("ldrb") || mnemonic.equals("strb") ||
                    mnemonic.equals("ldrh") || mnemonic.equals("strh")) {
                    String rep = inst.toString();
                    if (rep.contains("#0x330") || rep.contains("#0x331") ||
                        rep.contains("#0x330,") || rep.contains("#0x331,")) {
                        println("  " + func.getName() + " @ " + inst.getAddress() + ": " + rep);
                    }
                }
            }
        }
        
        println("\n=== Unlock 字段追踪完成 ===");
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
