// Ghidra Headless 脚本：分析 QcomBds 模块的 BDS 菜单门控逻辑
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_qcombds extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== QcomBds 模块分析开始 ===");
        
        // 1. 列出所有函数（按大小排序，前20个）
        println("\n--- 所有函数（按大小排序，前20个）---");
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> allFuncs = new ArrayList<>();
        while (funcIter.hasNext()) {
            allFuncs.add(funcIter.next());
        }
        allFuncs.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
        
        for (int i = 0; i < Math.min(20, allFuncs.size()); i++) {
            Function f = allFuncs.get(i);
            println("  " + f.getName() + " @ " + f.getEntryPoint() + 
                " (size=" + f.getBody().getNumAddresses() + ")");
        }
        println("  共 " + allFuncs.size() + " 个函数");
        
        // 2. 搜索关键字符串的引用者
        println("\n--- 关键字符串引用者 ---");
        Memory mem = currentProgram.getMemory();
        String[] keywords = {"menu", "Menu", "BDS", "bds", "Display", "display", 
                             "enable", "Enable", "disable", "Disable",
                             "boot", "Boot", "key", "Key", "button", "Button",
                             "timeout", "Timeout", "prompt", "Prompt",
                             "SecureBoot", "DebugPolicy", "fastboot", "recovery"};
        
        Map<String, List<Function>> stringRefs = new LinkedHashMap<>();
        
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    String s = readNullTerminatedString(addr, 200);
                    if (s != null && s.length() >= 5) {
                        for (String kw : keywords) {
                            if (s.toLowerCase().contains(kw.toLowerCase())) {
                                Reference[] refs = getReferencesTo(addr);
                                if (refs.length > 0) {
                                    String key = s.substring(0, Math.min(s.length(), 60));
                                    if (!stringRefs.containsKey(key)) {
                                        stringRefs.put(key, new ArrayList<>());
                                    }
                                    for (Reference ref : refs) {
                                        Function caller = getFunctionContaining(ref.getFromAddress());
                                        if (caller != null && !stringRefs.get(key).contains(caller)) {
                                            stringRefs.get(key).add(caller);
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        for (Map.Entry<String, List<Function>> entry : stringRefs.entrySet()) {
            if (entry.getValue().size() > 0) {
                println("  字符串 \"" + entry.getKey() + "\"");
                for (Function f : entry.getValue()) {
                    println("    → " + f.getName() + " @ " + f.getEntryPoint());
                }
            }
        }
        
        // 3. 反编译最大的 8 个函数（前60行）
        println("\n--- 最大的 8 个函数反编译（前60行）---");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        for (int i = 0; i < Math.min(8, allFuncs.size()); i++) {
            Function f = allFuncs.get(i);
            println("\n  === " + f.getName() + " @ " + f.getEntryPoint() + 
                " (size=" + f.getBody().getNumAddresses() + ") ===");
            
            DecompileResults results = decompiler.decompileFunction(f, 30, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                for (int j = 0; j < Math.min(lines.length, 60); j++) {
                    println("  " + lines[j]);
                }
                if (lines.length > 60) {
                    println("  ... (共 " + lines.length + " 行)");
                }
            }
        }
        decompiler.dispose();
        
        println("\n=== QcomBds 模块分析完成 ===");
    }
    
    private String readNullTerminatedString(Address addr, int maxLen) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxLen; i++) {
                byte b = getByte(addr.add(i));
                if (b == 0) break;
                if (b < 32 || b > 126) {
                    if (sb.length() < 5) return null;
                    break;
                }
                sb.append((char) b);
            }
            return sb.length() >= 5 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
