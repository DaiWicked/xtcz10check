// Ghidra Headless 脚本：分析 Ebl 模块的 mountfv/start/loadfv 命令实现
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_ebl extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Ebl 模块分析开始 ===");
        
        // 1. 列出所有函数
        println("\n--- 所有函数（按大小排序，前30个）---");
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> allFuncs = new ArrayList<>();
        while (funcIter.hasNext()) {
            allFuncs.add(funcIter.next());
        }
        allFuncs.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
        
        for (int i = 0; i < Math.min(30, allFuncs.size()); i++) {
            Function f = allFuncs.get(i);
            println("  " + f.getName() + " @ " + f.getEntryPoint() + 
                " (size=" + f.getBody().getNumAddresses() + ")");
        }
        println("  共 " + allFuncs.size() + " 个函数");
        
        // 2. 搜索关键字符串的引用者
        println("\n--- 关键字符串引用者 ---");
        Memory mem = currentProgram.getMemory();
        String[] keywords = {"mountfv", "MountFv", "loadfv", "start fv", "start fs", 
                             "fv1:", "fv2:", "fv3:", "fs1:", "fastboot", "Shell",
                             "BDS", "menu", "Menu", "toolsfv", "catefv"};
        
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    String s = readNullTerminatedString(addr, 200);
                    if (s != null && s.length() >= 4) {
                        for (String kw : keywords) {
                            if (s.toLowerCase().contains(kw.toLowerCase())) {
                                println("  字符串 \"" + s + "\" @ " + addr);
                                Reference[] refs = getReferencesTo(addr);
                                for (Reference ref : refs) {
                                    Function caller = getFunctionContaining(ref.getFromAddress());
                                    if (caller != null) {
                                        println("    → " + caller.getName() + " @ " + caller.getEntryPoint());
                                    }
                                }
                                break;
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        // 3. 反编译最大的 10 个函数（前50行）
        println("\n--- 最大的 10 个函数反编译（前50行）---");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        for (int i = 0; i < Math.min(10, allFuncs.size()); i++) {
            Function f = allFuncs.get(i);
            println("\n  === " + f.getName() + " @ " + f.getEntryPoint() + 
                " (size=" + f.getBody().getNumAddresses() + ") ===");
            
            DecompileResults results = decompiler.decompileFunction(f, 30, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                for (int j = 0; j < Math.min(lines.length, 50); j++) {
                    println("  " + lines[j]);
                }
                if (lines.length > 50) {
                    println("  ... (共 " + lines.length + " 行)");
                }
            }
        }
        decompiler.dispose();
        
        println("\n=== Ebl 模块分析完成 ===");
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
