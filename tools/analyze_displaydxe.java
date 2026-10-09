// Ghidra Headless 脚本：分析 DisplayDxe 是否调用 PIL 协议加载 imagefv
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_displaydxe extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== DisplayDxe 分析开始 ===");
        
        // 1. 列出所有函数
        println("\n--- 所有函数（前50个）---");
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0;
        List<Function> allFuncs = new ArrayList<>();
        while (funcIter.hasNext()) {
            Function f = funcIter.next();
            allFuncs.add(f);
            funcCount++;
            if (funcCount <= 50) {
                println("  " + f.getName() + " @ " + f.getEntryPoint() + 
                    " (size=" + f.getBody().getNumAddresses() + ")");
            }
        }
        println("  共 " + funcCount + " 个函数");
        
        // 2. 搜索关键字符串
        println("\n--- 关键字符串搜索 ---");
        Memory mem = currentProgram.getMemory();
        String[] keywords = {"ImageFv", "imagefv", "IMAGEFV", "pil", "PIL", 
                             "LoadImage", "StartImage", "MountFv", "splash", "Splash",
                             "ContinuousSplash", "partition", "Partition", "FvSimpleFileSystem"};
        
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
                                // 找引用者
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
        
        // 3. 找包含 "Splash" 或 "Display" 的函数
        println("\n--- 包含 Splash/Display 关键词的函数 ---");
        for (Function f : allFuncs) {
            String name = f.getName().toLowerCase();
            if (name.contains("splash") || name.contains("display") || 
                name.contains("image") || name.contains("load") || name.contains("fv")) {
                println("  " + f.getName() + " @ " + f.getEntryPoint());
            }
        }
        
        // 4. 反编译几个关键函数（最大的几个）
        println("\n--- 最大的 5 个函数反编译（前40行）---");
        allFuncs.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        for (int i = 0; i < Math.min(5, allFuncs.size()); i++) {
            Function f = allFuncs.get(i);
            println("\n  === " + f.getName() + " @ " + f.getEntryPoint() + 
                " (size=" + f.getBody().getNumAddresses() + ") ===");
            
            DecompileResults results = decompiler.decompileFunction(f, 30, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                for (int j = 0; j < Math.min(lines.length, 40); j++) {
                    println("  " + lines[j]);
                }
                if (lines.length > 40) {
                    println("  ... (共 " + lines.length + " 行)");
                }
            }
        }
        decompiler.dispose();
        
        println("\n=== DisplayDxe 分析完成 ===");
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
