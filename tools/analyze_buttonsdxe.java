// Ghidra Headless 脚本：分析 ButtonsDxe 按键映射
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_buttonsdxe extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== ButtonsDxe 按键映射分析开始 ===");
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        // 1. 列出所有函数
        println("\n=== 所有函数列表 ===");
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        List<Function> funcs = new ArrayList<>();
        while (funcIter.hasNext()) {
            Function f = funcIter.next();
            funcs.add(f);
        }
        // 按大小排序
        funcs.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));
        for (Function f : funcs) {
            println("  " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
        }
        
        // 2. 搜索 InitializeKeyMap 相关函数
        println("\n=== 搜索 InitializeKeyMap 相关 ===");
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    String s = readNullTerminatedString(addr, 200);
                    if (s != null && s.length() >= 5) {
                        if (s.contains("KeyMap") || s.contains("key") || s.contains("Key") ||
                            s.contains("Power") || s.contains("VOL") || s.contains("button") ||
                            s.contains("Button") || s.contains("Scan") || s.contains("scan")) {
                            Reference[] refs = getReferencesTo(addr);
                            if (refs.length > 0) {
                                print("  \"" + s.substring(0, Math.min(s.length(), 60)) + "\" @ " + addr);
                                for (Reference ref : refs) {
                                    Function caller = getFunctionContaining(ref.getFromAddress());
                                    if (caller != null) {
                                        print(" → " + caller.getName());
                                    }
                                }
                                println("");
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        // 3. 反编译最大的几个函数（可能包含 key map 初始化）
        println("\n=== 反编译前5大函数 ===");
        for (int i = 0; i < Math.min(5, funcs.size()); i++) {
            Function f = funcs.get(i);
            println("\n--- " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses() + " ---");
            DecompileResults results = decompiler.decompileFunction(f, 60, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                // 只打印前200行
                String[] lines = code.split("\n");
                for (int j = 0; j < Math.min(150, lines.length); j++) {
                    println(lines[j]);
                }
                if (lines.length > 150) {
                    println("... (省略 " + (lines.length - 150) + " 行)");
                }
            }
        }
        
        // 4. 搜索按键扫描码常量（0x01=UP, 0x02=DOWN, 0x03=RIGHT, 0x04=LEFT, 0x0B=F1, 0x0C=F2）
        println("\n=== 搜索按键扫描码相关数据 ===");
        // 搜索包含 0x01, 0x02, 0x03, 0x04 连续序列的数据区
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size - 16; offset++) {
                Address addr = start.add(offset);
                try {
                    // 搜索可能的 key map 表：GPIO号 + 扫描码 的组合
                    int b0 = getByte(addr) & 0xFF;
                    int b1 = getByte(addr.add(1)) & 0xFF;
                    int b2 = getByte(addr.add(2)) & 0xFF;
                    int b3 = getByte(addr.add(3)) & 0xFF;
                    // 扫描码 1-4 或 0x0B-0x0C
                    if ((b0 >= 1 && b0 <= 4) || b0 == 0x0B || b0 == 0x0C) {
                        if (b1 == 0 && b2 == 0 && b3 == 0) {
                            // 可能是扫描码
                            Reference[] refs = getReferencesTo(addr);
                            if (refs.length > 0) {
                                println("  可能的扫描码 @ " + addr + ": " + b0 + " (refs=" + refs.length + ")");
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        decompiler.dispose();
        println("\n=== ButtonsDxe 按键映射分析完成 ===");
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
