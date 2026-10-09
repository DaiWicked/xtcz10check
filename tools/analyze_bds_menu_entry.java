// Ghidra Headless 脚本：分析 BDS 菜单真正入口和电源键驱动
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_bds_menu_entry extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== BDS 菜单真正入口和电源键驱动分析开始 ===");
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        // 1. 完整反编译 FUN_000016a8 (FUN_0000f148 的另一个调用者)
        println("\n=== FUN_000016a8 完整反编译 ===");
        Function f1 = getFunctionAt(toAddr("000016a8"));
        if (f1 != null) {
            println("函数大小: " + f1.getBody().getNumAddresses());
            DecompileResults results = decompiler.decompileFunction(f1, 60, monitor);
            if (results.decompileCompleted()) {
                println(results.getDecompiledFunction().getC());
            }
        }
        
        // 2. 搜索 FUN_000016a8 的调用者
        println("\n=== FUN_000016a8 的调用者 ===");
        if (f1 != null) {
            Reference[] refs = getReferencesTo(f1.getEntryPoint());
            for (Reference ref : refs) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    println("  " + caller.getName() + " @ " + caller.getEntryPoint() + " (调用 @ " + ref.getFromAddress() + ")");
                }
            }
        }
        
        // 3. 搜索电源键/PMIC/GPIO/按键相关字符串
        println("\n=== 搜索电源键/PMIC/GPIO/按键相关字符串 ===");
        Memory mem = currentProgram.getMemory();
        String[] keywords = {"pwr", "Pwr", "PWR", "power", "Power", "powerkey", "PowerKey",
                             "pmic", "PMIC", "gpio", "GPIO", "key", "Key", "button", "Button",
                             "volume", "Volume", "home", "Home", "press", "Press", "longpress",
                             "debounce", "Debounce", "interrupt", "Interrupt", "wakeup", "Wakeup",
                             "pon", "Pon", "PON", "resin", "Resin", "kpdpwr", "Kpdpwr"};
        
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
                                break;
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        // 4. 搜索可能的 BDS 菜单函数（包含 menu/select/option 的函数名）
        println("\n=== 搜索可能的 BDS 菜单函数 ===");
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (funcIter.hasNext() && count < 50) {
            Function f = funcIter.next();
            String name = f.getName().toLowerCase();
            // Ghidra 自动命名的函数没有有意义的名字，所以搜索函数体中的字符串
            // 改为搜索引用了 BDS_Menu.cfg 相关字符串的函数
        }
        
        // 5. 搜索引用 "menu" 字符串的函数
        println("\n=== 引用 menu 相关字符串的函数 ===");
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    String s = readNullTerminatedString(addr, 200);
                    if (s != null && s.length() >= 5 && s.toLowerCase().contains("menu")) {
                        Reference[] refs = getReferencesTo(addr);
                        if (refs.length > 0) {
                            print("  \"" + s.substring(0, Math.min(s.length(), 60)) + "\" @ " + addr);
                            for (Reference ref : refs) {
                                Function caller = getFunctionContaining(ref.getFromAddress());
                                if (caller != null) {
                                    print(" → " + caller.getName() + " size=" + caller.getBody().getNumAddresses());
                                }
                            }
                            println("");
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        // 6. 搜索 SimpleTextInput 协议相关函数
        println("\n=== SimpleTextInput 协议相关函数 ===");
        funcIter = currentProgram.getFunctionManager().getFunctions(true);
        count = 0;
        while (funcIter.hasNext() && count < 30) {
            Function f = funcIter.next();
            // 搜索函数体中是否有 ConIn/TextInput 相关的调用
            // 由于函数名是自动生成的，我们搜索大小在 100-500 之间且可能是按键处理的函数
            long sz = f.getBody().getNumAddresses();
            if (sz >= 100 && sz <= 500) {
                // 检查函数是否引用了 DAT_000186d8（SimpleTextInput 协议指针）
                Reference[] refs = getReferencesTo(toAddr("000186d8"));
                for (Reference ref : refs) {
                    if (f.getBody().contains(ref.getFromAddress())) {
                        println("  " + f.getName() + " @ " + f.getEntryPoint() + " size=" + sz + " (引用 SimpleTextInput)");
                        count++;
                        break;
                    }
                }
            }
        }
        
        decompiler.dispose();
        println("\n=== BDS 菜单真正入口和电源键驱动分析完成 ===");
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
