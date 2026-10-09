// Ghidra Headless 脚本：深入分析 BDS 菜单相关函数
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_bds_menu extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== BDS 菜单深入分析开始 ===");
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        // 1. 完整反编译 FUN_0000fba0 (DefaultBDSBootApp)
        println("\n=== FUN_0000fba0 (DefaultBDSBootApp) 完整反编译 ===");
        Function f1 = getFunctionAt(toAddr("0000fba0"));
        if (f1 != null) {
            DecompileResults results = decompiler.decompileFunction(f1, 60, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                println(code);
            } else {
                println("反编译失败: " + results.getErrorMessage());
            }
        } else {
            println("函数不存在");
        }
        
        // 2. 完整反编译 FUN_00008a80 (最大函数)
        println("\n=== FUN_00008a80 (最大函数, size=4904) 完整反编译 ===");
        Function f2 = getFunctionAt(toAddr("00008a80"));
        if (f2 != null) {
            DecompileResults results = decompiler.decompileFunction(f2, 60, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                println(code);
            } else {
                println("反编译失败: " + results.getErrorMessage());
            }
        } else {
            println("函数不存在");
        }
        
        // 3. 反编译 FUN_0000fa48 (UEFI NV VOLATILE 检查)
        println("\n=== FUN_0000fa48 (UEFI NV VOLATILE 检查) 完整反编译 ===");
        Function f3 = getFunctionAt(toAddr("0000fa48"));
        if (f3 != null) {
            DecompileResults results = decompiler.decompileFunction(f3, 60, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                println(code);
            }
        }
        
        // 4. 搜索按键/菜单/超时相关字符串
        println("\n=== 搜索按键/菜单/超时相关字符串 ===");
        Memory mem = currentProgram.getMemory();
        String[] keywords = {"key", "Key", "button", "Button", "press", "Press", 
                             "timeout", "Timeout", "timer", "Timer", "wait", "Wait",
                             "menu", "Menu", "select", "Select", "enter", "Enter",
                             "boot", "Boot", "reboot", "Reboot", "recovery", "Recovery",
                             "fastboot", "Fastboot", "volume", "Volume", "power", "Power"};
        
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
                                    print("  \"" + s.substring(0, Math.min(s.length(), 50)) + "\" @ " + addr);
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
        
        // 5. 搜索 GetVariable/SetVariable 调用（UEFI 变量操作）
        println("\n=== 搜索 UEFI 变量操作（GetVariable/SetVariable）===");
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcIter = fm.getFunctions(true);
        int varFuncCount = 0;
        while (funcIter.hasNext()) {
            Function f = funcIter.next();
            String name = f.getName().toLowerCase();
            if (name.contains("variable") || name.contains("getvar") || name.contains("setvar")) {
                println("  " + f.getName() + " @ " + f.getEntryPoint() + " (size=" + f.getBody().getNumAddresses() + ")");
                varFuncCount++;
                if (varFuncCount > 20) break;
            }
        }
        if (varFuncCount == 0) {
            println("  未找到明显的变量操作函数（可能通过函数指针调用）");
        }
        
        decompiler.dispose();
        println("\n=== BDS 菜单深入分析完成 ===");
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
