// Ghidra Headless 脚本：分析 BDS 菜单触发方式（按键/USB/UART/变量）
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_bds_trigger extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== BDS 菜单触发方式分析开始 ===");
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        // 1. 完整反编译 FUN_0000f148 (可能是 BDS 菜单入口)
        println("\n=== FUN_0000f148 (可能是 BDS 菜单入口) 完整反编译 ===");
        Function f1 = getFunctionAt(toAddr("0000f148"));
        if (f1 != null) {
            println("函数大小: " + f1.getBody().getNumAddresses());
            DecompileResults results = decompiler.decompileFunction(f1, 60, monitor);
            if (results.decompileCompleted()) {
                println(results.getDecompiledFunction().getC());
            }
        } else {
            println("函数不存在，搜索附近的函数...");
            FunctionIterator fIter = currentProgram.getFunctionManager().getFunctions(toAddr("0000f100"), true);
            while (fIter.hasNext()) {
                Function f = fIter.next();
                if (f.getEntryPoint().getOffset() > 0xf200) break;
                println("  附近函数: " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
            }
        }
        
        // 2. 完整反编译 FUN_000030e8 (按键读取)
        println("\n=== FUN_000030e8 (按键读取) 完整反编译 ===");
        Function f2 = getFunctionAt(toAddr("000030e8"));
        if (f2 != null) {
            println("函数大小: " + f2.getBody().getNumAddresses());
            DecompileResults results = decompiler.decompileFunction(f2, 60, monitor);
            if (results.decompileCompleted()) {
                println(results.getDecompiledFunction().getC());
            }
        } else {
            println("函数不存在");
        }
        
        // 3. 搜索 FUN_0000f148 的调用者
        println("\n=== FUN_0000f148 的调用者 ===");
        if (f1 != null) {
            Reference[] refs = getReferencesTo(f1.getEntryPoint());
            for (Reference ref : refs) {
                Function caller = getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    println("  " + caller.getName() + " @ " + caller.getEntryPoint() + " (调用 @ " + ref.getFromAddress() + ")");
                }
            }
        }
        
        // 4. 搜索 USB/UART/串口相关字符串
        println("\n=== 搜索 USB/UART/串口/控制台相关字符串 ===");
        Memory mem = currentProgram.getMemory();
        String[] keywords = {"usb", "USB", "uart", "UART", "serial", "Serial", "console", "Console",
                             "key", "Key", "input", "Input", "event", "Event", "gpio", "GPIO",
                             "pmic", "PMIC", "power", "Power", "button", "Button", "touch", "Touch",
                             "recovery", "Recovery", "fastboot", "Fastboot", "BootMode", "bootmode"};
        
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
        
        // 5. 搜索 UEFI 变量名（可能控制 BDS 菜单）
        println("\n=== 搜索 UEFI 变量名（可能控制 BDS 菜单）===");
        String[] varKeywords = {"BootMenu", "BootNext", "BootOrder", "BootCurrent", 
                                "MenuEnable", "BdsMenu", "UsbBoot", "SerialBoot",
                                "BootOption", "BootFrom", "BootDevice"};
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size; offset++) {
                Address addr = start.add(offset);
                try {
                    String s = readNullTerminatedString(addr, 200);
                    if (s != null && s.length() >= 5) {
                        for (String kw : varKeywords) {
                            if (s.toLowerCase().contains(kw.toLowerCase())) {
                                Reference[] refs = getReferencesTo(addr);
                                if (refs.length > 0) {
                                    print("  \"" + s + "\" @ " + addr);
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
        
        // 6. 搜索 SimpleTextInput / ConIn 协议使用
        println("\n=== 搜索 SimpleTextInput/ConIn 相关 ===");
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (funcIter.hasNext() && count < 30) {
            Function f = funcIter.next();
            String name = f.getName().toLowerCase();
            if (name.contains("input") || name.contains("text") || name.contains("con") || 
                name.contains("key") || name.contains("read")) {
                println("  " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
                count++;
            }
        }
        
        decompiler.dispose();
        println("\n=== BDS 菜单触发方式分析完成 ===");
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
