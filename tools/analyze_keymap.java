// Ghidra Headless 脚本：分析 InitializeKeyMap 和 key map 查找
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_keymap extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== InitializeKeyMap 和 key map 分析 ===");
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        // 目标函数
        String[] targets = {
            "00003528",  // InitializeKeyMap
            "00003320",  // key map 查找
            "00001864",  // PollButtonKeys 调用的子函数
            "00001cf0",  // PollButtonKeys 调用的子函数
        };
        
        for (String addrStr : targets) {
            Function f = getFunctionAt(toAddr(addrStr));
            if (f != null) {
                println("\n" + "=".repeat(60));
                println("=== " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses() + " ===");
                println("=".repeat(60));
                
                DecompileResults results = decompiler.decompileFunction(f, 60, monitor);
                if (results.decompileCompleted()) {
                    String code = results.getDecompiledFunction().getC();
                    String[] lines = code.split("\n");
                    for (int i = 0; i < Math.min(200, lines.length); i++) {
                        println(lines[i]);
                    }
                    if (lines.length > 200) {
                        println("... (省略 " + (lines.length - 200) + " 行)");
                    }
                }
            }
        }
        
        // 搜索引用 DAT_000072c4 (key map 表) 的函数
        println("\n" + "=".repeat(60));
        println("=== 引用 key map 表 (DAT_000072c4) 的函数 ===");
        println("=".repeat(60));
        Reference[] refs = getReferencesTo(toAddr("000072c4"));
        Set<String> refFuncs = new HashSet<>();
        for (Reference ref : refs) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            if (caller != null) {
                refFuncs.add(caller.getName() + " @ " + caller.getEntryPoint() + " (ref @ " + ref.getFromAddress() + ")");
            }
        }
        List<String> refList = new ArrayList<>(refFuncs);
        Collections.sort(refList);
        for (String s : refList) {
            println("  " + s);
        }
        
        // 搜索扫描码常量 (0x01=UP, 0x02=DOWN, 0x03=RIGHT, 0x04=LEFT, 0x0B=F1, 0x0C=F2)
        println("\n" + "=".repeat(60));
        println("=== 搜索扫描码常量 ===");
        println("=".repeat(60));
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            if (!block.getName().contains(".text") && !block.getName().contains(".rodata")) continue;
            
            Address start = block.getStart();
            long size = block.getSize();
            for (long offset = 0; offset < size - 4; offset++) {
                Address addr = start.add(offset);
                try {
                    // 搜索 movz w?, #0x1 / #0x2 / #0x3 / #0x4 / #0xB / #0xC 的指令
                    // AARCH64 movz: 0x52800000 | (imm16 << 5) | rd
                    int instr = getInt(addr);
                    if ((instr & 0xFF800000) == 0x52800000) {  // movz
                        int imm = (instr >> 5) & 0xFFFF;
                        int rd = instr & 0x1F;
                        if (imm >= 1 && imm <= 4 || imm == 0x0B || imm == 0x0C) {
                            Function caller = getFunctionContaining(addr);
                            if (caller != null) {
                                println("  movz w" + rd + ", #" + imm + " @ " + addr + " in " + caller.getName());
                            }
                        }
                    }
                } catch (Exception e) {}
            }
        }
        
        decompiler.dispose();
        println("\n=== 分析完成 ===");
    }
}
