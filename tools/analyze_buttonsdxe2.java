// Ghidra Headless 脚本：针对性反编译 ButtonsDxe 关键函数
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.app.decompiler.*;
import java.util.*;

public class analyze_buttonsdxe2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== ButtonsDxe 关键函数针对性分析 ===");
        
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        
        // 关键函数列表
        String[] targets = {
            "00003740",  // ButtonsInit (含 InitializeKeyMap)
            "00003920",  // PollButtonArray
            "000039d4",  // PollPowerKey
            "00003700",  // ConfigureButtonGPIOs
            "00001950",  // PollButtonKeys
            "00003d04",  // 最大函数，可能是 ReadKeyStroke
        };
        
        for (String addrStr : targets) {
            Function f = getFunctionAt(toAddr(addrStr));
            if (f != null) {
                println("\n" + "=".repeat(60));
                println("=== " + f.getName() + " @ " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses() + " ===");
                println("=".repeat(60));
                
                // 打印调用的函数
                println("\n--- 调用的子函数 ---");
                Set<Function> calledSet = f.getCalledFunctions(monitor);
                List<String> calledList = new ArrayList<>();
                for (Function cf : calledSet) {
                    calledList.add(cf.getName() + " @ " + cf.getEntryPoint());
                }
                Collections.sort(calledList);
                for (String s : calledList) {
                    println("  " + s);
                }
                
                // 反编译
                println("\n--- 反编译 ---");
                DecompileResults results = decompiler.decompileFunction(f, 60, monitor);
                if (results.decompileCompleted()) {
                    String code = results.getDecompiledFunction().getC();
                    String[] lines = code.split("\n");
                    for (int i = 0; i < lines.length; i++) {
                        println(lines[i]);
                    }
                } else {
                    println("反编译失败: " + results.getErrorMessage());
                }
            }
        }
        
        // 搜索全局数据区（可能的 key map 表）
        println("\n" + "=".repeat(60));
        println("=== 搜索全局数据区的 key map ===");
        println("=".repeat(60));
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (block.getName().contains(".data") || block.getName().contains(".bss") || block.getName().contains("rodata")) {
                println("\n内存块: " + block.getName() + " @ " + block.getStart() + " size=" + block.getSize());
                // 打印前256字节的十六进制
                Address start = block.getStart();
                long size = Math.min(block.getSize(), 512);
                StringBuilder sb = new StringBuilder();
                for (long i = 0; i < size; i++) {
                    if (i % 16 == 0) {
                        if (sb.length() > 0) println(sb.toString());
                        sb = new StringBuilder();
                        sb.append(String.format("%08X: ", start.add(i).getOffset()));
                    }
                    try {
                        byte b = getByte(start.add(i));
                        sb.append(String.format("%02X ", b & 0xFF));
                    } catch (Exception e) {
                        sb.append("?? ");
                    }
                }
                if (sb.length() > 0) println(sb.toString());
            }
        }
        
        decompiler.dispose();
        println("\n=== 分析完成 ===");
    }
}
