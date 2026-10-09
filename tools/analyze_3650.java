// analyze_3650.java
// 分析 FUN_00003650 - 设置 local_b0 标志的函数
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class analyze_3650 extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== 分析 FUN_00003650 ===");
        
        Address funcAddr = toAddr(0x3650);
        Function func = getFunctionAt(funcAddr);
        
        if (func == null) {
            println("FUN_00003650 not found, trying to disassemble...");
            disassemble(funcAddr);
            func = getFunctionAt(funcAddr);
        }
        
        if (func != null) {
            println("\n=== Function: " + func.getName() + " ===");
            println("Entry: " + func.getEntryPoint());
            println("Body: " + func.getBody());
            
            // 反编译
            try {
                ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
                decomp.openProgram(currentProgram);
                ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(func, 60, monitor);
                if (results.decompileCompleted()) {
                    println("\n=== Decompiled ===");
                    println(results.getDecompiledFunction().getC());
                } else {
                    println("Decompile failed: " + results.getErrorMessage());
                }
            } catch (Exception e) {
                println("Decompile error: " + e.getMessage());
            }
            
            // 指令
            println("\n=== Instructions ===");
            InstructionIterator iter = currentProgram.getListing().getInstructions(func.getBody(), true);
            int count = 0;
            while (iter.hasNext() && count < 300) {
                Instruction inst = iter.next();
                println(inst.getAddress() + "  " + inst.toString());
                count++;
            }
            
            // 字符串引用
            println("\n=== String references ===");
            AddressIterator addrIter = func.getBody().getAddresses(true);
            while (addrIter.hasNext()) {
                Address addr = addrIter.next();
                Reference[] refs = getReferencesFrom(addr);
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isData()) {
                        Address toAddr = ref.getToAddress();
                        Data data = getDataAt(toAddr);
                        if (data != null && data.hasStringValue()) {
                            println("  " + addr + " -> " + toAddr + " : \"" + data.getValue() + "\"");
                        }
                    }
                }
            }
            
            // 调用的函数
            println("\n=== Called functions ===");
            AddressIterator addrIter2 = func.getBody().getAddresses(true);
            while (addrIter2.hasNext()) {
                Address addr = addrIter2.next();
                Reference[] refs = getReferencesFrom(addr);
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isCall()) {
                        Function calledFunc = getFunctionAt(ref.getToAddress());
                        if (calledFunc != null) {
                            println("  " + addr + " -> " + calledFunc.getName() + " (" + ref.getToAddress() + ")");
                        }
                    }
                }
            }
            
            // 谁调用了 FUN_00003650
            println("\n=== Callers of FUN_00003650 ===");
            Reference[] refsTo = getReferencesTo(funcAddr);
            for (Reference ref : refsTo) {
                if (ref.getReferenceType().isCall()) {
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        println("  " + ref.getFromAddress() + " in " + caller.getName());
                    }
                }
            }
        }
        
        // 分析 FUN_00002678 (GetProtocol)
        println("\n\n=== FUN_00002678 (GetProtocol?) ===");
        Address addr2678 = toAddr(0x2678);
        Function func2678 = getFunctionAt(addr2678);
        if (func2678 != null) {
            try {
                ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
                decomp.openProgram(currentProgram);
                ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(func2678, 60, monitor);
                if (results.decompileCompleted()) {
                    println(results.getDecompiledFunction().getC());
                }
            } catch (Exception e) {
                println("Error: " + e.getMessage());
            }
        }
        
        // 查找 DAT_0000d000 附近的数据
        println("\n=== Data around DAT_0000d000 ===");
        for (int offset = 0; offset < 0x100; offset += 16) {
            Address addr = toAddr(0xd000 + offset);
            Data data = getDataAt(addr);
            if (data != null) {
                println("  " + addr + " : " + data.getValue());
            }
        }
        
        // 查找安全状态相关字符串
        println("\n=== Security state strings ===");
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (data.hasStringValue()) {
                String val = data.getValue().toString().toLowerCase();
                if (val.contains("sec") || val.contains("fuse") || val.contains("rpmb") || 
                    val.contains("qsee") || val.contains("keymaster") || val.contains("state") ||
                    val.contains("boot") || val.contains("lock") || val.contains("unlock")) {
                    println("  " + data.getAddress() + " : \"" + data.getValue() + "\"");
                }
            }
        }
    }
}
