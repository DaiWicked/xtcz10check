// analyze_3544.java
// 分析 FUN_00003544 - 获取安全状态的函数
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class analyze_3544 extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== 分析 FUN_00003544 ===");
        
        Address funcAddr = toAddr(0x3544);
        Function func = getFunctionAt(funcAddr);
        
        if (func == null) {
            disassemble(funcAddr);
            func = getFunctionAt(funcAddr);
        }
        
        if (func != null) {
            println("Entry: " + func.getEntryPoint());
            println("Body: " + func.getBody());
            
            try {
                ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
                decomp.openProgram(currentProgram);
                ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(func, 60, monitor);
                if (results.decompileCompleted()) {
                    println("\n=== Decompiled ===");
                    println(results.getDecompiledFunction().getC());
                }
            } catch (Exception e) {
                println("Error: " + e.getMessage());
            }
            
            println("\n=== Instructions ===");
            InstructionIterator iter = currentProgram.getListing().getInstructions(func.getBody(), true);
            int count = 0;
            while (iter.hasNext() && count < 200) {
                Instruction inst = iter.next();
                println(inst.getAddress() + "  " + inst.toString());
                count++;
            }
            
            println("\n=== Called functions ===");
            AddressIterator addrIter = func.getBody().getAddresses(true);
            while (addrIter.hasNext()) {
                Address addr = addrIter.next();
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
            
            println("\n=== String references ===");
            AddressIterator addrIter2 = func.getBody().getAddresses(true);
            while (addrIter2.hasNext()) {
                Address addr = addrIter2.next();
                Reference[] refs = getReferencesFrom(addr);
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isData()) {
                        Data data = getDataAt(ref.getToAddress());
                        if (data != null && data.hasStringValue()) {
                            println("  " + addr + " -> " + ref.getToAddress() + " : \"" + data.getValue() + "\"");
                        }
                    }
                }
            }
        }
        
        // 分析 FUN_00003860
        println("\n\n=== FUN_00003860 ===");
        Address addr3860 = toAddr(0x3860);
        Function func3860 = getFunctionAt(addr3860);
        if (func3860 != null) {
            try {
                ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
                decomp.openProgram(currentProgram);
                ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(func3860, 60, monitor);
                if (results.decompileCompleted()) {
                    println(results.getDecompiledFunction().getC());
                }
            } catch (Exception e) {
                println("Error: " + e.getMessage());
            }
        }
        
        // 查找所有调用 FUN_00003544 的地方
        println("\n=== Callers of FUN_00003544 ===");
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
}
