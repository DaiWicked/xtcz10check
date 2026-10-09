// analyze_rwdevicestate.java
// 分析 VerifiedBootDxe 的标准 RWDeviceState 函数
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class analyze_rwdevicestate extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== 分析 VerifiedBootDxe 标准 RWDeviceState ===");
        
        // FUN_00001470 是标准 RWDeviceState
        Address funcAddr = toAddr(0x1470);
        Function func = getFunctionAt(funcAddr);
        
        if (func == null) {
            println("FUN_00001470 not found, trying to disassemble...");
            disassemble(funcAddr);
            func = getFunctionAt(funcAddr);
        }
        
        if (func != null) {
            println("\n=== Function: " + func.getName() + " ===");
            println("Entry: " + func.getEntryPoint());
            println("Body: " + func.getBody());
            
            // 打印反编译
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
            
            // 打印指令
            println("\n=== Instructions ===");
            InstructionIterator iter = currentProgram.getListing().getInstructions(func.getBody(), true);
            int count = 0;
            while (iter.hasNext() && count < 200) {
                Instruction inst = iter.next();
                println(inst.getAddress() + "  " + inst.toString());
                count++;
            }
        }
        
        // 查找字符串引用
        println("\n=== String references in function ===");
        if (func != null) {
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
        }
        
        // 查找调用的函数
        println("\n=== Called functions ===");
        if (func != null) {
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
        }
        
        // 分析 XTC RWDeviceState FUN_00002388
        println("\n\n=== XTC RWDeviceState FUN_00002388 ===");
        Address xtcAddr = toAddr(0x2388);
        Function xtcFunc = getFunctionAt(xtcAddr);
        if (xtcFunc != null) {
            try {
                ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
                decomp.openProgram(currentProgram);
                ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(xtcFunc, 60, monitor);
                if (results.decompileCompleted()) {
                    println(results.getDecompiledFunction().getC());
                }
            } catch (Exception e) {
                println("Error: " + e.getMessage());
            }
        }
        
        // 查找 rpmb/qsee/keymaster 字符串
        println("\n=== RPMB/QSEE/keymaster strings ===");
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (data.hasStringValue()) {
                String val = data.getValue().toString().toLowerCase();
                if (val.contains("rpmb") || val.contains("qsee") || val.contains("keymaster") || val.contains("devinfo") || val.contains("succeed using")) {
                    println("  " + data.getAddress() + " : \"" + data.getValue() + "\"");
                }
            }
        }
    }
}
