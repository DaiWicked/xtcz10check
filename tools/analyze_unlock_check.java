// Ghidra Headless Script: Analyze FUN_00016408 and its callers
// This function is called by FUN_00025968 (unlock check)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;

public class analyze_unlock_check extends GhidraScript {
    
    private static final long TARGET_FUNC = 0x16408L;
    private static final long UNLOCK_CHECK = 0x25968L;
    
    private DecompInterface decomp;
    
    @Override
    public void run() throws Exception {
        println("=" .repeat(80));
        println("Analyzing unlock check chain: FUN_00016408 -> FUN_00025968");
        println("=" .repeat(80));
        
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        // 1. Analyze FUN_00016408
        println("\n### 1. FUN_00016408 (called by unlock check) ###");
        analyzeFunction(TARGET_FUNC, true);
        
        // 2. Analyze FUN_00025968 (unlock check)
        println("\n### 2. FUN_00025968 (unlock check, reads devinfo[0x0D]) ###");
        analyzeFunction(UNLOCK_CHECK, true);
        
        // 3. Find callers of FUN_00025968
        println("\n### 3. Callers of FUN_00025968 (who checks unlock?) ###");
        findCallers(UNLOCK_CHECK);
        
        // 4. Find callers of FUN_00016408
        println("\n### 4. Callers of FUN_00016408 ###");
        findCallers(TARGET_FUNC);
        
        // 5. Analyze FUN_00030f3c and FUN_0003d940 (other readSecurityState callers)
        println("\n### 5. Other readSecurityState callers ###");
        analyzeFunction(0x30f3cL, false);
        analyzeFunction(0x3d940L, false);
        
        println("\n" + "=".repeat(80));
        println("Analysis complete!");
        println("=".repeat(80));
    }
    
    private void analyzeFunction(long addr, boolean showFullDecomp) {
        Address funcAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
        Function func = getFunctionAt(funcAddr);
        
        if (func == null) {
            println("  Function not found at 0x" + Long.toHexString(addr));
            return;
        }
        
        println("\n  Function: " + func.getName() + " @ 0x" + Long.toHexString(addr));
        println("  Entry: 0x" + Long.toHexString(func.getEntryPoint().getOffset()));
        println("  Body size: " + func.getBody().getNumAddresses() + " bytes");
        
        // Show disassembly
        println("\n  --- Disassembly (first 40 instructions) ---");
        Instruction insn = currentProgram.getListing().getInstructionAt(funcAddr);
        int count = 0;
        while (insn != null && count < 40) {
            println("    " + insn.getAddress() + "  " + insn.toString());
            insn = currentProgram.getListing().getInstructionAfter(insn.getAddress());
            count++;
        }
        
        // Show decompiled
        if (showFullDecomp) {
            String code = decompileFunction(func);
            if (code != null) {
                println("\n  --- Decompiled ---");
                String[] lines = code.split("\n");
                for (String line : lines) {
                    println("    " + line);
                }
            }
        } else {
            String code = decompileFunction(func);
            if (code != null) {
                String[] lines = code.split("\n");
                int show = Math.min(30, lines.length);
                println("\n  --- Decompiled (first " + show + " lines) ---");
                for (int i = 0; i < show; i++) {
                    println("    " + lines[i]);
                }
                if (lines.length > 30) {
                    println("    ... (truncated, total " + lines.length + " lines)");
                }
            }
        }
    }
    
    private void findCallers(long targetAddr) {
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(targetAddr);
        Iterator<Reference> refIter = currentProgram.getReferenceManager().getReferencesTo(addr);
        
        List<String> callers = new ArrayList<>();
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Address fromAddr = ref.getFromAddress();
                Function func = getFunctionContaining(fromAddr);
                if (func != null) {
                    callers.add(func.getName() + " @ 0x" + Long.toHexString(func.getEntryPoint().getOffset()) + 
                               " (call at 0x" + Long.toHexString(fromAddr.getOffset()) + ")");
                } else {
                    callers.add("NO_FUNCTION @ 0x" + Long.toHexString(fromAddr.getOffset()));
                }
            }
        }
        
        Collections.sort(callers);
        println("  Found " + callers.size() + " callers:");
        for (String c : callers) {
            println("    " + c);
        }
    }
    
    private String decompileFunction(Function func) {
        try {
            DecompileResults results = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }
}
