// Ghidra Headless Script: Find all readers of devinfo caches in abl
// Targets: 0x64938 (standard devinfo cache, 0xA50) and 0x65388 (XTC devinfo cache, 0xA50)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;

public class find_devinfo_readers extends GhidraScript {
    
    private static final long[] TARGETS = {0x64938L, 0x65388L};
    private static final String[] TARGET_NAMES = {"standard_devinfo_cache", "xtc_devinfo_cache"};
    private static final long TARGET_SIZE = 0xA50;
    private static final long READ_SECURITY_STATE = 0x1D7A8L;
    
    private DecompInterface decomp;
    
    @Override
    public void run() throws Exception {
        println("Ghidra Headless: Finding devinfo cache readers in abl");
        println("Program: " + currentProgram.getName());
        println("ImageBase: " + currentProgram.getImageBase());
        
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        // Analyze targets
        for (int i = 0; i < TARGETS.length; i++) {
            analyzeTarget(TARGETS[i], TARGET_NAMES[i]);
        }
        
        // Analyze readSecurityState callers
        analyzeReadSecurityState();
        
        println("\n" + "=".repeat(80));
        println("Analysis complete!");
        println("=".repeat(80));
    }
    
    private void analyzeTarget(long targetAddr, String targetName) {
        println("\n" + "=".repeat(80));
        println("=== References to " + targetName + " @ 0x" + Long.toHexString(targetAddr) + " (size 0xA50) ===");
        println("=".repeat(80));
        
        // Collect all references in the range
        Map<String, List<long[]>> funcRefs = new LinkedHashMap<>();
        int totalRefs = 0;
        Set<Long> offsetsAccessed = new TreeSet<>();
        
        for (long offset = 0; offset < TARGET_SIZE; offset++) {
            Address searchAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(targetAddr + offset);
            Iterator<Reference> refIter = currentProgram.getReferenceManager().getReferencesTo(searchAddr);
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                totalRefs++;
                offsetsAccessed.add(offset);
                
                Address fromAddr = ref.getFromAddress();
                Function func = getFunctionContaining(fromAddr);
                String funcKey;
                long funcEntry;
                if (func == null) {
                    funcKey = "NO_FUNCTION";
                    funcEntry = fromAddr.getOffset();
                } else {
                    funcKey = func.getName();
                    funcEntry = func.getEntryPoint().getOffset();
                }
                
                String mapKey = funcKey + "@0x" + Long.toHexString(funcEntry);
                funcRefs.computeIfAbsent(mapKey, k -> new ArrayList<>()).add(new long[]{offset, fromAddr.getOffset()});
            }
        }
        
        if (totalRefs == 0) {
            println("  No direct references found.");
            return;
        }
        
        println("\n  Found " + totalRefs + " references in " + funcRefs.size() + " functions:");
        println("  Offsets accessed: " + offsetsAccessed);
        
        // Key offsets
        long[] keyOffsets = {0x0D, 0x0E, 0x0F, 0x90};
        for (long ko : keyOffsets) {
            if (offsetsAccessed.contains(ko)) {
                println("  ★ Accesses key offset 0x" + Long.toHexString(ko) + "!");
            }
        }
        
        // Show each function
        for (Map.Entry<String, List<long[]>> entry : funcRefs.entrySet()) {
            String funcKey = entry.getKey();
            List<long[]> refs = entry.getValue();
            
            println("\n  --- Function: " + funcKey + " ---");
            println("      References: " + refs.size());
            
            // Show offsets
            Set<Long> funcOffsets = new TreeSet<>();
            for (long[] r : refs) funcOffsets.add(r[0]);
            println("      Offsets: " + funcOffsets);
            
            // Show disassembly for first 3 references
            for (int i = 0; i < Math.min(3, refs.size()); i++) {
                long offset = refs.get(i)[0];
                long fromAddr = refs.get(i)[1];
                println("\n      Ref " + (i+1) + ": 0x" + Long.toHexString(fromAddr) + " +0x" + Long.toHexString(offset));
                
                Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(fromAddr);
                Instruction insn = currentProgram.getListing().getInstructionAt(addr);
                if (insn != null) {
                    println("        " + insn.getAddress() + "  " + insn.toString());
                    // Show next few instructions
                    for (int j = 0; j < 5; j++) {
                        insn = currentProgram.getListing().getInstructionAfter(insn.getAddress());
                        if (insn == null) break;
                        println("        " + insn.getAddress() + "  " + insn.toString());
                    }
                }
            }
            
            // Show decompiled function (if not NO_FUNCTION)
            if (!funcKey.startsWith("NO_FUNCTION")) {
                long funcEntry = Long.parseLong(funcKey.split("@0x")[1], 16);
                Function func = getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(funcEntry));
                if (func != null) {
                    String code = decompileFunction(func);
                    if (code != null) {
                        String[] lines = code.split("\n");
                        int showLines = Math.min(50, lines.length);
                        println("\n      --- Decompiled (first " + showLines + " lines) ---");
                        for (int i = 0; i < showLines; i++) {
                            println("      " + lines[i]);
                        }
                        if (lines.length > 50) {
                            println("      ... (truncated, total " + lines.length + " lines)");
                        }
                    }
                }
            }
        }
    }
    
    private void analyzeReadSecurityState() {
        println("\n" + "=".repeat(80));
        println("=== Callers of readSecurityState @ 0x" + Long.toHexString(READ_SECURITY_STATE) + " ===");
        println("=".repeat(80));
        
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(READ_SECURITY_STATE);
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
                }
            }
        }
        
        println("\n  Found " + callers.size() + " callers:");
        Collections.sort(callers);
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
