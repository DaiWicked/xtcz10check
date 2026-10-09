# Ghidra Headless Script: Find all readers of devinfo caches in abl
# Targets: 0x64938 (standard devinfo cache, 0xA50) and 0x65388 (XTC devinfo cache, 0xA50)
# Output: function address, name, disassembly around reference, decompiled code

from ghidra.program.model.symbol import RefType
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Target addresses (ImageBase=0, so file offset == VA)
TARGETS = {
    0x64938: "standard_devinfo_cache",
    0x65388: "xtc_devinfo_cache",
}

# Also search for readSecurityState callers (FUN_1D7A8)
READ_SECURITY_STATE = 0x1D7A8

def get_decompiler():
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    return decomp

def decompile_function(func, decomp):
    try:
        results = decomp.decompileFunction(func, 30, ConsoleTaskMonitor())
        if results.decompileCompleted():
            return results.getDecompiledFunction().getC()
    except:
        pass
    return None

def get_disasm_around(addr, num_before=5, num_after=10):
    """Get disassembly lines around an address"""
    listing = currentProgram.getListing()
    code_units = []
    
    # Get instructions before
    cur = addr
    for _ in range(num_before):
        prev = listing.getInstructionBefore(cur)
        if prev is None:
            break
        code_units.insert(0, prev)
        cur = prev.getAddress()
    
    # Get instruction at and after
    cur = addr
    for _ in range(num_after):
        insn = listing.getInstructionAt(cur)
        if insn is None:
            insn = listing.getInstructionAfter(cur)
        if insn is None:
            break
        code_units.append(insn)
        cur = insn.getAddress().add(insn.getLength())
    
    return code_units

def analyze_target(target_addr, target_name):
    print("\n" + "="*80)
    print(f"=== References to {target_name} @ 0x{target_addr:X} (size 0xA50) ===")
    print("="*80)
    
    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target_addr)
    
    # Get all references to this address range (0xA50 bytes)
    ref_manager = currentProgram.getReferenceManager()
    refs = []
    
    # Search for references to any address in the range
    end_addr = target_addr + 0xA50
    for offset in range(0, 0xA50, 1):
        search_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target_addr + offset)
        for ref in ref_manager.getReferencesTo(search_addr):
            refs.append((offset, ref))
    
    if not refs:
        print(f"  No direct references found. Searching for adrp/add patterns...")
        # Fallback: search for instructions that compute this address
        # This is handled by Ghidra's reference analysis if it ran correctly
        return
    
    # Group by function
    func_refs = {}
    for offset, ref in refs:
        from_addr = ref.getFromAddress()
        func = getFunctionContaining(from_addr)
        if func is None:
            func_key = ("NO_FUNCTION", from_addr.getOffset())
        else:
            func_key = (func.getName(), func.getEntryPoint().getOffset())
        
        if func_key not in func_refs:
            func_refs[func_key] = []
        func_refs[func_key].append((offset, ref))
    
    print(f"\n  Found {len(refs)} references in {len(func_refs)} functions:")
    
    decomp = get_decompiler()
    
    for (func_name, func_entry), ref_list in sorted(func_refs.items(), key=lambda x: x[0][1]):
        print(f"\n  --- Function: {func_name} @ 0x{func_entry:X} ---")
        print(f"      References: {len(ref_list)}")
        
        # Show offsets accessed
        offsets = sorted(set(r[0] for r in ref_list))
        print(f"      Offsets accessed: {[hex(o) for o in offsets]}")
        
        # Show key offsets
        key_offsets = [0x0D, 0x0E, 0x0F, 0x90]
        for ko in key_offsets:
            if ko in offsets:
                print(f"      ★ Accesses key offset 0x{ko:X}!")
        
        # Show disassembly for first few references
        for i, (offset, ref) in enumerate(ref_list[:3]):
            from_addr = ref.getFromAddress()
            ref_type = ref.getReferenceType()
            print(f"\n      Ref {i+1}: 0x{from_addr.getOffset():X} +0x{offset:X} ({ref_type})")
            
            # Get disassembly
            insns = get_disasm_around(from_addr, 3, 5)
            for insn in insns:
                marker = "  >>> " if insn.getAddress() == from_addr else "      "
                print(f"{marker}{insn.getAddress()}  {insn.toString()}")
        
        # Show decompiled function (truncated)
        if func_name != "NO_FUNCTION":
            func = getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(func_entry))
            if func:
                code = decompile_function(func, decomp)
                if code:
                    # Show first 50 lines
                    lines = code.split('\n')[:60]
                    print(f"\n      --- Decompiled (first {len(lines)} lines) ---")
                    for line in lines:
                        print(f"      {line}")
                    if len(code.split('\n')) > 60:
                        print(f"      ... (truncated, total {len(code.split(chr(10)))} lines)")

def analyze_read_security_state():
    print("\n" + "="*80)
    print(f"=== Callers of readSecurityState @ 0x{READ_SECURITY_STATE:X} ===")
    print("="*80)
    
    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(READ_SECURITY_STATE)
    refs = currentProgram.getReferenceManager().getReferencesTo(addr)
    
    callers = []
    for ref in refs:
        if ref.getReferenceType().isCall():
            from_addr = ref.getFromAddress()
            func = getFunctionContaining(from_addr)
            if func:
                callers.append((func.getName(), func.getEntryPoint().getOffset(), from_addr.getOffset()))
    
    print(f"\n  Found {len(callers)} callers:")
    for name, entry, call_addr in sorted(callers, key=lambda x: x[1]):
        print(f"    {name} @ 0x{entry:X} (call at 0x{call_addr:X})")

def main():
    print("Ghidra Headless: Finding devinfo cache readers in abl")
    print(f"Program: {currentProgram.getName()}")
    print(f"ImageBase: {currentProgram.getImageBase()}")
    
    # Analyze targets
    for target_addr, target_name in TARGETS.items():
        analyze_target(target_addr, target_name)
    
    # Analyze readSecurityState callers
    analyze_read_security_state()
    
    print("\n" + "="*80)
    print("Analysis complete!")
    print("="*80)

main()
