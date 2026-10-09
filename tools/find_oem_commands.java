// 查找 fastboot OEM 命令处理函数和参数注入点
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.Memory;
import java.util.*;

public class find_oem_commands extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== 查找 fastboot OEM 命令 ===");
        
        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        
        // 搜索包含关键词的字符串
        List<String> targetStrings = Arrays.asList(
            "oem device-info",
            "oem select-display-panel", 
            "oem off-mode-charge",
            "oem enable-charger-screen",
            "oem disable-charger-screen",
            "manual-set-panel-mode",
            "set-gpu-preemption",
            "xtcCmdLine",
            "XTCCustomCmdLine"
        );
        
        // 遍历所有数据查找字符串
        DataIterator dataIter = listing.getDefinedData(true);
        Map<String, Address> strAddrMap = new HashMap<>();
        
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            try {
                String val = data.getDefaultValueRepresentation();
                if (val != null) {
                    for (String target : targetStrings) {
                        if (val.contains(target) && !strAddrMap.containsKey(target)) {
                            strAddrMap.put(target, data.getAddress());
                            println("找到 '" + target + "' @ " + data.getAddress());
                        }
                    }
                }
            } catch (Exception e) {}
        }
        
        // 查找字符串引用
        println("\n=== 查找字符串引用 ===");
        for (Map.Entry<String, Address> entry : strAddrMap.entrySet()) {
            Reference[] refs = getReferencesTo(entry.getValue());
            println("\n" + entry.getKey() + " (" + refs.length + " 个引用):");
            for (Reference ref : refs) {
                println("  引用 @ " + ref.getFromAddress());
                Function func = listing.getFunctionContaining(ref.getFromAddress());
                if (func != null) {
                    println("    函数: " + func.getName() + " @ " + func.getEntryPoint());
                }
            }
        }
        
        println("\n=== 完成 ===");
    }
}
