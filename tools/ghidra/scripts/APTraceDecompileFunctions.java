/* APTrace: dump Ghidra's decompiler output for specific functions.
 *
 * Run as a headless -postScript (after auto-analysis + any entry seeding),
 * to get decompiled C for functions of interest -- structure-recovery
 * evidence (what does this code read/write, and under what condition)
 * that's much clearer from decompiler output than from raw instructions or
 * the flat data-reference list APTraceExportStaticAnalysis.java exports.
 * See docs/tooling/tool-selection.md: "Ghidra... decompiler output... is
 * far cheaper to query than staring at raw IR."
 *
 * Script args: <output.txt> <hexAddr1>[,<hexAddr2>...]
 */
//@category APTrace

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.PrintWriter;

public class APTraceDecompileFunctions extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			println("usage: APTraceDecompileFunctions.java <output.txt> <hexAddr1>[,<hexAddr2>...]");
			return;
		}
		String outPath = args[0];
		String[] addrs = args[1].split(",");

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);

		try (PrintWriter out = new PrintWriter(outPath, "UTF-8")) {
			for (String tok : addrs) {
				String hex = tok.trim();
				if (hex.startsWith("0x") || hex.startsWith("0X")) {
					hex = hex.substring(2);
				}
				long off = Long.parseLong(hex, 16);
				Address a = currentProgram.getMinAddress().getNewAddress(off);
				Function f = currentProgram.getFunctionManager().getFunctionAt(a);
				out.println("==================================================");
				if (f == null) {
					out.println("No function at " + a + " (seed it first via APTraceSeedVectorTable.java)");
					out.println();
					continue;
				}
				out.println("Function: " + f.getName() + " @ " + f.getEntryPoint()
					+ "  size=" + f.getBody().getNumAddresses()
					+ "  params=" + f.getParameterCount()
					+ "  callingConvention=" + f.getCallingConventionName());
				out.println();
				DecompileResults res = decomp.decompileFunction(f, 60, new ConsoleTaskMonitor());
				if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
					out.println(res.getDecompiledFunction().getC());
				} else {
					out.println("(decompilation failed: " + res.getErrorMessage() + ")");
				}
				out.println();
			}
		}

		decomp.dispose();
		println("APTraceDecompileFunctions: wrote " + outPath);
	}
}
