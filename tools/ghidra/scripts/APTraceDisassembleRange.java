/* APTrace: dump per-instruction (address, mnemonic, operands) for one
 * address range -- a reusable static-analysis convenience alongside
 * APTraceDecompileFunctions.java, for the cases where decompiler C output
 * hides the real instruction addresses (e.g. finding the exact address of
 * a specific call site within a function, to use as a Unicorn entry point
 * that skips a not-yet-modeled earlier step). See
 * docs/tooling/tool-selection.md: Ghidra is the static-structure tool;
 * this is a thin, direct use of its own disassembly listing, not a new
 * disassembler.
 *
 * Run as a headless -postScript (after auto-analysis + any entry seeding).
 *
 * Script args: <output.txt> <hexStartAddr> <hexEndAddrInclusive>
 */
//@category APTrace

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

import java.io.PrintWriter;

public class APTraceDisassembleRange extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 3) {
			println("usage: APTraceDisassembleRange.java <output.txt> <hexStartAddr> <hexEndAddrInclusive>");
			return;
		}
		String outPath = args[0];
		Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[1]);
		Address end = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[2]);

		try (PrintWriter pw = new PrintWriter(outPath)) {
			InstructionIterator it = currentProgram.getListing().getInstructions(start, true);
			while (it.hasNext()) {
				Instruction insn = it.next();
				if (insn.getAddress().compareTo(end) > 0) {
					break;
				}
				pw.printf("0x%08x  %s%n", insn.getAddress().getOffset(), insn.toString());
			}
		}
		println("APTraceDisassembleRange: wrote " + outPath);
	}
}
