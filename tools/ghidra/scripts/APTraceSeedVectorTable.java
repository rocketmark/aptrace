/* APTrace: seed Ghidra function starts from the ARMv7-M vector table.
 *
 * Run as a headless -preScript, before auto-analysis (see
 * tools/ghidra/analyze_firmware.sh). Without this, a raw BinaryLoader
 * import gives Ghidra no entry points at all, and its heuristic Function
 * Start Search alone misses most of the real functions (confirmed: an
 * unseeded run of this same firmware found only 204 functions, none in the
 * 0x8000-0x9700 region where the protocol dispatcher lives -- see
 * docs/harness/protocol-harness-results.md for that region's significance).
 *
 * This reuses the same vector-table structure already validated by
 * tools/vector_scan.py and APTrace.VectorTable (56 entries: 16 system +
 * 40 IRQ, per docs/firmware/firmware-layout.md) -- it does not
 * reimplement vector-table *parsing* logic beyond what's needed to hand
 * Ghidra a list of addresses to disassemble as Thumb functions.
 *
 * Script args: [numVectors] [extraHexAddrs]
 *   numVectors:    how many 4-byte vector-table words to read, starting
 *                  after the initial-SP word (default 56).
 *   extraHexAddrs: optional comma-separated list of additional addresses
 *                  to seed as functions (e.g. a specific address under
 *                  investigation) -- e.g. "0x8259,0x801c,0x8a35".
 */
//@category APTrace

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class APTraceSeedVectorTable extends GhidraScript {

	private void seed(Address a, String label) {
		try {
			disassemble(a);
			createFunction(a, null);
			println("  seeded " + label + " -> " + a);
		} catch (Exception e) {
			println("  (skipping " + label + " -> " + a + ": " + e.getMessage() + ")");
		}
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		int numVectors = (args.length >= 1 && !args[0].isEmpty()) ? Integer.parseInt(args[0]) : 56;

		Memory mem = currentProgram.getMemory();
		MemoryBlock block = mem.getBlocks()[0];
		Address base = block.getStart();

		// Vector 0 is the initial stack pointer, not code; vectors 1..N are
		// Thumb handler pointers (low bit set, per the ARMv7-M convention).
		for (int i = 1; i <= numVectors; i++) {
			Address wordAddr = base.add((long) i * 4);
			if (wordAddr.compareTo(block.getEnd()) > 0) {
				break;
			}
			long raw = mem.getInt(wordAddr) & 0xFFFFFFFFL;
			if (raw == 0 || raw == 0xFFFFFFFFL) {
				continue;
			}
			long target = raw & ~1L;
			if (target < base.getOffset() || target > block.getEnd().getOffset()) {
				continue;
			}
			seed(base.getNewAddress(target), "vector[" + i + "]");
		}

		if (args.length >= 2 && !args[1].isEmpty()) {
			for (String tok : args[1].split(",")) {
				String hex = tok.trim();
				if (hex.startsWith("0x") || hex.startsWith("0X")) {
					hex = hex.substring(2);
				}
				long addr = Long.parseLong(hex, 16);
				seed(base.getNewAddress(addr), "extra");
			}
		}
	}
}
