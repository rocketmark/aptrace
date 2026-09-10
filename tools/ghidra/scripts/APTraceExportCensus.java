/* APTrace: export basic-block/CFG-edge/memory-access facts for the
 * `aptrace census` mechanical firmware census (tools/census/).
 *
 * Run as a headless -postScript, after import + auto-analysis, alongside
 * (not instead of) APTraceExportStaticAnalysis.java -- that script owns
 * functions/calls/dataReferences/strings; this one owns everything that
 * needs Ghidra's basic-block model and per-instruction operand
 * classification: basic blocks, block-level CFG edges (including
 * call edges and indirect/computed edges Ghidra did or did not resolve),
 * and RAM/MMIO memory accesses with an access width derived from the
 * instruction mnemonic.
 *
 * Deliberately does NOT resolve MMIO addresses to SAMD51 peripheral/
 * register names -- that happens in Python (tools/svd/resolve_mmio.py),
 * kept as the sole SVD authority per docs/tooling/tool-selection.md.
 * This script only classifies an access as landing in the RAM window or
 * the MMIO window (by address range, given as script args) and reports
 * the raw address/width/direction -- a fact, not an interpretation.
 *
 * Script args: <output.json> <ramBaseHex> <ramSizeHex> <mmioBaseHex> <mmioSizeHex>
 */
//@category APTrace

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;

public class APTraceExportCensus extends GhidraScript {

	private static String jsonString(String s) {
		StringBuilder b = new StringBuilder("\"");
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"': b.append("\\\""); break;
				case '\\': b.append("\\\\"); break;
				case '\n': b.append("\\n"); break;
				case '\r': b.append("\\r"); break;
				case '\t': b.append("\\t"); break;
				default:
					if (c < 0x20) {
						b.append(String.format("\\u%04x", (int) c));
					} else {
						b.append(c);
					}
			}
		}
		b.append('"');
		return b.toString();
	}

	private static String hexAddr(Address a) {
		return "0x" + a.toString(false);
	}

	private static String jsonOrNull(String s) {
		return s == null ? "null" : jsonString(s);
	}

	private Function functionAt(Address a) {
		return currentProgram.getFunctionManager().getFunctionContaining(a);
	}

	/* Coarse, deterministic classification of a FlowType into a kind
	 * string -- driven entirely by FlowType's own boolean accessors, in
	 * a fixed priority order (call before jump before fallthrough), with
	 * the FlowType's own name as a fallback so nothing is silently
	 * dropped into the wrong bucket. */
	private static String classifyFlow(FlowType ft) {
		if (ft.isCall()) {
			return ft.isComputed() ? "computed-call" : "call";
		}
		if (ft.isComputed()) {
			return "computed-jump";
		}
		if (ft.isJump()) {
			return ft.isConditional() ? "cbranch" : "branch";
		}
		if (ft.hasFallthrough()) {
			return "fallthrough";
		}
		if (ft.isTerminal()) {
			return "terminator";
		}
		return ft.getName();
	}

	/* Access width in bytes from a Cortex-M Thumb load/store mnemonic, or
	 * null if the mnemonic isn't a single-fixed-width load/store this
	 * script recognizes (e.g. LDM/STM/PUSH/POP move multiple registers --
	 * genuinely ambiguous as a single "width", left null rather than
	 * guessed at). Specific (longer) mnemonics are checked before the
	 * generic ldr/str fallback so e.g. "ldrb" doesn't fall through to the
	 * 4-byte "ldr" bucket. */
	private static Integer widthFromMnemonic(String mnemonic) {
		String m = mnemonic.toLowerCase();
		if (m.startsWith("ldrsb") || m.startsWith("strb") || m.startsWith("ldrb")) {
			return 1;
		}
		if (m.startsWith("ldrsh") || m.startsWith("strh") || m.startsWith("ldrh")) {
			return 2;
		}
		if (m.startsWith("ldrd") || m.startsWith("strd")) {
			return 8;
		}
		if (m.startsWith("ldr") || m.startsWith("str") || m.startsWith("vldr") || m.startsWith("vstr")) {
			return 4;
		}
		return null;
	}

	private static String directionOf(RefType rt) {
		if (rt.isWrite()) return "WRITE";
		if (rt.isRead()) return "READ";
		return "DATA";
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 5) {
			println("usage: APTraceExportCensus.java <output.json> <ramBaseHex> <ramSizeHex> <mmioBaseHex> <mmioSizeHex>");
			return;
		}
		String outPath = args[0];
		long ramBase = Long.decode(args[1]);
		long ramSize = Long.decode(args[2]);
		long mmioBase = Long.decode(args[3]);
		long mmioSize = Long.decode(args[4]);
		long ramEnd = ramBase + ramSize;       // exclusive
		long mmioEnd = mmioBase + mmioSize;    // exclusive

		Listing listing = currentProgram.getListing();
		ReferenceManager refMgr = currentProgram.getReferenceManager();
		BasicBlockModel blockModel = new BasicBlockModel(currentProgram);

		try (PrintWriter out = new PrintWriter(outPath, "UTF-8")) {
			out.println("{");

			// --- basic blocks + block-level CFG edges (single pass over
			// Ghidra's own basic-block model) ---
			List<String> blockLines = new ArrayList<>();
			List<String> edgeLines = new ArrayList<>();
			Set<String> resolvedComputedFrom = new HashSet<>();

			CodeBlockIterator blocks = blockModel.getCodeBlocks(monitor);
			while (blocks.hasNext()) {
				if (monitor.isCancelled()) break;
				CodeBlock block = blocks.next();
				Address start = block.getFirstStartAddress();
				Address end = block.getMaxAddress();
				Function fn = functionAt(start);
				blockLines.add("    { \"start\": " + jsonString(hexAddr(start))
					+ ", \"end\": " + jsonString(hexAddr(end))
					+ ", \"functionEntry\": " + (fn == null ? "null" : jsonString(hexAddr(fn.getEntryPoint())))
					+ ", \"functionName\": " + (fn == null ? "null" : jsonString(fn.getName())) + " }");

				CodeBlockReferenceIterator destIter = block.getDestinations(monitor);
				while (destIter.hasNext()) {
					if (monitor.isCancelled()) break;
					CodeBlockReference ref = destIter.next();
					FlowType ft = ref.getFlowType();
					Address from = ref.getSourceAddress();
					Address to = ref.getDestinationAddress();
					if (to == null || !to.getAddressSpace().equals(start.getAddressSpace())) {
						// External/other-space destination (e.g. a call
						// into an unanalyzed external region) -- nothing
						// useful to join against this firmware's own
						// address space; skip rather than emit a
						// misleading edge.
						continue;
					}
					Function fromFn = functionAt(from);
					Function toFn = functionAt(to);
					String kind = classifyFlow(ft);
					if (ft.isComputed()) {
						resolvedComputedFrom.add(hexAddr(from));
					}
					edgeLines.add("    { \"from\": " + jsonString(hexAddr(from))
						+ ", \"to\": " + jsonString(hexAddr(to))
						+ ", \"kind\": " + jsonString(kind)
						+ ", \"resolved\": true"
						+ ", \"fromFunctionEntry\": " + (fromFn == null ? "null" : jsonString(hexAddr(fromFn.getEntryPoint())))
						+ ", \"toFunctionEntry\": " + (toFn == null ? "null" : jsonString(hexAddr(toFn.getEntryPoint())))
						+ ", \"source\": \"ghidra-basicblockmodel\" }");
				}
			}

			// --- unresolved indirect edges + RAM/MMIO memory accesses
			// (single pass over every instruction) ---
			List<String> memLines = new ArrayList<>();
			List<String> mmioLines = new ArrayList<>();
			InstructionIterator iIter = listing.getInstructions(true);
			while (iIter.hasNext()) {
				if (monitor.isCancelled()) break;
				Instruction insn = iIter.next();
				Address from = insn.getAddress();
				String fromHex = hexAddr(from);
				Function fromFn = functionAt(from);
				String fromFnEntry = fromFn == null ? "null" : jsonString(hexAddr(fromFn.getEntryPoint()));

				FlowType ft = insn.getFlowType();
				if (ft.isComputed() && !resolvedComputedFrom.contains(fromHex)) {
					edgeLines.add("    { \"from\": " + jsonString(fromHex)
						+ ", \"to\": null"
						+ ", \"kind\": " + jsonString(classifyFlow(ft) + "-unresolved")
						+ ", \"resolved\": false"
						+ ", \"fromFunctionEntry\": " + fromFnEntry
						+ ", \"toFunctionEntry\": null"
						+ ", \"source\": \"ghidra-instrscan\" }");
				}

				Integer width = widthFromMnemonic(insn.getMnemonicString());
				Reference[] refs = refMgr.getReferencesFrom(from);
				for (Reference ref : refs) {
					RefType rt = ref.getReferenceType();
					if (!(rt.isRead() || rt.isWrite() || rt == RefType.DATA)) {
						continue;
					}
					long toOffset = ref.getToAddress().getOffset();
					String direction = directionOf(rt);
					String widthJson = width == null ? "null" : String.valueOf(width);
					if (toOffset >= ramBase && toOffset < ramEnd) {
						memLines.add("    { \"from\": " + jsonString(fromHex)
							+ ", \"fromFunctionEntry\": " + fromFnEntry
							+ ", \"to\": " + jsonString(hexAddr(ref.getToAddress()))
							+ ", \"width\": " + widthJson
							+ ", \"direction\": " + jsonString(direction)
							+ ", \"source\": \"ghidra-refmgr\" }");
					} else if (toOffset >= mmioBase && toOffset < mmioEnd) {
						mmioLines.add("    { \"from\": " + jsonString(fromHex)
							+ ", \"fromFunctionEntry\": " + fromFnEntry
							+ ", \"to\": " + jsonString(hexAddr(ref.getToAddress()))
							+ ", \"width\": " + widthJson
							+ ", \"direction\": " + jsonString(direction)
							+ ", \"source\": \"ghidra-refmgr\" }");
					}
				}
			}

			out.println("  \"basicBlocks\": [");
			out.println(String.join(",\n", blockLines));
			out.println("  ],");
			out.println("  \"edges\": [");
			out.println(String.join(",\n", edgeLines));
			out.println("  ],");
			out.println("  \"memoryAccesses\": [");
			out.println(String.join(",\n", memLines));
			out.println("  ],");
			out.println("  \"mmioAccesses\": [");
			out.println(String.join(",\n", mmioLines));
			out.println("  ]");
			out.println("}");
		}

		println("APTraceExportCensus: wrote " + outPath);
	}
}
