/* APTrace: export a Ghidra-analyzed program's static structure to JSON.
 *
 * Run as a headless -postScript after import + auto-analysis (see
 * tools/ghidra/analyze_firmware.sh, which is the intended entry point --
 * don't invoke this script directly unless you know what you're doing).
 *
 * Exports: functions, call edges (caller->callee), data references from
 * code, and defined strings. This is meant to be the "static RE" leg of
 * APTrace's evidence model (see docs/tooling/tool-selection.md) --
 * cross-checked against Macaw's independent discovery, not a replacement
 * for it.
 *
 * Output is hand-rolled JSON (no external library dependency, since
 * headless scripts only have Ghidra's own bundled classpath available).
 */
//@category APTrace

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;

public class APTraceExportStaticAnalysis extends GhidraScript {

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

	private String functionNameAt(Address a) {
		Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
		return f == null ? null : f.getName();
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			println("usage: APTraceExportStaticAnalysis.java <output.json>");
			return;
		}
		String outPath = args[0];

		Listing listing = currentProgram.getListing();
		ReferenceManager refMgr = currentProgram.getReferenceManager();
		Language language = currentProgram.getLanguage();
		CompilerSpec cspec = currentProgram.getCompilerSpec();

		try (PrintWriter out = new PrintWriter(outPath, "UTF-8")) {
			out.println("{");

			// --- program metadata ---
			out.println("  \"program\": {");
			out.println("    \"name\": " + jsonString(currentProgram.getName()) + ",");
			out.println("    \"languageId\": " + jsonString(language.getLanguageID().getIdAsString()) + ",");
			out.println("    \"compilerSpecId\": " + jsonString(cspec.getCompilerSpecID().getIdAsString()) + ",");
			out.println("    \"imageBase\": " + jsonString(hexAddr(currentProgram.getImageBase())) + ",");
			List<String> blockLines = new ArrayList<>();
			Memory mem = currentProgram.getMemory();
			for (MemoryBlock b : mem.getBlocks()) {
				blockLines.add("      { \"name\": " + jsonString(b.getName())
					+ ", \"start\": " + jsonString(hexAddr(b.getStart()))
					+ ", \"end\": " + jsonString(hexAddr(b.getEnd()))
					+ ", \"execute\": " + b.isExecute()
					+ ", \"write\": " + b.isWrite() + " }");
			}
			out.println("    \"memoryBlocks\": [");
			out.println(String.join(",\n", blockLines));
			out.println("    ]");
			out.println("  },");

			// --- functions ---
			List<String> funcLines = new ArrayList<>();
			FunctionIterator fIter = listing.getFunctions(true);
			while (fIter.hasNext()) {
				Function f = fIter.next();
				funcLines.add("    { \"name\": " + jsonString(f.getName())
					+ ", \"entry\": " + jsonString(hexAddr(f.getEntryPoint()))
					+ ", \"size\": " + f.getBody().getNumAddresses()
					+ ", \"thunk\": " + f.isThunk()
					+ ", \"external\": " + f.isExternal() + " }");
			}
			out.println("  \"functions\": [");
			out.println(String.join(",\n", funcLines));
			out.println("  ],");

			// --- call edges + data references from code (single pass over instructions) ---
			List<String> callLines = new ArrayList<>();
			List<String> dataRefLines = new ArrayList<>();
			InstructionIterator iIter = listing.getInstructions(true);
			while (iIter.hasNext()) {
				Instruction insn = iIter.next();
				Address from = insn.getAddress();
				String fromFunc = functionNameAt(from);
				Reference[] refs = refMgr.getReferencesFrom(from);
				for (Reference ref : refs) {
					RefType rt = ref.getReferenceType();
					Address to = ref.getToAddress();
					if (rt.isCall()) {
						String toFunc = functionNameAt(to);
						callLines.add("    { \"from\": " + jsonString(hexAddr(from))
							+ ", \"fromFunction\": " + (fromFunc == null ? "null" : jsonString(fromFunc))
							+ ", \"to\": " + jsonString(hexAddr(to))
							+ ", \"toFunction\": " + (toFunc == null ? "null" : jsonString(toFunc)) + " }");
					} else if (rt.isData()) {
						CodeUnit cu = listing.getCodeUnitAt(to);
						String label = null;
						if (currentProgram.getSymbolTable().getPrimarySymbol(to) != null) {
							label = currentProgram.getSymbolTable().getPrimarySymbol(to).getName();
						}
						dataRefLines.add("    { \"from\": " + jsonString(hexAddr(from))
							+ ", \"fromFunction\": " + (fromFunc == null ? "null" : jsonString(fromFunc))
							+ ", \"to\": " + jsonString(hexAddr(to))
							+ ", \"toLabel\": " + (label == null ? "null" : jsonString(label))
							+ ", \"refType\": " + jsonString(rt.getName()) + " }");
					}
				}
			}
			out.println("  \"calls\": [");
			out.println(String.join(",\n", callLines));
			out.println("  ],");
			out.println("  \"dataReferences\": [");
			out.println(String.join(",\n", dataRefLines));
			out.println("  ],");

			// --- defined strings ---
			List<String> stringLines = new ArrayList<>();
			for (Data dd : listing.getDefinedData(true)) {
				if (monitor.isCancelled()) break;
				DataType dt = dd.getDataType();
				if (dd.hasStringValue()) {
					StringDataInstance sdi = StringDataInstance.getStringDataInstance(dd);
					String value = sdi == null ? dd.getDefaultValueRepresentation() : sdi.getStringValue();
					if (value == null) {
						value = "";
					}
					stringLines.add("    { \"address\": " + jsonString(hexAddr(dd.getAddress()))
						+ ", \"length\": " + dd.getLength()
						+ ", \"dataType\": " + jsonString(dt.getName())
						+ ", \"value\": " + jsonString(value) + " }");
				}
			}
			out.println("  \"strings\": [");
			out.println(String.join(",\n", stringLines));
			out.println("  ]");

			out.println("}");
		}

		println("APTraceExportStaticAnalysis: wrote " + outPath);
	}
}
