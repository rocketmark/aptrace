/* Native executable inventory and bounded function/CFG queries. No ISA decoder.
 * Args: output.json inventory|function|cfg address limit
 */
//@category APTrace
import java.io.FileWriter;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.block.*;

public class APTraceExecutableQuery extends GhidraScript {
    String hex(Address a) { return "0x" + a.toString(false); }
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length != 4) throw new IllegalArgumentException("output kind address limit required");
        int limit = Integer.parseInt(a[3]);
        if (limit < 1 || limit > 5000) throw new IllegalArgumentException("limit 1..5000");
        JsonObject out = new JsonObject();
        out.addProperty("format", currentProgram.getExecutableFormat());
        out.addProperty("language", currentProgram.getLanguageID().toString());
        out.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        out.addProperty("image_base", hex(currentProgram.getImageBase()));
        out.addProperty("input_sha256", currentProgram.getExecutableSHA256());
        out.addProperty("kind", a[1]);
        if (a[1].equals("inventory")) {
            JsonArray blocks = new JsonArray();
            for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
                JsonObject x = new JsonObject(); x.addProperty("name", b.getName());
                x.addProperty("start", hex(b.getStart())); x.addProperty("end", hex(b.getEnd()));
                x.addProperty("read", b.isRead()); x.addProperty("write", b.isWrite());
                x.addProperty("execute", b.isExecute()); blocks.add(x);
            }
            out.add("memory_blocks", blocks);
            JsonArray imports = new JsonArray();
            SymbolIterator symbols = currentProgram.getSymbolTable().getExternalSymbols();
            int count = 0;
            while (symbols.hasNext()) {
                Symbol s = symbols.next(); count++;
                if (imports.size() >= limit) continue;
                JsonObject x = new JsonObject(); x.addProperty("name", s.getName(true));
                x.addProperty("address", hex(s.getAddress())); imports.add(x);
            }
            out.add("imports", imports); out.addProperty("imports_total", count);
            out.addProperty("truncated", count > limit);
            JsonArray entries = new JsonArray();
            AddressIterator it = currentProgram.getSymbolTable().getExternalEntryPointIterator();
            int entryCount = 0;
            while (it.hasNext()) {
                Address p = it.next(); entryCount++;
                if (entries.size() < limit) entries.add(hex(p));
            }
            out.add("entry_points", entries); out.addProperty("entry_points_total", entryCount);
            if (entryCount > limit) out.addProperty("truncated", true);
        } else if (a[1].equals("data")) {
            Address start = toAddr(Long.parseUnsignedLong(a[2].replaceFirst("^0[xX]", ""), 16));
            JsonArray bytes = new JsonArray(); JsonArray refs = new JsonArray();
            for (int n = 0; n < limit; n++) {
                Address p = start.add(n);
                if (!currentProgram.getMemory().contains(p)) break;
                try { bytes.add(currentProgram.getMemory().getByte(p) & 255); }
                catch (MemoryAccessException e) { break; }
                for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(p)) {
                    JsonObject x = new JsonObject(); x.addProperty("from", hex(p));
                    x.addProperty("to", hex(r.getToAddress()));
                    x.addProperty("type", r.getReferenceType().toString()); refs.add(x);
                }
            }
            out.addProperty("start", hex(start)); out.add("bytes", bytes); out.add("references", refs);
            out.addProperty("bytes_returned", bytes.size());
            out.addProperty("scope", "requested byte window only; not an exhaustive data inventory");
        } else {
            Address addr = toAddr(Long.parseUnsignedLong(a[2].replaceFirst("^0[xX]", ""), 16));
            Function f = currentProgram.getFunctionManager().getFunctionContaining(addr);
            if (a[1].equals("entry-function")) {
                MemoryBlock block = currentProgram.getMemory().getBlock(addr);
                if (block == null || !block.isExecute())
                    throw new IllegalArgumentException("entry must be in executable memory");
                if (f != null && !f.getEntryPoint().equals(addr))
                    throw new IllegalArgumentException("entry overlaps an attributed function");
                if (f == null) {
                    disassemble(addr);
                    f = createFunction(addr, null);
                }
                out.addProperty("analysis_requested", "native disassembly/function creation at explicit entry; read-only project, transient analysis");
            }
            if (f == null) {
                out.addProperty("status", "function_not_attributed");
            } else {
                out.addProperty("status", "observed");
                out.addProperty("function", f.getName()); out.addProperty("entry", hex(f.getEntryPoint()));
                out.addProperty("calling_convention", f.getCallingConventionName());
                JsonArray ranges = new JsonArray();
                for (AddressRange r : f.getBody()) {
                    JsonObject x = new JsonObject(); x.addProperty("start", hex(r.getMinAddress()));
                    x.addProperty("end", hex(r.getMaxAddress())); ranges.add(x);
                }
                out.add("body_ranges", ranges);
                if (a[1].equals("function") || a[1].equals("entry-function")) {
                    DecompInterface d = new DecompInterface();
                    try {
                        d.openProgram(currentProgram);
                        DecompileResults r = d.decompileFunction(f, 30, monitor);
                        out.addProperty("decompile_completed", r.decompileCompleted());
                        out.addProperty("decompile_error", r.getErrorMessage());
                        if (r.decompileCompleted() && r.getDecompiledFunction() != null) {
                            String c = r.getDecompiledFunction().getC(); int max = limit * 120;
                            out.addProperty("decompiled_c", c.substring(0, Math.min(c.length(), max)));
                            out.addProperty("decompile_truncated", c.length() > max);
                        }
                    } finally { d.dispose(); }
                    JsonArray ins = new JsonArray(); int total = 0;
                    InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
                    while (ii.hasNext()) {
                        Instruction i = ii.next(); total++;
                        if (ins.size() >= limit) continue;
                        JsonObject x = new JsonObject(); x.addProperty("address", hex(i.getAddress()));
                        x.addProperty("text", i.toString()); ins.add(x);
                    }
                    out.add("instructions", ins); out.addProperty("instructions_total", total);
                    out.addProperty("truncated", total > limit);
                } else if (a[1].equals("cfg")) {
                    JsonArray edges = new JsonArray(); int total = 0;
                    BasicBlockModel model = new BasicBlockModel(currentProgram);
                    CodeBlockIterator bi = model.getCodeBlocksContaining(f.getBody(), monitor);
                    while (bi.hasNext()) {
                        CodeBlock b = bi.next();
                        CodeBlockReferenceIterator ei = b.getDestinations(monitor);
                        while (ei.hasNext()) {
                            CodeBlockReference e = ei.next(); total++;
                            if (edges.size() >= limit) continue;
                            JsonObject x = new JsonObject(); x.addProperty("from", hex(e.getReferent()));
                            x.addProperty("to", hex(e.getDestinationAddress()));
                            x.addProperty("flow", e.getFlowType().toString());
                            x.addProperty("computed", e.getFlowType().isComputed()); edges.add(x);
                        }
                    }
                    out.add("edges", edges); out.addProperty("edges_total", total);
                    out.addProperty("truncated", total > limit);
                } else throw new IllegalArgumentException("unsupported query kind");
            }
        }
        try (FileWriter w = new FileWriter(a[0])) {
            new GsonBuilder().setPrettyPrinting().create().toJson(out, w);
        }
    }
}
