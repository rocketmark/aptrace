// SPIKE ONLY (architecture evaluation). Not production code.
//
// Forward use classification of ONE value defined by ONE instruction,
// computed two ways from Ghidra's own semantics:
//
//   raw   -- a small worklist over Ghidra's raw (SLEIGH) p-code, instruction
//            flows and the program's calling-convention model (argument,
//            return and unaffected storage). No ISA-specific code here: the
//            same script runs on any SLEIGH language.
//   high  -- the decompiler's SSA (HighFunction) and DecompilerUtils'
//            forward slice from the instruction's output varnode.
//
// Args: OUT_JSON  DEF_ADDR[@FUNC_ENTRY][,DEF_ADDR[@FUNC_ENTRY]...]  [CREATE]
//   DEF_ADDR    instruction whose (single) register output is tracked
//   FUNC_ENTRY  function to create/disassemble first (fixtures only)
//   CREATE      "create": disassemble+create functions at FUNC_ENTRY
//
//@category APTrace.Spike
import java.io.*;
import java.util.*;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.FlowType;

public class PointerUseProbe extends GhidraScript {

    static final int MAX_STATES = 20000;

    PrototypeModel cc;
    List<Varnode> argStorage = new ArrayList<>();
    List<Varnode> unaffected = new ArrayList<>();
    Varnode retStorage;
    Varnode spReg;

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String out = a[0];
        boolean create = a.length > 2 && a[2].equals("create");
        if (a.length > 3) targetConst = Long.decode(a[3]);
        if (a.length > 4) memWord = toAddr(a[4]);
        cc = currentProgram.getCompilerSpec().getDefaultCallingConvention();
        for (VariableStorage s : cc.getPotentialInputRegisterStorage(currentProgram)) {
            for (Varnode v : s.getVarnodes()) argStorage.add(v);
        }
        for (Varnode v : cc.getUnaffectedList()) unaffected.add(v);
        VariableStorage r = cc.getReturnLocation(PointerDataType.dataType, currentProgram);
        retStorage = r.getVarnodes().length > 0 ? r.getVarnodes()[0] : null;
        Register sp = currentProgram.getCompilerSpec().getStackPointer();
        spReg = new Varnode(sp.getAddress(), sp.getMinimumByteSize());

        StringBuilder js = new StringBuilder();
        js.append("{\"language\":\"").append(currentProgram.getLanguageID()).append("\",");
        js.append("\"ghidra\":\"").append(ghidra.framework.Application.getApplicationVersion()).append("\",");
        js.append("\"calling_convention\":\"").append(cc.getName()).append("\",");
        js.append("\"arg_storage\":").append(vnList(argStorage)).append(",");
        js.append("\"return_storage\":\"").append(vn(retStorage)).append("\",");
        js.append("\"probes\":[");
        boolean first = true;
        for (String spec : a[1].split(",")) {
            String[] p = spec.split("@");
            Address def = toAddr(p[0]);
            if (create && p.length > 1) {
                Address ent = toAddr(p[1]);
                new DisassembleCommand(ent, null, true).applyTo(currentProgram, monitor);
                if (getFunctionAt(ent) == null) new CreateFunctionCmd(ent).applyTo(currentProgram, monitor);
            }
            if (!first) js.append(",");
            first = false;
            js.append(probe(def));
        }
        js.append("]}");
        try (Writer w = new FileWriter(out)) { w.write(js.toString()); }
        println("wrote " + out);
    }

    String probe(Address def) throws Exception {
        Instruction insn = getInstructionAt(def);
        StringBuilder js = new StringBuilder("{\"def_addr\":\"" + def + "\",");
        if (insn == null) return js.append("\"error\":\"no instruction\"}").toString();
        js.append("\"def_instruction\":\"").append(esc(insn.toString())).append("\",");
        Varnode tracked = null;
        for (PcodeOp op : insn.getPcode()) {
            Varnode o = op.getOutput();
            if (o != null && o.isRegister()) tracked = o;
        }
        js.append("\"tracked\":\"").append(vn(tracked)).append("\",");
        long t0 = System.nanoTime();
        js.append("\"raw\":").append(rawForward(insn, tracked)).append(",");
        long t1 = System.nanoTime();
        js.append("\"raw_ms\":").append((t1 - t0) / 1000000).append(",");
        js.append("\"high\":").append(highForward(def));
        js.append(",\"high_ms\":").append((System.nanoTime() - t1) / 1000000);
        return js.append("}").toString();
    }

    // ---- raw p-code forward walk ----------------------------------------

    static final class State {
        final Address at; final Set<Varnode> live;
        State(Address at, Set<Varnode> live) { this.at = at; this.live = live; }
        String key() { List<String> l = new ArrayList<>(); for (Varnode v : live) l.add(v.toString()); Collections.sort(l); return at + "|" + l; }
    }

    boolean overlapsAny(Varnode v, Collection<Varnode> set) {
        for (Varnode s : set) if (s.intersects(v)) return true;
        return false;
    }

    String rawForward(Instruction defInsn, Varnode tracked) {
        List<String> uses = new ArrayList<>();
        List<String> incomplete = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Deque<State> work = new ArrayDeque<>();
        Function fn = getFunctionContaining(defInsn.getAddress());
        // Without a containing function there is no boundary at which a
        // tail transfer can be recognized: report that, never "no uses".
        if (fn == null) incomplete.add("definition is not inside a known function; tail transfers cannot be recognized");
        // Seed: state after the defining instruction.
        Set<Varnode> init = new HashSet<>();
        init.add(tracked);
        for (Address s : successors(defInsn, incomplete)) work.add(new State(s, init));
        int states = 0;
        int instructions = 0;
        while (!work.isEmpty()) {
            State st = work.pop();
            if (st.live.isEmpty()) continue;
            if (!seen.add(st.key())) continue;
            if (++states > MAX_STATES) { incomplete.add("state bound " + MAX_STATES); break; }
            Instruction insn = getInstructionAt(st.at);
            if (insn == null) { incomplete.add("no instruction at " + st.at); continue; }
            instructions++;
            if (fn != null && !fn.getBody().contains(st.at)) {
                // Fell or branched out of the function body: a tail transfer.
                if (anyOverlap(argList(), st.live)) uses.add(use("ARGUMENT", insn, "tail transfer out of " + fn.getName() + " with value in argument storage"));
                else uses.add(use("LEAVES_FUNCTION", insn, "flow leaves the function; value not in argument storage"));
                continue;
            }
            Set<Varnode> live = new HashSet<>(st.live);
            boolean terminated = false;
            // An internal CBRANCH (relative p-code target, or to the
            // fall-through) makes every later write in this instruction
            // conditional: it may add a copy but must not kill one.
            boolean conditional = false;
            for (PcodeOp op : insn.getPcode()) {
                if (op.getOpcode() == PcodeOp.CBRANCH && (op.getInput(0).isConstant()
                        || op.getInput(0).getAddress().equals(insn.getFallThrough()))) conditional = true;
                int opc = op.getOpcode();
                boolean in0 = op.getNumInputs() > 0 && live.contains(op.getInput(0));
                boolean anyIn = false;
                for (Varnode i : op.getInputs()) if (live.contains(i)) anyIn = true;
                switch (opc) {
                    case PcodeOp.STORE:
                        if (op.getNumInputs() > 2 && live.contains(op.getInput(2)))
                            uses.add(use("STORE", insn, live.contains(op.getInput(1)) ? "value and address" : "value stored to memory"));
                        else if (live.contains(op.getInput(1)))
                            uses.add(use("DEREFERENCE_STORE", insn, "used as a store address"));
                        break;
                    case PcodeOp.LOAD:
                        if (live.contains(op.getInput(1))) uses.add(use("DEREFERENCE_LOAD", insn, "used as a load address"));
                        break;
                    case PcodeOp.BRANCHIND:
                    case PcodeOp.CALLIND:
                        if (in0) uses.add(use("CONTROL_TRANSFER", insn, PcodeOp.getMnemonic(opc)));
                        if (opc == PcodeOp.CALLIND) {
                            if (anyOverlap(argList(), live)) uses.add(use("ARGUMENT", insn, "live in argument storage at indirect call"));
                            killCallClobbered(live);
                        } else { terminated = true; incomplete.add("computed jump at " + insn.getAddress()); }
                        break;
                    case PcodeOp.CALL:
                        if (anyOverlap(argList(), live)) uses.add(use("ARGUMENT", insn, "live in argument storage at call to " + op.getInput(0).getAddress()));
                        killCallClobbered(live);
                        break;
                    case PcodeOp.RETURN:
                        if (in0) uses.add(use("CONTROL_TRANSFER", insn, "RETURN target"));
                        if (retStorage != null && anyOverlap(List.of(retStorage), live)) uses.add(use("RETURN_VALUE", insn, "live in return storage at return"));
                        terminated = true;
                        break;
                    case PcodeOp.INT_EQUAL: case PcodeOp.INT_NOTEQUAL: case PcodeOp.INT_LESS: case PcodeOp.INT_SLESS:
                    case PcodeOp.INT_LESSEQUAL: case PcodeOp.INT_SLESSEQUAL: case PcodeOp.INT_CARRY: case PcodeOp.INT_SCARRY:
                    case PcodeOp.INT_SBORROW:
                        if (anyIn) uses.add(use("COMPARE", insn, PcodeOp.getMnemonic(opc)));
                        break;
                    default:
                        break;
                }
                Varnode o = op.getOutput();
                if (o != null) {
                    // Kill every tracked varnode the output overwrites, then
                    // propagate through value-preserving/arithmetic ops.
                    if (!conditional) live.removeIf(v -> v.intersects(o));
                    if (anyIn && propagates(opc)) live.add(o);
                }
            }
            // Instruction-local temporaries do not survive the instruction.
            live.removeIf(v -> v.isUnique());
            if (terminated || live.isEmpty()) {
                if (live.isEmpty() && !terminated) uses.add(use("DEAD", insn, "every tracked copy overwritten"));
                continue;
            }
            for (Address s : successors(insn, incomplete)) work.add(new State(s, live));
        }
        Set<String> kinds = new TreeSet<>();
        for (String u : uses) kinds.add(u.replaceAll(".*\"kind\":\"([A-Z_]+)\".*", "$1"));
        Set<String> uniq = new LinkedHashSet<>(uses);
        return "{\"instructions_visited\":" + instructions + ",\"states\":" + states + ",\"complete\":" + incomplete.isEmpty()
                + ",\"incomplete\":" + strList(incomplete) + ",\"use_kinds\":" + strList(new ArrayList<>(kinds))
                + ",\"uses\":[" + String.join(",", uniq) + "]}";
    }

    List<Varnode> argList() { return argStorage; }

    static boolean anyOverlap(List<Varnode> a, Collection<Varnode> b) {
        for (Varnode x : a) for (Varnode y : b) if (x.intersects(y)) return true;
        return false;
    }

    void killCallClobbered(Set<Varnode> live) {
        live.removeIf(v -> v.isRegister() && !overlapsAny(v, unaffected));
    }

    static boolean overlapsAny(Varnode v, List<Varnode> l) {
        for (Varnode s : l) if (s.intersects(v)) return true;
        return false;
    }

    static boolean propagates(int opc) {
        switch (opc) {
            case PcodeOp.COPY: case PcodeOp.INT_ADD: case PcodeOp.INT_SUB: case PcodeOp.INT_AND: case PcodeOp.INT_OR:
            case PcodeOp.INT_XOR: case PcodeOp.INT_ZEXT: case PcodeOp.INT_SEXT: case PcodeOp.SUBPIECE: case PcodeOp.PIECE:
            case PcodeOp.PTRADD: case PcodeOp.PTRSUB: case PcodeOp.CAST: case PcodeOp.MULTIEQUAL: case PcodeOp.INDIRECT:
            case PcodeOp.INT_LEFT: case PcodeOp.INT_RIGHT: case PcodeOp.INT_SRIGHT:
                return true;
            default:
                return false;
        }
    }

    List<Address> successors(Instruction insn, List<String> incomplete) {
        List<Address> out = new ArrayList<>();
        FlowType ft = insn.getFlowType();
        Address[] flows = insn.getFlows();
        if (!ft.isCall() && flows != null) out.addAll(Arrays.asList(flows));
        if (ft.isComputed() && !ft.isCall() && !ft.isTerminal() && (flows == null || flows.length == 0))
            incomplete.add("unresolved computed flow at " + insn.getAddress());
        if (insn.getFallThrough() != null) out.add(insn.getFallThrough());
        return out;
    }

    String use(String kind, Instruction insn, String detail) {
        return "{\"kind\":\"" + kind + "\",\"addr\":\"" + insn.getAddress() + "\",\"instruction\":\"" + esc(insn.toString())
                + "\",\"detail\":\"" + esc(detail) + "\"}";
    }

    // ---- decompiler SSA forward slice -----------------------------------

    String highForward(Address def) {
        Function fn = getFunctionContaining(def);
        if (fn == null) return "{\"error\":\"no function\"}";
        memWord = null;
        for (PcodeOp op : getInstructionAt(def).getPcode())
            if (op.getOpcode() == PcodeOp.LOAD && op.getInput(1).isConstant()) memWord = toAddr(op.getInput(1).getOffset());
            else for (Varnode in : op.getInputs()) if (in.isAddress()) memWord = in.getAddress();
        DecompInterface ifc = new DecompInterface();
        try {
            ifc.openProgram(currentProgram);
            DecompileResults res = ifc.decompileFunction(fn, 120, monitor);
            HighFunction hf = res.getHighFunction();
            if (hf == null) return "{\"error\":\"" + esc(res.getErrorMessage()) + "\"}";
            List<String> defs = new ArrayList<>();
            List<String> slice = new ArrayList<>();
            Iterator<PcodeOpAST> it = hf.getPcodeOps(def);
            Set<PcodeOp> all = new LinkedHashSet<>();
            while (it.hasNext()) {
                PcodeOpAST op = it.next();
                defs.add("\"" + esc(op.toString()) + "\"");
                if (op.getOutput() != null) all.addAll(DecompilerUtils.getForwardSliceToPCodeOps(op.getOutput()));
            }
            // Also: is the loaded constant visible anywhere as a constant input?
            List<String> constUses = new ArrayList<>();
            Iterator<PcodeOpAST> every = hf.getPcodeOps();
            while (every.hasNext()) {
                PcodeOpAST op = every.next();
                for (Varnode v : op.getInputs()) {
                    if (memWord != null && v.getAddress().equals(memWord)) {
                        constUses.add("\"memvar " + esc(op.getSeqnum().getTarget() + " " + op) + "\"");
                        for (PcodeOp d : DecompilerUtils.getForwardSliceToPCodeOps(v)) slice.add("\"" + esc(d.getSeqnum().getTarget() + " " + d) + "\"");
                    }
                    if (v.isConstant() && targetConst != 0 && (v.getOffset() == targetConst || v.getOffset() == (targetConst & ~1L))) constUses.add("\"" + esc(op.getSeqnum().getTarget() + " " + op) + "\"");
                }
            }
            for (PcodeOp op : all) slice.add("\"" + esc(op.getSeqnum().getTarget() + " " + op) + "\"");
            String c = res.getDecompiledFunction() != null ? res.getDecompiledFunction().getC() : "";
            String snippet = "";
            for (String line : c.split("\n")) if (line.contains("ec48") || line.contains("eafc") || line.contains("ec49")) snippet += line.trim() + " | ";
            if (slice.isEmpty()) snippet = c;
            return "{\"mem_word\":\"" + memWord + "\",\"ops_at_def\":[" + String.join(",", defs) + "],\"forward_slice\":[" + String.join(",", slice)
                    + "],\"constant_uses\":[" + String.join(",", constUses) + "],\"c_lines\":\"" + esc(snippet) + "\"}";
        } finally {
            ifc.dispose();
        }
    }

    long targetConst = 0;
    Address memWord = null;

    static String vn(Varnode v) { return v == null ? "null" : esc(v.toString()); }
    static String vnList(List<Varnode> l) { List<String> s = new ArrayList<>(); for (Varnode v : l) s.add("\"" + vn(v) + "\""); return "[" + String.join(",", s) + "]"; }
    static String strList(List<String> l) { List<String> s = new ArrayList<>(); for (String v : l) s.add("\"" + esc(v) + "\""); return "[" + String.join(",", s) + "]"; }
    static String esc(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " "); }
}
