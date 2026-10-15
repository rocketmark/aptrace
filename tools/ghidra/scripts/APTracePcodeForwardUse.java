/* APTrace: forward use of ONE value defined by ONE instruction, over
 * Ghidra's raw (SLEIGH) p-code.
 *
 * Instruction semantics come only from the program's SLEIGH language and
 * calling conventions from its compiler spec (cspec). This script contains
 * no ISA-specific code: it reads p-code opcodes, varnodes, the language's
 * program counter, the cspec's stack pointer and its default prototype
 * model (argument, return, unaffected storage). The same script runs on any
 * SLEIGH language without delay slots.
 *
 * The analysis is a monotone may-dataflow over the containing function's
 * instructions: the state at an instruction is the set of storage locations
 * (registers, instruction-local temporaries) that may hold the tracked value.
 * Within an instruction the p-code is interpreted op by op, so an internal
 * conditional branch (e.g. predication lowered by SLEIGH) kills a copy only
 * on the path that executes the write. Gen/kill transfer is distributive, so
 * the fixpoint equals the union over paths. A second pass over the fixpoint
 * states records uses, kills and derivation steps.
 *
 * Every condition under which uses could be missed is reported as an
 * incompleteness reason with a code; this script never turns a missing
 * function, edge, instruction, unmodeled operation or exhausted budget into
 * "no uses". Classification into escape kinds and the overall verdict are
 * APTrace policy (tools/ghidra/pcode_forward_use.py), not done here.
 *
 * Program mutation: code seeds and functions listed in the request are
 * disassembled and created first (import-mode fixtures only). The driver runs this script with
 * -deleteProject (import) or -readOnly on a scratch copy (project), so
 * nothing is persisted either way.
 *
 * Script args: <request.json> <output.json>
 */
//@category APTrace

import java.io.FileReader;
import java.io.FileWriter;
import java.io.Reader;
import java.io.Writer;
import java.util.*;

import com.google.gson.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;

public class APTracePcodeForwardUse extends GhidraScript {

	static final String WALKER = "aptrace-pcode-forward-use";
	static final int WALKER_VERSION = 1;
	static final int DEFAULT_MAX_STEPS = 20000;
	// Per-instruction p-code path states; only a pathological p-code loop
	// reaches it, and it is reported, never silently truncated.
	static final int MAX_PCODE_STATES = 4096;
	static final int MAX_DERIVATION_STEPS = 512;

	Language language;
	PrototypeModel convention;
	List<Varnode> argumentStorage = new ArrayList<>();
	List<Varnode> unaffected = new ArrayList<>();
	Varnode returnStorage;
	Varnode stackPointer;

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length != 2) throw new IllegalArgumentException("usage: <request.json> <output.json>");
		JsonObject request;
		try (Reader r = new FileReader(args[0])) {
			request = JsonParser.parseReader(r).getAsJsonObject();
		}

		language = currentProgram.getLanguage();
		CompilerSpec cspec = currentProgram.getCompilerSpec();
		convention = cspec.getDefaultCallingConvention();
		for (VariableStorage s : convention.getPotentialInputRegisterStorage(currentProgram))
			argumentStorage.addAll(Arrays.asList(s.getVarnodes()));
		unaffected.addAll(Arrays.asList(convention.getUnaffectedList()));
		VariableStorage ret = convention.getReturnLocation(PointerDataType.dataType, currentProgram);
		returnStorage = ret != null && ret.getVarnodes().length > 0 ? ret.getVarnodes()[0] : null;
		Register stackRegister = cspec.getStackPointer();
		stackPointer = stackRegister == null ? null : new Varnode(stackRegister.getAddress(), stackRegister.getMinimumByteSize());

		JsonObject out = new JsonObject();
		out.addProperty("walker", WALKER);
		out.addProperty("walker_version", WALKER_VERSION);
		out.add("engine", engineIdentity(cspec));
		out.add("program", programIdentity());

		JsonArray created = new JsonArray();
		if (request.has("disassemble")) {
			for (JsonElement e : request.getAsJsonArray("disassemble")) {
				Address at = toAddr(Long.decode(e.getAsString()));
				new DisassembleCommand(at, null, true).applyTo(currentProgram, monitor);
			}
		}
		if (request.has("functions")) {
			for (JsonElement e : request.getAsJsonArray("functions")) created.add(createFunction(e.getAsJsonObject()));
		}
		out.add("functions_created", created);

		int maxSteps = request.has("max_steps") ? request.get("max_steps").getAsInt() : DEFAULT_MAX_STEPS;
		out.addProperty("max_steps", maxSteps);
		JsonArray results = new JsonArray();
		long started = System.nanoTime();
		for (JsonElement e : request.getAsJsonArray("origins")) {
			JsonObject o = e.getAsJsonObject();
			String reg = o.has("register") && !o.get("register").isJsonNull() ? o.get("register").getAsString() : null;
			results.add(analyze(toAddr(Long.decode(o.get("address").getAsString())), reg, maxSteps));
		}
		out.add("results", results);
		// Wall time inside the script; not part of the deterministic result.
		out.addProperty("timing_analysis_ms", (System.nanoTime() - started) / 1_000_000.0);
		out.addProperty("complete_output", true);
		try (Writer w = new FileWriter(args[1])) {
			new GsonBuilder().disableHtmlEscaping().serializeNulls().setPrettyPrinting().create().toJson(out, w);
		}
	}

	// ---- identity ---------------------------------------------------------

	JsonObject engineIdentity(CompilerSpec cspec) {
		JsonObject e = new JsonObject();
		e.addProperty("name", "ghidra");
		e.addProperty("version", Application.getApplicationVersion());
		e.addProperty("language_id", language.getLanguageID().getIdAsString());
		e.addProperty("language_version", language.getVersion() + "." + language.getMinorVersion());
		e.addProperty("compiler_spec_id", cspec.getCompilerSpecID().getIdAsString());
		e.addProperty("calling_convention", convention.getName());
		e.addProperty("pointer_size", currentProgram.getDefaultPointerSize());
		e.addProperty("low_bit_code_mode", PseudoDisassembler.hasLowBitCodeModeInAddrValues(currentProgram));
		e.addProperty("program_counter", language.getProgramCounter().getName());
		e.addProperty("stack_pointer", cspec.getStackPointer() == null ? null : cspec.getStackPointer().getName());
		e.add("argument_storage", names(argumentStorage));
		e.addProperty("return_storage", returnStorage == null ? null : name(returnStorage));
		e.add("unaffected_storage", names(unaffected));
		return e;
	}

	JsonObject programIdentity() {
		JsonObject p = new JsonObject();
		p.addProperty("executable_sha256", currentProgram.getExecutableSHA256());
		p.addProperty("image_base", hex(currentProgram.getImageBase()));
		JsonArray blocks = new JsonArray();
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			JsonObject j = new JsonObject();
			j.addProperty("name", b.getName());
			j.addProperty("start", hex(b.getStart()));
			j.addProperty("end", hex(b.getEnd()));
			j.addProperty("permissions", (b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-"));
			j.addProperty("initialized", b.isInitialized());
			blocks.add(j);
		}
		p.add("memory_blocks", blocks);
		p.addProperty("function_count", currentProgram.getFunctionManager().getFunctionCount());
		return p;
	}

	JsonObject createFunction(JsonObject spec) throws Exception {
		Address entry = toAddr(Long.decode(spec.get("entry").getAsString()));
		AddressSet body = null;
		if (spec.has("body")) {
			body = new AddressSet();
			for (JsonElement r : spec.getAsJsonArray("body")) {
				JsonArray range = r.getAsJsonArray();
				Address lo = toAddr(Long.decode(range.get(0).getAsString()));
				Address hi = toAddr(Long.decode(range.get(1).getAsString()));
				body.add(lo, hi);
				new DisassembleCommand(lo, new AddressSet(lo, hi), true).applyTo(currentProgram, monitor);
			}
		} else {
			new DisassembleCommand(entry, null, true).applyTo(currentProgram, monitor);
		}
		if (getFunctionAt(entry) == null) {
			CreateFunctionCmd cmd = body == null ? new CreateFunctionCmd(entry)
					: new CreateFunctionCmd(null, entry, body, SourceType.USER_DEFINED);
			cmd.applyTo(currentProgram, monitor);
		}
		Function f = getFunctionAt(entry);
		JsonObject j = new JsonObject();
		j.addProperty("entry", hex(entry));
		j.addProperty("created", f != null);
		if (f != null) j.add("body", ranges(f.getBody()));
		return j;
	}

	// ---- one origin -------------------------------------------------------

	JsonObject analyze(Address origin, String registerName, int maxSteps) {
		JsonObject r = new JsonObject();
		r.addProperty("origin_address", hex(origin));
		Instruction def = getInstructionAt(origin);
		if (def == null) return unsupported(r, "NO_INSTRUCTION", "no instruction is defined at the origin address");
		r.addProperty("origin_instruction", def.toString());

		Varnode tracked;
		if (registerName != null) {
			Register reg = currentProgram.getRegister(registerName);
			if (reg == null) return unsupported(r, "UNKNOWN_REGISTER", "the language has no register " + registerName);
			tracked = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
			if (!writes(def, tracked)) return unsupported(r, "REGISTER_NOT_WRITTEN", "the origin instruction does not write " + registerName);
		} else {
			List<Varnode> candidates = valueOutputs(def);
			if (candidates.size() != 1) {
				return unsupported(r, candidates.isEmpty() ? "NO_VALUE_OUTPUT" : "AMBIGUOUS_VALUE_OUTPUT",
					"the origin instruction writes " + candidates.size() + " pointer-sized registers " + names(candidates)
						+ "; name the register to track");
			}
			tracked = candidates.get(0);
		}
		JsonObject t = new JsonObject();
		t.addProperty("storage", name(tracked));
		t.addProperty("varnode", tracked.toString());
		r.add("tracked", t);
		r.add("origin_value", originValue(def, tracked));

		Function fn = getFunctionContaining(origin);
		JsonObject scope = new JsonObject();
		if (fn != null) {
			scope.addProperty("kind", "function");
			scope.addProperty("function_entry", hex(fn.getEntryPoint()));
			scope.addProperty("function_name", fn.getName());
			scope.add("body", ranges(fn.getBody()));
			scope.addProperty("body_bytes", fn.getBody().getNumAddresses());
		} else {
			scope.addProperty("kind", "none");
		}
		r.add("scope", scope);

		Walk w = new Walk(fn, origin, tracked, maxSteps);
		w.run();
		r.addProperty("status", "analyzed");
		r.add("uses", w.usesJson());
		r.add("kills", w.killsJson());
		r.add("derivation", w.derivationJson());
		r.add("incomplete", w.incompleteJson());
		r.add("assumptions", w.assumptionsJson());
		JsonObject work = new JsonObject();
		work.addProperty("steps", w.steps);
		work.addProperty("max_steps", maxSteps);
		work.addProperty("instructions", w.in.size());
		work.addProperty("budget_exhausted", w.budgetExhausted);
		r.add("work", work);
		return r;
	}

	JsonObject unsupported(JsonObject r, String code, String detail) {
		r.addProperty("status", "unsupported");
		r.addProperty("unsupported_code", code);
		r.addProperty("unsupported_detail", detail);
		return r;
	}

	boolean writes(Instruction insn, Varnode v) {
		for (PcodeOp op : insn.getPcode(false)) {
			Varnode o = op.getOutput();
			if (o != null && covers(o, v)) return true;
		}
		return false;
	}

	/** Pointer-sized registers the instruction writes, other than the PC and SP. */
	List<Varnode> valueOutputs(Instruction insn) {
		int size = currentProgram.getDefaultPointerSize();
		Register programCounter = language.getProgramCounter();
		Set<Varnode> seen = new LinkedHashSet<>();
		for (PcodeOp op : insn.getPcode(false)) {
			Varnode o = op.getOutput();
			if (o == null || !o.isRegister() || o.getSize() != size) continue;
			if (programCounter != null && o.getAddress().equals(programCounter.getAddress())) continue;
			if (stackPointer != null && o.intersects(stackPointer)) continue;
			seen.add(o);
		}
		return new ArrayList<>(seen);
	}

	/** What the origin instruction stores into the tracked location, when the p-code says so directly. */
	JsonObject originValue(Instruction def, Varnode tracked) {
		JsonObject v = new JsonObject();
		v.addProperty("kind", "computed");
		Map<Varnode, PcodeOp> defs = new HashMap<>();
		PcodeOp last = null;
		for (PcodeOp op : def.getPcode(false)) {
			if (op.getOutput() != null) defs.put(op.getOutput(), op);
			if (op.getOutput() != null && covers(op.getOutput(), tracked)) last = op;
		}
		// Follow COPYs back to the op that produced the value: a constant, a
		// direct memory varnode, or a LOAD from a constant address.
		Address src = null;
		int size = 0;
		PcodeOp op = last;
		for (int i = 0; op != null && i < 8; i++) {
			if (op.getOpcode() == PcodeOp.COPY) {
				Varnode in = op.getInput(0);
				if (in.isConstant()) {
					v.addProperty("kind", "constant");
					addValue(v, in.getOffset(), in.getSize());
					return v;
				}
				if (in.isAddress()) {
					src = in.getAddress();
					size = in.getSize();
					break;
				}
				op = defs.get(in);
			} else {
				if (op.getOpcode() == PcodeOp.LOAD && op.getInput(1).isConstant()) {
					AddressSpace space = currentProgram.getAddressFactory().getAddressSpace((int) op.getInput(0).getOffset());
					src = space.getAddress(op.getInput(1).getOffset());
					size = op.getOutput().getSize();
				}
				break;
			}
		}
		if (src != null) {
			v.addProperty("kind", "load");
			v.addProperty("source_address", hex(src));
			v.addProperty("size", size);
			MemoryBlock b = currentProgram.getMemory().getBlock(src);
			if (b != null) {
				v.addProperty("source_block", b.getName());
				v.addProperty("source_block_writable", b.isWrite());
				v.addProperty("source_initialized", b.isInitialized());
			}
			try {
				byte[] bytes = new byte[size];
				if (b != null && b.isInitialized() && currentProgram.getMemory().getBytes(src, bytes) == size) {
					long value = 0;
					boolean big = language.isBigEndian();
					for (int i = 0; i < size; i++) {
						int k = big ? i : size - 1 - i;
						value = (value << 8) | (bytes[k] & 0xff);
					}
					addValue(v, value, size);
				}
			} catch (Exception e) {
				v.addProperty("value_error", e.getMessage());
			}
		}
		return v;
	}

	/** The image-time value, and where Ghidra's language would disassemble it as code. */
	void addValue(JsonObject v, long value, int size) {
		v.addProperty("value", String.format("0x%0" + (size * 2) + "x", value));
		try {
			Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
			Address code = PseudoDisassembler.getNormalizedDisassemblyAddress(currentProgram, a);
			v.addProperty("code_address", hex(code));
			Function f = getFunctionAt(code);
			v.addProperty("function_at_code_address", f == null ? null : f.getName());
		} catch (Exception e) {
			v.addProperty("code_address", (String) null);
		}
	}

	// ---- the walk ---------------------------------------------------------

	final class Walk {
		final Function fn;
		final AddressSetView body;
		final Address origin;
		final Varnode tracked;
		final int maxSteps;
		final Map<Address, Set<Varnode>> in = new HashMap<>();
		int steps = 0;
		boolean budgetExhausted = false;
		boolean recording = false;

		final TreeMap<String, JsonObject> uses = new TreeMap<>();
		final TreeMap<String, JsonObject> kills = new TreeMap<>();
		final TreeMap<String, JsonObject> derivation = new TreeMap<>();
		final TreeMap<String, JsonObject> incomplete = new TreeMap<>();
		final TreeSet<String> assumptions = new TreeSet<>();

		Walk(Function fn, Address origin, Varnode tracked, int maxSteps) {
			this.fn = fn;
			this.body = fn == null ? null : fn.getBody();
			this.origin = origin;
			this.tracked = tracked;
			this.maxSteps = maxSteps;
		}

		void run() {
			if (fn == null) {
				incomplete("NO_CONTAINING_FUNCTION", origin, "the origin is not inside a known function: no body bounds "
					+ "the analysis, so a flow out of the function cannot be told from a tail transfer");
			}
			// Phase 1: fixpoint of may-hold sets.
			TreeSet<Address> work = new TreeSet<>();
			for (Map.Entry<Address, Set<Varnode>> e : transfer(getInstructionAt(origin), new HashSet<>(), true).entrySet()) {
				if (merge(e.getKey(), e.getValue())) work.add(e.getKey());
			}
			while (!work.isEmpty()) {
				if (steps >= maxSteps) {
					budgetExhausted = true;
					incomplete("BUDGET_EXHAUSTED", null, "step budget " + maxSteps + " exhausted with " + work.size()
						+ " instruction(s) pending");
					break;
				}
				steps++;
				Address a = work.pollFirst();
				Instruction insn = getInstructionAt(a);
				if (insn == null) continue;
				for (Map.Entry<Address, Set<Varnode>> e : transfer(insn, in.get(a), a.equals(origin)).entrySet()) {
					if (merge(e.getKey(), e.getValue())) work.add(e.getKey());
				}
			}
			// Phase 2: record from the final states.
			recording = true;
			transfer(getInstructionAt(origin), new HashSet<>(in.getOrDefault(origin, Set.of())), true);
			for (Address a : new TreeSet<>(in.keySet())) {
				if (a.equals(origin)) continue;
				Instruction insn = getInstructionAt(a);
				if (insn == null) {
					incomplete("NO_INSTRUCTION", a, "flow reaches an address with no instruction");
					continue;
				}
				transfer(insn, in.get(a), false);
			}
		}

		boolean merge(Address a, Set<Varnode> live) {
			Set<Varnode> cur = in.get(a);
			if (cur == null) {
				in.put(a, new HashSet<>(live));
				return true;
			}
			return cur.addAll(live);
		}

		/** One instruction's p-code from a state; returns the in-scope successor states. */
		Map<Address, Set<Varnode>> transfer(Instruction insn, Set<Varnode> liveIn, boolean isOrigin) {
			Map<Address, Set<Varnode>> exits = new TreeMap<>();
			if (insn.getDelaySlotDepth() > 0) {
				incomplete("DELAY_SLOT_UNSUPPORTED", insn.getAddress(), "instructions with delay slots are not modeled");
				return exits;
			}
			PcodeOp[] ops = insn.getPcode(false);
			Deque<Object[]> q = new ArrayDeque<>();
			Set<String> seen = new HashSet<>();
			q.push(new Object[] { 0, new HashSet<>(liveIn) });
			boolean wasLive = !liveIn.isEmpty() || isOrigin;
			while (!q.isEmpty()) {
				Object[] s = q.pop();
				int i = (Integer) s[0];
				@SuppressWarnings("unchecked")
				Set<Varnode> live = (Set<Varnode>) s[1];
				if (!seen.add(i + "|" + key(live))) continue;
				if (seen.size() > MAX_PCODE_STATES) {
					incomplete("PCODE_PATH_BOUND", insn.getAddress(), "instruction p-code paths exceed " + MAX_PCODE_STATES);
					break;
				}
				if (i < 0 || i >= ops.length) {
					if (i == ops.length) exit(insn, fallThrough(insn), live, exits, wasLive);
					else incomplete("PCODE_BRANCH_OUT_OF_RANGE", insn.getAddress(), "relative p-code branch to op " + i);
					continue;
				}
				PcodeOp op = ops[i];
				int opc = op.getOpcode();
				switch (opc) {
					case PcodeOp.BRANCH: {
						Varnode t = op.getInput(0);
						if (t.isConstant()) q.push(new Object[] { i + (int) t.getOffset(), live });
						else exit(insn, t.getAddress(), live, exits, wasLive);
						continue;
					}
					case PcodeOp.CBRANCH: {
						Varnode t = op.getInput(0);
						if (reads(op.getInput(1), live)) use("COMPARE", insn, op, carried(op.getInput(1), live), "used directly as a branch condition", null);
						if (t.isConstant()) q.push(new Object[] { i + (int) t.getOffset(), new HashSet<>(live) });
						else exit(insn, t.getAddress(), new HashSet<>(live), exits, wasLive);
						q.push(new Object[] { i + 1, live });
						continue;
					}
					case PcodeOp.BRANCHIND: {
						if (reads(op.getInput(0), live)) use("CONTROL_TRANSFER", insn, op, carried(op.getInput(0), live), "indirect branch target", null);
						Address[] flows = insn.getFlows();
						if (flows == null || flows.length == 0) {
							if (!live.isEmpty()) incomplete("COMPUTED_FLOW_UNRESOLVED", insn.getAddress(),
								"computed jump with no known targets while the value may be live");
						} else {
							assumption("computed-jump targets are Ghidra's flow references (analysis-derived)");
							for (Address f : flows) exit(insn, f, new HashSet<>(live), exits, wasLive);
						}
						continue;
					}
					case PcodeOp.CALL:
					case PcodeOp.CALLIND: {
						Function callee = null;
						String detail;
						if (opc == PcodeOp.CALLIND) {
							if (reads(op.getInput(0), live)) use("CONTROL_TRANSFER", insn, op, carried(op.getInput(0), live), "indirect call target", null);
							detail = "indirect call";
						} else {
							Address target = op.getInput(0).getAddress();
							callee = getFunctionAt(target);
							detail = "call to " + hex(target) + (callee == null ? "" : " (" + callee.getName() + ")");
						}
						if (overlaps(argumentStorage, live)) use("ARGUMENT", insn, op, within(argumentStorage, live), "may be live in argument storage at " + detail,
							callee == null ? null : callee.getName());
						killCallClobbered(insn, live);
						if (callee != null && callee.hasNoReturn()) {
							assumption("a call to a function Ghidra marks no-return ends the path");
							continue;
						}
						q.push(new Object[] { i + 1, live });
						continue;
					}
					case PcodeOp.RETURN: {
						if (reads(op.getInput(0), live)) use("CONTROL_TRANSFER", insn, op, carried(op.getInput(0), live), "return target", null);
						if (returnStorage != null && overlaps(List.of(returnStorage), live))
							use("RETURN_VALUE", insn, op, within(List.of(returnStorage), live), "may be live in return storage at return", null);
						List<Varnode> rest = new ArrayList<>(live);
						rest.removeIf(x -> x.isUnique() || (returnStorage != null && x.intersects(returnStorage)));
						if (!rest.isEmpty()) use("ENDS_AT_RETURN", insn, op, rest, "live outside return storage at return", null);
						continue;
					}
					case PcodeOp.STORE: {
						if (reads(op.getInput(2), live)) {
							use("STORE", insn, op, carried(op.getInput(2), live), "stored to memory", storeTarget(ops, i, op.getInput(1)));
						} else if (reads(op.getInput(1), live)) {
							use("DEREFERENCE_STORE", insn, op, carried(op.getInput(1), live), "used as a store address", null);
						}
						q.push(new Object[] { i + 1, live });
						continue;
					}
					case PcodeOp.CALLOTHER: {
						List<Varnode> via = new ArrayList<>();
						for (int k = 1; k < op.getNumInputs(); k++) via.addAll(carried(op.getInput(k), live));
						boolean any = !via.isEmpty();
						String name = language.getUserDefinedOpName((int) op.getInput(0).getOffset());
						if (any) {
							use("UNMODELED", insn, op, via, "input to user-defined p-code op " + name, null);
							incomplete("UNMODELED_OPERATION", insn.getAddress(), "value may reach user-defined p-code op " + name
								+ ", whose semantics are not modeled");
						}
						write(insn, op, live, any);
						gen(isOrigin, op, live);
						q.push(new Object[] { i + 1, live });
						continue;
					}
					case PcodeOp.LOAD: {
						if (reads(op.getInput(1), live)) use("DEREFERENCE_LOAD", insn, op, carried(op.getInput(1), live), "used as a load address", null);
						write(insn, op, live, false);
						gen(isOrigin, op, live);
						q.push(new Object[] { i + 1, live });
						continue;
					}
					default: {
						List<Varnode> via = new ArrayList<>();
						for (Varnode v : op.getInputs()) via.addAll(carried(v, live));
						boolean any = !via.isEmpty();
						if (any && predicate(opc)) {
							use("COMPARE", insn, op, via, PcodeOp.getMnemonic(opc), null);
							write(insn, op, live, false);
						} else {
							write(insn, op, live, any);
						}
						gen(isOrigin, op, live);
						q.push(new Object[] { i + 1, live });
					}
				}
			}
			return exits;
		}

		/** Apply an op's output: kill what it fully overwrites, then propagate if it carries the value. */
		void write(Instruction insn, PcodeOp op, Set<Varnode> live, boolean carries) {
			Varnode o = op.getOutput();
			if (o == null) return;
			if (!o.isRegister() && !o.isUnique()) {
				// A direct write to a memory-space varnode (no STORE op).
				if (carries) {
					List<Varnode> via = new ArrayList<>();
					for (Varnode in : op.getInputs()) via.addAll(carried(in, live));
					use("STORE", insn, op, via, "written directly to memory varnode " + o, null);
				}
				return;
			}
			Iterator<Varnode> it = live.iterator();
			while (it.hasNext()) {
				Varnode v = it.next();
				if (covers(o, v)) {
					it.remove();
					if (recording && v.isRegister()) kill(insn, v, PcodeOp.getMnemonic(op.getOpcode()));
				}
			}
			if (carries) {
				if (recording) derive(insn, op, live, o);
				live.add(o);
			}
		}

		void killCallClobbered(Instruction insn, Set<Varnode> live) {
			Iterator<Varnode> it = live.iterator();
			while (it.hasNext()) {
				Varnode v = it.next();
				if (v.isRegister() && !overlaps(unaffected, Set.of(v))) {
					it.remove();
					if (recording) kill(insn, v, "call clobber (cspec)");
				}
			}
		}

		/** A transfer out of the instruction to an address. */
		void exit(Instruction insn, Address target, Set<Varnode> live, Map<Address, Set<Varnode>> exits, boolean wasLive) {
			live.removeIf(Varnode::isUnique);
			if (live.isEmpty()) {
				if (wasLive && recording) use("DEAD", insn, null, List.of(), "no copy of the value survives this edge to " + hex(target), null);
				return;
			}
			Function callee = getFunctionAt(target);
			boolean leaves = body != null ? !body.contains(target) : callee != null;
			if (leaves) {
				if (callee != null) {
					if (overlaps(argumentStorage, live)) {
						use("ARGUMENT", insn, null, within(argumentStorage, live), "may be live in argument storage at tail transfer to " + hex(target)
							+ " (" + callee.getName() + ")", callee.getName());
					} else {
						use("TAIL_TRANSFER", insn, null, live, "tail transfer to " + hex(target) + " (" + callee.getName()
							+ ") with the value only outside argument storage", callee.getName());
					}
					assumption("a transfer to another function's entry is a tail call under the default calling convention");
				} else {
					incomplete("FLOW_LEAVES_FUNCTION", insn.getAddress(), "flow to " + hex(target)
						+ " leaves the function body at a non-entry address while the value may be live");
				}
				return;
			}
			Set<Varnode> cur = exits.get(target);
			if (cur == null) exits.put(target, live);
			else cur.addAll(live);
		}

		Address fallThrough(Instruction insn) {
			return insn.getAddress().addWrap(insn.getDefaultFallThroughOffset());
		}

		/** Where a STORE writes, when the instruction's own p-code says: a stack slot or a constant address. */
		JsonObject storeTarget(PcodeOp[] ops, int index, Varnode addr) {
			JsonObject t = new JsonObject();
			Varnode a = addr;
			long offset = 0;
			for (int k = index - 1; k >= 0 && a != null && !a.isConstant(); k--) {
				PcodeOp d = ops[k];
				if (d.getOutput() == null || !d.getOutput().equals(a)) continue;
				int opc = d.getOpcode();
				if (opc == PcodeOp.COPY) a = d.getInput(0);
				else if ((opc == PcodeOp.INT_ADD || opc == PcodeOp.INT_SUB) && d.getInput(1).isConstant()) {
					long c = d.getInput(1).getOffset();
					offset += opc == PcodeOp.INT_ADD ? c : -c;
					a = d.getInput(0);
				} else break;
			}
			if (a != null && stackPointer != null && a.equals(stackPointer)) {
				t.addProperty("region", "stack");
				t.addProperty("stack_offset", offset);
			} else if (a != null && a.isConstant()) {
				t.addProperty("region", "absolute");
				t.addProperty("address", String.format("0x%x", a.getOffset() + offset));
			} else {
				t.addProperty("region", "computed");
			}
			return t;
		}

		// ---- recording ----

		/** Record a use; via names the storage that carries the value into it. */
		void use(String kind, Instruction insn, PcodeOp op, Collection<Varnode> via, String detail, Object extra) {
			if (!recording) return;
			String opName = op == null ? "" : PcodeOp.getMnemonic(op.getOpcode());
			String k = hex(insn.getAddress()) + "|" + kind + "|" + opName + "|" + detail;
			JsonObject u = uses.get(k);
			if (u == null) {
				u = new JsonObject();
				u.addProperty("kind", kind);
				u.addProperty("address", hex(insn.getAddress()));
				u.addProperty("instruction", insn.toString());
				u.addProperty("pcode_op", op == null ? null : opName);
				u.addProperty("detail", detail);
				if (extra instanceof JsonObject) u.add("store_target", (JsonObject) extra);
				else if (extra instanceof String) u.addProperty("callee", (String) extra);
				u.add("via", new JsonArray());
				uses.put(k, u);
			}
			TreeSet<String> names = new TreeSet<>();
			for (JsonElement e : u.getAsJsonArray("via")) names.add(e.getAsString());
			for (Varnode v : via) names.add(name(v));
			JsonArray arr = new JsonArray();
			for (String s : names) arr.add(s);
			u.add("via", arr);
		}

		/** The origin instruction defines the tracked location at each op that writes it. */
		void gen(boolean isOrigin, PcodeOp op, Set<Varnode> live) {
			if (isOrigin && op.getOutput() != null && covers(op.getOutput(), tracked)) live.add(tracked);
		}

		void kill(Instruction insn, Varnode v, String by) {
			String k = hex(insn.getAddress()) + "|" + name(v);
			if (kills.containsKey(k)) return;
			JsonObject j = new JsonObject();
			j.addProperty("address", hex(insn.getAddress()));
			j.addProperty("instruction", insn.toString());
			j.addProperty("storage", name(v));
			j.addProperty("by", by);
			kills.put(k, j);
		}

		void derive(Instruction insn, PcodeOp op, Set<Varnode> live, Varnode out) {
			if (derivation.size() >= MAX_DERIVATION_STEPS) {
				incomplete("DERIVATION_RECORD_TRUNCATED", insn.getAddress(), "derivation record truncated at "
					+ MAX_DERIVATION_STEPS + " steps (analysis unaffected)");
				return;
			}
			TreeSet<String> from = new TreeSet<>();
			for (Varnode in : op.getInputs()) for (Varnode l : live) if (l.intersects(in)) from.add(name(l));
			String k = hex(insn.getAddress()) + "|" + op.getSeqnum().getTime() + "|" + name(out);
			if (derivation.containsKey(k)) {
				JsonArray old = derivation.get(k).getAsJsonArray("from");
				for (JsonElement e : old) from.add(e.getAsString());
			}
			JsonObject j = new JsonObject();
			j.addProperty("address", hex(insn.getAddress()));
			j.addProperty("instruction", insn.toString());
			j.addProperty("pcode_index", op.getSeqnum().getTime());
			j.addProperty("pcode_op", PcodeOp.getMnemonic(op.getOpcode()));
			JsonArray f = new JsonArray();
			for (String s : from) f.add(s);
			j.add("from", f);
			j.addProperty("to", name(out));
			derivation.put(k, j);
		}

		void incomplete(String code, Address at, String detail) {
			String k = code + "|" + (at == null ? "" : hex(at));
			if (incomplete.containsKey(k)) return;
			JsonObject j = new JsonObject();
			j.addProperty("code", code);
			j.addProperty("address", at == null ? null : hex(at));
			j.addProperty("detail", detail);
			incomplete.put(k, j);
		}

		void assumption(String text) {
			if (recording) assumptions.add(text);
		}

		JsonArray usesJson() { return sorted(uses.values()); }
		JsonArray killsJson() { return sorted(kills.values()); }
		JsonArray derivationJson() { return sorted(derivation.values()); }
		JsonArray incompleteJson() {
			JsonArray a = new JsonArray();
			for (JsonObject o : incomplete.values()) a.add(o);
			return a;
		}
		JsonArray assumptionsJson() {
			JsonArray a = new JsonArray();
			for (String s : assumptions) a.add(s);
			return a;
		}
	}

	// ---- varnode helpers ----------------------------------------------------

	/** True when an op predicate's output is a truth value: its input is consumed, not carried. */
	static boolean predicate(int opc) {
		switch (opc) {
			case PcodeOp.INT_EQUAL: case PcodeOp.INT_NOTEQUAL: case PcodeOp.INT_LESS: case PcodeOp.INT_SLESS:
			case PcodeOp.INT_LESSEQUAL: case PcodeOp.INT_SLESSEQUAL: case PcodeOp.INT_CARRY: case PcodeOp.INT_SCARRY:
			case PcodeOp.INT_SBORROW: case PcodeOp.BOOL_NEGATE: case PcodeOp.BOOL_AND: case PcodeOp.BOOL_OR:
			case PcodeOp.BOOL_XOR: case PcodeOp.FLOAT_EQUAL: case PcodeOp.FLOAT_NOTEQUAL: case PcodeOp.FLOAT_LESS:
			case PcodeOp.FLOAT_LESSEQUAL: case PcodeOp.FLOAT_NAN:
				return true;
			default:
				return false;
		}
	}

	static boolean reads(Varnode v, Collection<Varnode> live) {
		if (v == null || v.isConstant()) return false;
		for (Varnode l : live) if (l.intersects(v)) return true;
		return false;
	}

	/** The live locations an input reads. */
	static List<Varnode> carried(Varnode v, Collection<Varnode> live) {
		List<Varnode> out = new ArrayList<>();
		if (v == null || v.isConstant()) return out;
		for (Varnode l : live) if (l.intersects(v)) out.add(l);
		return out;
	}

	/** The live locations that overlap some storage. */
	static List<Varnode> within(Collection<Varnode> storage, Collection<Varnode> live) {
		List<Varnode> out = new ArrayList<>();
		for (Varnode l : live) for (Varnode s : storage) if (l.intersects(s)) { out.add(l); break; }
		return out;
	}

	static boolean covers(Varnode outer, Varnode inner) {
		return outer.getSpace() == inner.getSpace() && outer.getOffset() <= inner.getOffset()
			&& outer.getOffset() + outer.getSize() >= inner.getOffset() + inner.getSize();
	}

	static boolean overlaps(Collection<Varnode> a, Collection<Varnode> b) {
		for (Varnode x : a) for (Varnode y : b) if (x.intersects(y)) return true;
		return false;
	}

	static String key(Set<Varnode> live) {
		List<String> l = new ArrayList<>();
		for (Varnode v : live) l.add(v.toString());
		Collections.sort(l);
		return String.join(",", l);
	}

	String name(Varnode v) {
		if (v.isUnique()) return String.format("$U%x:%d", v.getOffset(), v.getSize());
		Register r = currentProgram.getRegister(v);
		if (r != null) return r.getName();
		r = currentProgram.getRegister(v.getAddress());
		return r != null ? r.getName() + ":" + v.getSize() : v.toString();
	}

	JsonArray names(Collection<Varnode> vs) {
		JsonArray a = new JsonArray();
		for (Varnode v : vs) a.add(name(v));
		return a;
	}

	static String hex(Address a) {
		int digits = Math.max(8, (a.getAddressSpace().getSize() + 3) / 4);
		return String.format("0x%0" + digits + "x", a.getOffset());
	}

	static JsonArray ranges(AddressSetView set) {
		JsonArray a = new JsonArray();
		for (AddressRange r : set) {
			JsonArray p = new JsonArray();
			p.add(hex(r.getMinAddress()));
			p.add(hex(r.getMaxAddress()));
			a.add(p);
		}
		return a;
	}

	static JsonArray sorted(Collection<JsonObject> values) {
		List<JsonObject> l = new ArrayList<>(values);
		l.sort(Comparator.comparing((JsonObject o) -> o.get("address").isJsonNull() ? "" : o.get("address").getAsString())
			.thenComparing(o -> o.toString()));
		JsonArray a = new JsonArray();
		for (JsonObject o : l) a.add(o);
		return a;
	}
}
