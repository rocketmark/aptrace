/* Test-only pre-script for test_pcode_forward_use.py: disassemble and
 * create functions at the given entries before auto-analysis, so a fixture
 * image becomes an analyzed project to read in project mode.
 *
 * Script args: <entry>[,<entry>...]
 */
//@category APTrace.Test

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class APTracePcodeForwardUseTestSeed extends GhidraScript {
	@Override
	public void run() throws Exception {
		for (String s : getScriptArgs()[0].split(",")) {
			Address entry = toAddr(Long.decode(s));
			new DisassembleCommand(entry, null, true).applyTo(currentProgram, monitor);
			if (getFunctionAt(entry) == null) new CreateFunctionCmd(entry).applyTo(currentProgram, monitor);
		}
	}
}
