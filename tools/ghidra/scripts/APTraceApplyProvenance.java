/* APTrace: apply a bounded standard-library/provenance classification to
 * named addresses, so Ghidra's own function list/decompile output
 * visually de-emphasizes known Adafruit-core/toolchain/library code and
 * lets future RE passes focus on custom application logic.
 *
 * This does NOT change program behavior, does NOT rename anything not
 * listed in the TSV, and does NOT attempt automatic function matching --
 * every entry in the TSV was placed there by a human-reviewed
 * investigation (see docs/investigations/standard-library-provenance.md
 * for the method and evidence). Re-running this script is idempotent
 * (it just re-applies the same names/comments).
 *
 * Input format: a tab-separated file with a header row, columns
 * "address\tname\tclassification" -- see
 * research/provenance/ghidra_labels.tsv. Rows whose address doesn't
 * parse as a single 0x-prefixed hex value are skipped (the richer,
 * prose-bearing CSV this file is derived from has some multi-address
 * and non-address rows not meant for this script).
 *
 * Run as a headless -postScript (after auto-analysis + any entry
 * seeding): APTraceApplyProvenance.java <labels.tsv>
 */
//@category APTrace

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.FileReader;

public class APTraceApplyProvenance extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			println("usage: APTraceApplyProvenance.java <labels.tsv>");
			return;
		}
		String tsvPath = args[0];

		int applied = 0, skipped = 0;
		try (BufferedReader r = new BufferedReader(new FileReader(tsvPath))) {
			String line = r.readLine(); // header
			while ((line = r.readLine()) != null) {
				if (line.trim().isEmpty()) {
					continue;
				}
				String[] cols = line.split("\t", -1);
				if (cols.length < 3) {
					skipped++;
					continue;
				}
				String addrTok = cols[0].trim();
				String name = cols[1].trim();
				String classification = cols[2].trim();
				if (!addrTok.startsWith("0x") && !addrTok.startsWith("0X")) {
					skipped++;
					continue;
				}
				long off;
				try {
					off = Long.parseLong(addrTok.substring(2), 16);
				} catch (NumberFormatException e) {
					skipped++;
					continue;
				}
				Address a = currentProgram.getMinAddress().getNewAddress(off);
				Function f = currentProgram.getFunctionManager().getFunctionAt(a);
				if (f == null) {
					println("no function at " + addrTok + " (seed it first) -- skipped");
					skipped++;
					continue;
				}
				f.setName(name, SourceType.USER_DEFINED);
				f.setComment("APTrace provenance: " + classification
					+ " -- see docs/investigations/standard-library-provenance.md"
					+ " and research/provenance/function_classification.csv");
				applied++;
			}
		}

		println("APTraceApplyProvenance: applied " + applied + ", skipped " + skipped);
	}
}
