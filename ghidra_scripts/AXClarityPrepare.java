/* AX-Clarity by AlexDev-TH. MIT License. */
// Prepare an ECU program for readable decompiler output (headless friendly).
// Sets the global base registers the finder is sure about, maps RAM/IO blocks,
// adds xrefs, types and names globals. Optional args: reg=value pairs, e.g. gp=0xFEBF0000
//@category AX-Clarity
import java.util.List;

import axclarity.core.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;

public class AXClarityPrepare extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Arch arch = Arch.detect(currentProgram);
		println("AX-Clarity: CPU " + arch);
		List<BaseRegisterFinder.Result> found = BaseRegisterFinder.find(currentProgram, arch, monitor);
		for (BaseRegisterFinder.Result r : found) {
			println("  " + r.reg.getName() + ": " +
				(r.chosen == null ? "-" : "0x" + Long.toHexString(r.chosen)) + "  " + r.describe() +
				"  unknownWrites=" + r.unknownWrites);
			for (java.util.Map.Entry<Long, java.util.List<ghidra.program.model.address.Address>> e : r.values
					.entrySet()) {
				println("      0x" + Long.toHexString(e.getKey()) + "  x" + e.getValue().size() + "  first @ " +
					e.getValue().get(0) +
					(BaseRegisterFinder.plausibleBase(currentProgram, arch, e.getKey()) ? "" : "  (rejected)"));
			}
		}
		EcuPrep.Options opt = EcuPrep.defaults(found);
		for (String a : getScriptArgs()) {
			String[] kv = a.split("=", 2);
			if (kv.length != 2) {
				continue;
			}
			Register reg = Arch.findRegister(currentProgram.getLanguage(), kv[0]);
			if (reg == null) {
				printerr("unknown register " + kv[0]);
				continue;
			}
			String v = kv[1].toLowerCase().replace("0x", "");
			opt.baseValues.put(reg, Long.parseUnsignedLong(v, 16));
		}
		int tx = currentProgram.startTransaction("AX-Clarity Prepare");
		boolean ok = false;
		try {
			EcuPrep.Report rep = EcuPrep.run(currentProgram, opt, monitor);
			println("AX-Clarity: " + rep);
			ok = true;
		}
		finally {
			currentProgram.endTransaction(tx, ok);
		}
	}
}
