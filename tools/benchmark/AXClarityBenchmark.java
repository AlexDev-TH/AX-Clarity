/* AX-Clarity by AlexDev-TH. MIT License. */
// Benchmark: Ghidra default output vs. AX-Clarity (Prepare + Clean Code) on the same program.
// Run headless with -readOnly so the project is not changed.
// args: <outPrefix> [sampleAddr,sampleAddr,...] [reg=value ...]
//@category AX-Clarity
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

import axclarity.clean.*;
import axclarity.core.*;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;

public class AXClarityBenchmark extends GhidraScript {

	static final String[][] PATTERNS = {
		{ "unaff_/in_/extraout_ (unknown register)", "\\b(?:unaff|in|extraout)_\\w+" },
		{ "base register arithmetic (gp+0x..)", "\\b(?:unaff_|in_)?(?:gp|ep|tp|SB|sb|r2|r13)\\s*[+-]\\s*(?:-?0x|\\d)" },
		{ "type casts", "\\((?:u?char|u?short|u?int|u?long|byte|sbyte|undefined\\d*|bool|longlong|ulonglong|[us](?:8|16|24|32|64)|uint3)(?: \\*+)?\\)" },
		{ "undefined types", "\\bundefined\\d?\\b" },
		{ "CONCAT/SUB/ZEXT/SEXT", "\\b(?:CONCAT\\d+|SUB\\d\\d|[ZS]EXT\\d+)\\(" },
		{ "unnamed globals (DAT_)", "\\b_?DAT_[0-9a-fA-F]+" },
		{ "raw pointer constants *(T *)0x..", "\\*\\([\\w ]+\\*\\)0x[0-9a-fA-F]+" },
		{ "char literals '\\x04'", "'(?:\\\\.|[^'])+'" },
		{ "WARNING comments", "WARNING" },
		{ "named globals ram_/cal_/io_", "\\b(?:ram|cal|io)_[0-9a-f]+" },
		{ "BIT()/SETBIT()/CLRBIT()", "\\b(?:BIT|SETBIT|CLRBIT)\\(" },
	};

	static final class M {
		int functions, failed, lines, chars;
		long[] counts = new long[PATTERNS.length];
		Map<String, String> text = new HashMap<>();
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		String prefix = args.length > 0 ? args[0] : "bench";
		List<String> samples = new ArrayList<>();
		if (args.length > 1 && !args[1].contains("=")) {
			samples.addAll(Arrays.asList(args[1].split(",")));
		}

		M a = measure(false, false);
		println("A done " + a.functions);

		Arch arch = Arch.detect(currentProgram);
		List<BaseRegisterFinder.Result> found = BaseRegisterFinder.find(currentProgram, arch, monitor);
		EcuPrep.Options opt = EcuPrep.defaults(found);
		for (String s : args) {
			String[] kv = s.split("=", 2);
			if (kv.length == 2) {
				Register reg = Arch.findRegister(currentProgram.getLanguage(), kv[0]);
				if (reg != null) {
					opt.baseValues.put(reg, Long.parseUnsignedLong(kv[1].toLowerCase().replace("0x", ""), 16));
				}
			}
		}
		StringBuilder baseInfo = new StringBuilder();
		for (BaseRegisterFinder.Result r : found) {
			baseInfo.append(r.reg.getName()).append(": ")
					.append(r.chosen == null ? "-" : "0x" + Long.toHexString(r.chosen)).append(" ")
					.append(r.describe()).append(" values=").append(r.values.size()).append("; ");
		}
		int tx = currentProgram.startTransaction("AX-Clarity benchmark");
		EcuPrep.Report rep;
		try {
			rep = EcuPrep.run(currentProgram, opt, monitor);
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		println("prep " + rep);

		M b = measure(false, false);
		println("B done");
		M c = measure(true, true);
		println("C done");

		try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
			new FileOutputStream(prefix + "_bench.txt"), StandardCharsets.UTF_8))) {
			w.println("program=" + currentProgram.getName());
			w.println("language=" + currentProgram.getLanguageID());
			w.println("sha256=" + currentProgram.getExecutableSHA256());
			w.println("arch=" + arch);
			w.println("baseRegisters=" + baseInfo);
			w.println("prep=" + rep);
			w.println("metric\tghidra_default\tafter_prepare\tax_clarity_clean");
			w.println("functions\t" + a.functions + "\t" + b.functions + "\t" + c.functions);
			w.println("failed\t" + a.failed + "\t" + b.failed + "\t" + c.failed);
			w.println("lines\t" + a.lines + "\t" + b.lines + "\t" + c.lines);
			w.println("chars\t" + a.chars + "\t" + b.chars + "\t" + c.chars);
			for (int i = 0; i < PATTERNS.length; i++) {
				w.println(PATTERNS[i][0] + "\t" + a.counts[i] + "\t" + b.counts[i] + "\t" + c.counts[i]);
			}
		}
		if (samples.isEmpty()) {
			// pick functions where the difference is most visible: 15..45 lines, most noise in A
			List<String> keys = new ArrayList<>(a.text.keySet());
			Pattern noise = Pattern.compile(PATTERNS[0][1] + "|" + PATTERNS[1][1] + "|" + PATTERNS[2][1]);
			keys.sort((x, y) -> Integer.compare(score(a.text.get(y), noise), score(a.text.get(x), noise)));
			for (String k : keys) {
				int n = a.text.get(k).split("\n").length;
				if (n >= 15 && n <= 45) {
					samples.add(k);
				}
				if (samples.size() >= 6) {
					break;
				}
			}
		}
		try (PrintWriter w = new PrintWriter(new OutputStreamWriter(
			new FileOutputStream(prefix + "_samples.txt"), StandardCharsets.UTF_8))) {
			for (String s : samples) {
				w.println("######## " + s);
				w.println("######## A ghidra default");
				w.println(a.text.get(s));
				w.println("######## B after prepare");
				w.println(b.text.get(s));
				w.println("######## C ax-clarity clean");
				w.println(c.text.get(s));
			}
		}
		println("samples " + samples);
	}

	private static int score(String t, Pattern p) {
		if (t == null) {
			return 0;
		}
		Matcher m = p.matcher(t);
		int n = 0;
		while (m.find()) {
			n++;
		}
		return n;
	}

	private M measure(boolean inplace, boolean clean) throws Exception {
		M m = new M();
		CleanOptions none = CleanOptions.none();
		CleanOptions all = new CleanOptions();
		Pattern[] ps = new Pattern[PATTERNS.length];
		for (int i = 0; i < ps.length; i++) {
			ps[i] = Pattern.compile(PATTERNS[i][1]);
		}
		try (CleanDecompiler dec = new CleanDecompiler(currentProgram, null, inplace)) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				monitor.checkCancelled();
				if (f.isExternal()) {
					continue;
				}
				DecompileResults r = dec.decompile(f, 60, monitor);
				if (r == null || !r.decompileCompleted()) {
					m.failed++;
					continue;
				}
				m.functions++;
				CleanPrinter.Result cr = new CleanPrinter(currentProgram, clean ? all : none).clean(r);
				String text = cr.text();
				// fair size metric: non-blank lines and non-whitespace characters, without the
				// legend line and without the inline calibration values (those add information)
				for (String ln : text.split("\n")) {
					if (ln.isBlank() || ln.startsWith("// BIT(")) {
						continue;
					}
					m.lines++;
					m.chars += ln.replaceAll("/\\*=[^*]*\\*/", "").replaceAll("\\s+", "").length();
				}
				for (int i = 0; i < ps.length; i++) {
					Matcher mm = ps[i].matcher(text);
					while (mm.find()) {
						m.counts[i]++;
					}
				}
				m.text.put(f.getEntryPoint().toString(), text);
			}
		}
		return m;
	}
}
