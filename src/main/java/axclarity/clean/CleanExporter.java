/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.clean;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Writes every function of a program as clean C into one file. */
public final class CleanExporter {

	public static final class Summary {
		public int functions, failed, origLines, origChars, cleanLines, cleanChars, fixes;

		@Override
		public String toString() {
			long pct = origChars == 0 ? 0 : Math.round(100.0 * (origChars - cleanChars) / origChars);
			return String.format(Locale.ROOT,
				"%d functions (%d failed), Ghidra %d lines / %d chars, AX-Clarity %d lines / %d chars (-%d%%), %d fixes",
				functions, failed, origLines, origChars, cleanLines, cleanChars, pct, fixes);
		}
	}

	private CleanExporter() {
	}

	public static Summary export(Program program, DecompileOptions base, CleanOptions opt, File out,
			TaskMonitor monitor) throws IOException, CancelledException {
		Summary s = new Summary();
		try (CleanDecompiler dec = new CleanDecompiler(program, base, true);
				Writer w = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8))) {
			w.write("/*\n * " + program.getName() + "\n");
			w.write(" * language : " + program.getLanguageID() + "\n");
			String sha = program.getExecutableSHA256();
			if (sha != null) {
				w.write(" * sha256   : " + sha + "\n");
			}
			w.write(" * exported : " +
				LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm", Locale.ROOT)) +
				"\n");
			w.write(" * AX-Clarity by AlexDev-TH\n */\n\n");
			w.write("// BIT(x,n) = bit n of x   SETBIT/CLRBIT(x,n) = set/clear bit n\n\n");
			monitor.initialize(program.getFunctionManager().getFunctionCount());
			for (Function f : program.getFunctionManager().getFunctions(true)) {
				monitor.checkCancelled();
				monitor.incrementProgress(1);
				monitor.setMessage(f.getName());
				if (f.isExternal()) {
					continue;
				}
				CleanPrinter.Result r = new CleanPrinter(program, opt)
						.clean(dec.decompile(f, 60, monitor));
				if (r.lines.isEmpty() || r.lines.get(0).text.startsWith("/* decompile failed")) {
					s.failed++;
				}
				s.functions++;
				s.origLines += r.origLines;
				s.origChars += r.origChars;
				s.cleanLines += r.cleanLines;
				s.cleanChars += r.cleanChars;
				s.fixes += r.totalFixes();
				w.write("// " + f.getEntryPoint() + "\n");
				for (CleanPrinter.Line l : r.lines) {
					if (l.text.startsWith("// BIT(")) {
						continue;
					}
					w.write(l.text);
					w.write('\n');
				}
				w.write('\n');
			}
		}
		return s;
	}
}
