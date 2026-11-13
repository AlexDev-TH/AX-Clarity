/* AX-Clarity by AlexDev-TH. MIT License. */
// Export every function of the current program as clean C into one file.
// Headless arg: output path (default: <program>_clean.c next to the project)
//@category AX-Clarity
import java.io.File;

import axclarity.clean.CleanExporter;
import axclarity.clean.CleanOptions;
import ghidra.app.script.GhidraScript;

public class AXClarityExportCleanC extends GhidraScript {
	@Override
	protected void run() throws Exception {
		File out;
		if (getScriptArgs().length > 0) {
			out = new File(getScriptArgs()[0]);
		}
		else if (isRunningHeadless()) {
			out = new File(currentProgram.getName() + "_clean.c");
		}
		else {
			out = askFile("AX-Clarity: save clean C", "Save");
		}
		CleanExporter.Summary s =
			CleanExporter.export(currentProgram, null, new CleanOptions(), out, monitor);
		println("AX-Clarity: " + out.getAbsolutePath() + "  " + s);
	}
}
