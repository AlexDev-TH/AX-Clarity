/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.clean;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/** A decompiler session configured for the Clean Code view. */
public final class CleanDecompiler implements AutoCloseable {

	public static final int WIDTH = 220;

	private final DecompInterface ifc = new DecompInterface();
	private final Program program;

	/**
	 * @param base options from the tool (keeps the user's own decompiler settings), or null
	 * @param inplace print x += 1 instead of x = x + 1
	 */
	public CleanDecompiler(Program program, DecompileOptions base, boolean inplace) {
		this.program = program;
		DecompileOptions o = base;
		if (o == null) {
			o = new DecompileOptions();
			o.grabFromProgram(program);
		}
		o.setMaxWidth(WIDTH);
		o.setInplaceTokens(inplace);
		ifc.setOptions(o);
		ifc.toggleCCode(true);
		ifc.toggleSyntaxTree(true);
		ifc.setSimplificationStyle("decompile");
		ifc.openProgram(program);
	}

	public Program getProgram() {
		return program;
	}

	public DecompileResults decompile(Function f, int timeoutSecs, TaskMonitor monitor) {
		return ifc.decompileFunction(f, timeoutSecs, monitor);
	}

	public CleanPrinter.Result clean(Function f, CleanOptions opt, TaskMonitor monitor) {
		DecompileResults r = decompile(f, 60, monitor);
		CleanPrinter.Result out = new CleanPrinter(program, opt).clean(r);
		return out;
	}

	@Override
	public void close() {
		ifc.closeProgram();
		ifc.dispose();
	}
}
