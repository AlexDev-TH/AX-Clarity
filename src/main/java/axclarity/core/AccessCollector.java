/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.core;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Collects every global memory access whose address can be computed, including
 * accesses relative to gp/tp/ep/SB once those registers have a value. Nothing is
 * changed in the program while collecting.
 */
public final class AccessCollector {

	public static final int SIGN_UNKNOWN = -1, UNSIGNED = 0, SIGNED = 1;

	public static final class Access {
		public final Address from;
		public final Address to;
		public final int size;
		public final boolean write;
		public final int sign;

		Access(Address from, Address to, int size, boolean write, int sign) {
			this.from = from;
			this.to = to;
			this.size = size;
			this.write = write;
			this.sign = sign;
		}

		@Override
		public boolean equals(Object o) {
			if (!(o instanceof Access)) {
				return false;
			}
			Access a = (Access) o;
			return a.from.equals(from) && a.to.equals(to) && a.size == size && a.write == write;
		}

		@Override
		public int hashCode() {
			return Objects.hash(from, to, size, write);
		}
	}

	private AccessCollector() {
	}

	public static List<Access> collect(Program program, TaskMonitor monitor) throws CancelledException {
		Set<Access> found = new LinkedHashSet<>();
		ContextEvaluatorAdapter eval = new ContextEvaluatorAdapter() {
			@Override
			public Address evaluateConstant(VarnodeContext ctx, Instruction in, int pcodeop,
					Address constant, int size, DataType dataType, RefType refType) {
				// let load/store targets computed from constants through; reject pure
				// speculative constants (they are not memory accesses)
				if (refType != null && (refType.isRead() || refType.isWrite()) &&
					(pcodeop == PcodeOp.LOAD || pcodeop == PcodeOp.STORE)) {
					return constant;
				}
				return null;
			}

			@Override
			public boolean evaluateReference(VarnodeContext ctx, Instruction in, int pcodeop,
					Address address, int size, DataType dataType, RefType refType) {
				if (address != null && address.isMemoryAddress() && refType != null &&
					refType.isData() && (refType.isRead() || refType.isWrite()) && size > 0 &&
					size <= 8) {
					boolean w = refType.isWrite() && !refType.isRead();
					found.add(new Access(in.getMinAddress(), address, size, w,
						w ? SIGN_UNKNOWN : signOf(in, size)));
				}
				return false; // AX-Clarity creates its own references later
			}
		};

		FunctionManager fm = program.getFunctionManager();
		monitor.setMessage("AX-Clarity: tracing global variable accesses");
		monitor.initialize(fm.getFunctionCount());
		for (Function f : fm.getFunctions(true)) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (f.isExternal() || f.isThunk()) {
				continue;
			}
			try {
				SymbolicPropogator sp = new SymbolicPropogator(program);
				sp.flowConstants(f.getEntryPoint(), f.getBody(), eval, false, monitor);
			}
			catch (CancelledException ce) {
				throw ce;
			}
			catch (Exception ex) {
				// skip a function the propagator cannot follow
			}
		}

		// direct-address operands that analysis already referenced (M16C/R8C abs16 etc.)
		ReferenceManager rm = program.getReferenceManager();
		Listing listing = program.getListing();
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction in = it.next();
			for (Reference r : rm.getReferencesFrom(in.getMinAddress())) {
				RefType t = r.getReferenceType();
				if (!r.isMemoryReference() || !t.isData() || !(t.isRead() || t.isWrite())) {
					continue;
				}
				int size = directSize(in, r.getToAddress());
				if (size <= 0) {
					continue;
				}
				boolean w = t.isWrite() && !t.isRead();
				found.add(new Access(in.getMinAddress(), r.getToAddress(), size, w,
					w ? SIGN_UNKNOWN : signOf(in, size)));
			}
		}
		return new ArrayList<>(found);
	}

	/** Size of a direct (non-LOAD) memory varnode at {@code to} used by the instruction. */
	static int directSize(Instruction in, Address to) {
		int best = 0;
		try {
			for (PcodeOp op : in.getPcode()) {
				Varnode out = op.getOutput();
				if (out != null && out.isAddress() && out.getAddress().equals(to)) {
					best = Math.max(best, out.getSize());
				}
				for (Varnode v : op.getInputs()) {
					if (v != null && v.isAddress() && v.getAddress().equals(to)) {
						best = Math.max(best, v.getSize());
					}
				}
				if (op.getOpcode() == PcodeOp.LOAD && op.getOutput() != null && best == 0) {
					best = op.getOutput().getSize();
				}
				if (op.getOpcode() == PcodeOp.STORE && op.getNumInputs() > 2 && best == 0) {
					best = op.getInput(2).getSize();
				}
			}
		}
		catch (Exception e) {
			return 0;
		}
		return best;
	}

	/**
	 * Signedness of a read of {@code size} bytes: a load that is sign-extended
	 * (V850 ld.b/ld.h, PowerPC lha) is signed, a zero-extended one (ld.bu/ld.hu,
	 * lbz/lhz) is unsigned.
	 */
	static int signOf(Instruction in, int size) {
		PcodeOp[] ops;
		try {
			ops = in.getPcode();
		}
		catch (Exception e) {
			return SIGN_UNKNOWN;
		}
		for (PcodeOp op : ops) {
			Varnode loaded = null;
			if (op.getOpcode() == PcodeOp.LOAD && op.getOutput() != null &&
				op.getOutput().getSize() == size) {
				loaded = op.getOutput();
			}
			else if (op.getOutput() != null) {
				for (Varnode v : op.getInputs()) {
					if (v != null && v.isAddress() && v.getSize() == size &&
						(op.getOpcode() == PcodeOp.INT_SEXT || op.getOpcode() == PcodeOp.INT_ZEXT)) {
						return op.getOpcode() == PcodeOp.INT_SEXT ? SIGNED : UNSIGNED;
					}
				}
			}
			if (loaded == null) {
				continue;
			}
			for (PcodeOp use : ops) {
				if (use.getNumInputs() > 0 && loaded.equals(use.getInput(0))) {
					if (use.getOpcode() == PcodeOp.INT_SEXT) {
						return SIGNED;
					}
					if (use.getOpcode() == PcodeOp.INT_ZEXT) {
						return UNSIGNED;
					}
				}
			}
		}
		return SIGN_UNKNOWN;
	}

	/** Operand index that carries the memory access, or {@link Reference#MNEMONIC}. */
	static int operandFor(Instruction in, List<Register> baseRegs) {
		int n = in.getNumOperands();
		for (int i = 0; i < n; i++) {
			for (Object o : in.getOpObjects(i)) {
				if (o instanceof Register && baseRegs.contains(o)) {
					return i;
				}
			}
		}
		for (int i = 0; i < n; i++) {
			int t = in.getOperandType(i);
			if ((t & (ghidra.program.model.lang.OperandType.ADDRESS |
				ghidra.program.model.lang.OperandType.DYNAMIC)) != 0) {
				return i;
			}
		}
		for (int i = 0; i < n; i++) {
			for (Object o : in.getOpObjects(i)) {
				if (o instanceof Scalar) {
					return i;
				}
			}
		}
		return Reference.MNEMONIC;
	}
}
