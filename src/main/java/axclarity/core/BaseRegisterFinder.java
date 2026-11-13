/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.core;

import java.math.BigInteger;
import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds the constant that startup code loads into a global base register
 * (V850/RH850 gp, tp, ep; M16C/R8C SB; PowerPC r2/r13).
 * <p>
 * Every instruction that writes one of the registers is evaluated with Ghidra's
 * own constant propagator, so split forms such as {@code movhi hi,r0,gp ;
 * movea lo,gp,gp} are resolved to the final value.
 */
public final class BaseRegisterFinder {

	public static final class Result {
		public final Register reg;
		/** constant value written, mapped to the instructions that wrote it */
		public final Map<Long, List<Address>> values = new LinkedHashMap<>();
		public int unknownWrites;
		/** value already present in the program context, or null */
		public Long existing;
		/** suggested value, or null when nothing was found */
		public Long chosen;
		/** true when every constant write agrees on one value */
		public boolean confident;

		Result(Register reg) {
			this.reg = reg;
		}

		public int siteCount(long value) {
			List<Address> l = values.get(value);
			return l == null ? 0 : l.size();
		}

		public String describe() {
			if (chosen == null) {
				return existing != null ? "already set" : "not found";
			}
			List<Address> l = values.get(chosen);
			String where = (l == null || l.isEmpty()) ? "" : " @ " + l.get(0);
			return (confident ? "confirmed" : "ambiguous (" + values.size() + " values)") + where;
		}
	}

	private BaseRegisterFinder() {
	}

	public static List<Result> find(Program program, Arch arch, TaskMonitor monitor)
			throws CancelledException {
		List<Result> out = new ArrayList<>();
		if (arch.baseRegisters.isEmpty()) {
			return out;
		}
		Map<Register, Result> byReg = new LinkedHashMap<>();
		for (Register r : arch.baseRegisters) {
			Result res = new Result(r);
			res.existing = existingValue(program, r);
			byReg.put(r, res);
			out.add(res);
		}

		Listing listing = program.getListing();
		FunctionManager fm = program.getFunctionManager();
		Map<Address, List<Register>> writers = new HashMap<>();
		InstructionIterator it = listing.getInstructions(true);
		monitor.setMessage("AX-Clarity: scanning base register writes");
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction in = it.next();
			for (Object o : in.getResultObjects()) {
				if (!(o instanceof Register)) {
					continue;
				}
				Register w = (Register) o;
				for (Register b : arch.baseRegisters) {
					if (w.equals(b) || w.contains(b)) {
						writers.computeIfAbsent(in.getMinAddress(), k -> new ArrayList<>()).add(b);
					}
				}
			}
		}
		if (writers.isEmpty()) {
			finish(program, arch, out);
			return out;
		}

		// one propagation run per containing function (or short straight-line run)
		Map<Address, AddressSet> starts = new LinkedHashMap<>();
		for (Address a : writers.keySet()) {
			Function f = fm.getFunctionContaining(a);
			if (f != null) {
				starts.computeIfAbsent(f.getEntryPoint(), k -> new AddressSet()).add(f.getBody());
			}
			else {
				Instruction w = listing.getInstructionAt(a);
				Address s = walkBack(listing, a, 24);
				starts.computeIfAbsent(s, k -> new AddressSet()).add(new AddressRangeImpl(s,
					w != null ? w.getMaxAddress() : a));
			}
		}

		Map<Address, Map<Register, Long>> known = new HashMap<>();
		ContextEvaluatorAdapter eval = new ContextEvaluatorAdapter() {
			@Override
			public boolean evaluateContext(VarnodeContext ctx, Instruction in) {
				List<Register> regs = writers.get(in.getMinAddress());
				if (regs != null) {
					for (Register r : regs) {
						RegisterValue rv = ctx.getRegisterValue(r);
						Map<Register, Long> m =
							known.computeIfAbsent(in.getMinAddress(), k -> new HashMap<>());
						if (rv != null && rv.hasValue()) {
							m.put(r, rv.getUnsignedValue().longValue());
						}
						else if (!m.containsKey(r)) {
							m.put(r, null);
						}
					}
				}
				return false;
			}
		};
		monitor.setMessage("AX-Clarity: evaluating base register values");
		monitor.initialize(starts.size());
		for (Map.Entry<Address, AddressSet> e : starts.entrySet()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			try {
				SymbolicPropogator sp = new SymbolicPropogator(program);
				sp.flowConstants(e.getKey(), e.getValue(), eval, false, monitor);
			}
			catch (CancelledException ce) {
				throw ce;
			}
			catch (Exception ex) {
				// a single bad flow must not stop the search
			}
		}

		for (Map.Entry<Address, List<Register>> e : writers.entrySet()) {
			for (Register r : e.getValue()) {
				Result res = byReg.get(r);
				Map<Register, Long> m = known.get(e.getKey());
				Long v = m == null ? null : m.get(r);
				if (v == null) {
					res.unknownWrites++;
				}
				else {
					res.values.computeIfAbsent(v, k -> new ArrayList<>()).add(e.getKey());
				}
			}
		}
		dropIntermediate(program, arch, out);
		return out;
	}

	private static void finish(Program program, Arch arch, List<Result> out) {
		for (Result r : out) {
			Long best = null;
			int bestCount = 0;
			int plausible = 0;
			for (Map.Entry<Long, List<Address>> e : r.values.entrySet()) {
				if (!plausibleBase(program, arch, e.getKey())) {
					continue; // e.g. 0x55555555 from a startup register self-test
				}
				plausible++;
				if (e.getValue().size() > bestCount) {
					best = e.getKey();
					bestCount = e.getValue().size();
				}
			}
			r.chosen = best;
			// gp/SB/r2/r13 are set once at startup (interrupt code may save and restore them).
			// ep/tp are often reloaded per function, so any non-constant write makes them unsafe
			// to assume program-wide; they are then offered unchecked for the analyst to review.
			String n = r.reg.getName().toLowerCase(Locale.ROOT);
			boolean primary = n.equals("gp") || n.equals("sb") || n.equals("r2") || n.equals("r13");
			r.confident = best != null && plausible == 1 && (primary || r.unknownWrites == 0);
		}
	}

	/** A base register must point at RAM of this CPU family or into a mapped, non-I/O block. */
	public static boolean plausibleBase(Program program, Arch arch, long value) {
		long v = value & 0xFFFFFFFFL;
		if (v < 0x100) {
			return false;
		}
		if (arch.plausible(v) && arch.roleOf(v) == Arch.Role.RAM) {
			return true;
		}
		try {
			AddressSpace sp = program.getAddressFactory().getDefaultAddressSpace();
			if (v > sp.getMaxAddress().getOffset()) {
				return false;
			}
			MemoryBlock b = program.getMemory().getBlock(sp.getAddress(v));
			return b != null && !b.isVolatile();
		}
		catch (Exception e) {
			return false;
		}
	}

	/** Remove intermediate values (e.g. the movhi half) that a following write replaced. */
	private static void dropIntermediate(Program program, Arch arch, List<Result> results) {
		Listing listing = program.getListing();
		for (Result r : results) {
			Iterator<Map.Entry<Long, List<Address>>> it = r.values.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<Long, List<Address>> e = it.next();
				e.getValue().removeIf(a -> nextWritesSame(listing, a, r.reg));
				if (e.getValue().isEmpty()) {
					it.remove();
				}
			}
		}
		finish(program, arch, results);
	}

	private static boolean nextWritesSame(Listing listing, Address a, Register reg) {
		Instruction in = listing.getInstructionAt(a);
		if (in == null) {
			return false;
		}
		Address ft = in.getFallThrough();
		if (ft == null) {
			return false;
		}
		Instruction next = listing.getInstructionAt(ft);
		if (next == null) {
			return false;
		}
		boolean reads = false;
		for (Object o : next.getInputObjects()) {
			if (o instanceof Register && (((Register) o).equals(reg) || ((Register) o).contains(reg))) {
				reads = true;
			}
		}
		if (!reads) {
			return false;
		}
		for (Object o : next.getResultObjects()) {
			if (o instanceof Register && (((Register) o).equals(reg) || ((Register) o).contains(reg))) {
				return true;
			}
		}
		return false;
	}

	private static Address walkBack(Listing listing, Address a, int max) {
		Instruction cur = listing.getInstructionAt(a);
		if (cur == null) {
			return a;
		}
		for (int i = 0; i < max; i++) {
			Address ff = cur.getFallFrom();
			if (ff == null) {
				break;
			}
			Instruction prev = listing.getInstructionAt(ff);
			if (prev == null) {
				break;
			}
			cur = prev;
		}
		return cur.getMinAddress();
	}

	/** Value already stored in the program context for {@code reg}, if any. */
	public static Long existingValue(Program program, Register reg) {
		ProgramContext ctx = program.getProgramContext();
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			if (!b.isInitialized() || !b.getStart().isMemoryAddress()) {
				continue;
			}
			BigInteger v = ctx.getValue(reg, b.getStart(), false);
			if (v == null) {
				FunctionIterator fi = program.getFunctionManager().getFunctions(
					new AddressSet(b.getStart(), b.getEnd()), true);
				if (fi.hasNext()) {
					v = ctx.getValue(reg, fi.next().getEntryPoint(), false);
				}
			}
			if (v != null) {
				return v.longValue();
			}
		}
		return null;
	}

	/** Store {@code value} for {@code reg} over every initialized block. Requires a transaction. */
	public static int apply(Program program, Register reg, long value) throws Exception {
		ProgramContext ctx = program.getProgramContext();
		BigInteger mask = BigInteger.ONE.shiftLeft(reg.getBitLength()).subtract(BigInteger.ONE);
		BigInteger v = BigInteger.valueOf(value).and(mask);
		int n = 0;
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			if (!b.isInitialized() || !b.getStart().isMemoryAddress()) {
				continue;
			}
			ctx.setValue(reg, b.getStart(), b.getEnd(), v);
			n++;
		}
		return n;
	}
}
