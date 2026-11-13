/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.core;

import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * One-click preparation of an ECU program so that Ghidra's own decompiler can
 * print named, typed global variables instead of base-register arithmetic.
 * <ol>
 * <li>Store the global base register values (gp/tp/ep, SB, r2/r13).</li>
 * <li>Trace every global access and map missing RAM / I/O blocks.</li>
 * <li>Add cross references so "who reads this calibration?" works.</li>
 * <li>Type each variable from its access width and sign (ld.h = s16, ld.hu = u16).</li>
 * <li>Name it by memory role: ram_, cal_, io_.</li>
 * </ol>
 * All steps run inside the caller's transaction, so one Undo reverts everything.
 */
public final class EcuPrep {

	public static final String CATEGORY = "/AX-Clarity";

	public static final class Options {
		/** register to value; only registers present here are written */
		public final Map<Register, Long> baseValues = new LinkedHashMap<>();
		public boolean createBlocks = true;
		public boolean createReferences = true;
		public boolean typeGlobals = true;
		public boolean nameGlobals = true;
	}

	public static final class Report {
		public Arch arch;
		public final List<String> baseRegs = new ArrayList<>();
		public final List<String> blocks = new ArrayList<>();
		public int accesses;
		public int referencesAdded;
		public int typed;
		public int named;
		public int conflicts;
		public long millis;

		public String toHtml() {
			StringBuilder sb = new StringBuilder("<html><body style='font-family:sans-serif'>");
			sb.append("<h3>AX-Clarity: เตรียมโปรแกรมเสร็จแล้ว</h3>");
			sb.append("<b>CPU:</b> ").append(esc(String.valueOf(arch))).append("<br>");
			sb.append("<b>Base register:</b> ")
					.append(baseRegs.isEmpty() ? "ไม่มี" : esc(String.join(", ", baseRegs)))
					.append("<br>");
			sb.append("<b>Memory block ใหม่:</b> ")
					.append(blocks.isEmpty() ? "ไม่มี" : esc(String.join(", ", blocks)))
					.append("<br>");
			sb.append("<b>การเข้าถึงตัวแปร global ที่ตามได้:</b> ").append(accesses).append("<br>");
			sb.append("<b>Xref ที่เพิ่ม:</b> ").append(referencesAdded).append("<br>");
			sb.append("<b>ตัวแปรที่ใส่ชนิด (u8/s16/...):</b> ").append(typed).append("<br>");
			sb.append("<b>ตัวแปรที่ตั้งชื่อ ram_/cal_/io_:</b> ").append(named).append("<br>");
			if (conflicts > 0) {
				sb.append("<b>ข้ามเพราะขนาดขัดกัน:</b> ").append(conflicts).append("<br>");
			}
			sb.append("<b>เวลา:</b> ").append(millis).append(" ms<br><br>");
			sb.append("กด Undo (Ctrl+Z) ครั้งเดียวเพื่อย้อนทุกอย่าง");
			sb.append("</body></html>");
			return sb.toString();
		}

		@Override
		public String toString() {
			return "arch=" + arch + " base=" + baseRegs + " blocks=" + blocks + " accesses=" + accesses +
				" refs=" + referencesAdded + " typed=" + typed + " named=" + named + " conflicts=" +
				conflicts + " ms=" + millis;
		}
	}

	private EcuPrep() {
	}

	static String esc(String s) {
		return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
	}

	/** Default options: every base register the finder is sure about. */
	public static Options defaults(List<BaseRegisterFinder.Result> found) {
		Options o = new Options();
		for (BaseRegisterFinder.Result r : found) {
			if (r.existing == null && r.chosen != null && r.confident) {
				o.baseValues.put(r.reg, r.chosen);
			}
		}
		return o;
	}

	/** Run all steps. Must be called inside a transaction. */
	public static Report run(Program program, Options opt, TaskMonitor monitor) throws Exception {
		long t0 = System.currentTimeMillis();
		Report rep = new Report();
		Arch arch = Arch.detect(program);
		rep.arch = arch;

		for (Map.Entry<Register, Long> e : opt.baseValues.entrySet()) {
			BaseRegisterFinder.apply(program, e.getKey(), e.getValue());
			rep.baseRegs.add(e.getKey().getName() + "=0x" + Long.toHexString(e.getValue()));
		}

		List<AccessCollector.Access> acc = AccessCollector.collect(program, monitor);
		rep.accesses = acc.size();

		if (opt.createBlocks) {
			List<MemoryPlanner.Planned> plan = MemoryPlanner.plan(program, arch, acc);
			MemoryPlanner.create(program, plan);
			for (MemoryPlanner.Planned p : plan) {
				rep.blocks.add(p.name() + " (" + p.start + "-" + p.end + ")");
			}
		}

		Memory mem = program.getMemory();
		if (opt.createReferences) {
			monitor.setMessage("AX-Clarity: adding cross references");
			ReferenceManager rm = program.getReferenceManager();
			Listing listing = program.getListing();
			for (AccessCollector.Access a : acc) {
				monitor.checkCancelled();
				if (!mem.contains(a.to)) {
					continue;
				}
				Instruction in = listing.getInstructionAt(a.from);
				if (in == null) {
					continue;
				}
				boolean exists = false;
				for (Reference r : rm.getReferencesFrom(a.from)) {
					if (r.getToAddress().equals(a.to)) {
						exists = true;
						break;
					}
				}
				if (exists) {
					continue;
				}
				int op = AccessCollector.operandFor(in, arch.baseRegisters);
				rm.addMemoryReference(a.from, a.to, a.write ? RefType.WRITE : RefType.READ,
					SourceType.ANALYSIS, op);
				rep.referencesAdded++;
			}
		}

		if (opt.typeGlobals || opt.nameGlobals) {
			typeAndName(program, acc, opt, rep, monitor);
		}
		if (opt.nameGlobals) {
			nameReferencedData(program, rep, monitor);
		}
		rep.millis = System.currentTimeMillis() - t0;
		return rep;
	}

	/** Table and pointer targets that code references (&amp;DAT_0003aedd) get role names too. */
	private static void nameReferencedData(Program program, Report rep, TaskMonitor monitor)
			throws CancelledException {
		Memory mem = program.getMemory();
		Listing listing = program.getListing();
		SymbolTable st = program.getSymbolTable();
		ReferenceManager rm = program.getReferenceManager();
		FunctionManager fm = program.getFunctionManager();
		Set<Address> done = new HashSet<>();
		monitor.setMessage("AX-Clarity: naming tables and pointers");
		InstructionIterator it = listing.getInstructions(true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction in = it.next();
			for (Reference r : rm.getReferencesFrom(in.getMinAddress())) {
				Address to = r.getToAddress();
				if (!r.isMemoryReference() || r.getReferenceType().isFlow() || !to.isMemoryAddress() ||
					!done.add(to)) {
					continue;
				}
				MemoryBlock blk = mem.getBlock(to);
				if (blk == null || listing.getInstructionContaining(to) != null ||
					fm.getFunctionAt(to) != null) {
					continue;
				}
				Symbol s = st.getPrimarySymbol(to);
				if (s != null && s.getSource() != SourceType.DEFAULT) {
					continue;
				}
				try {
					Symbol ns = st.createLabel(to, prefixFor(blk) + hex(to.getOffset()), SourceType.ANALYSIS);
					ns.setPrimary();
					rep.named++;
				}
				catch (Exception ex) {
					// keep the existing name
				}
			}
		}
	}

	/** Vote per address: width that most instructions use, sign from the load form. */
	private static void typeAndName(Program program, List<AccessCollector.Access> acc, Options opt,
			Report rep, TaskMonitor monitor) throws CancelledException {
		Memory mem = program.getMemory();
		Map<Address, Map<Integer, int[]>> votes = new HashMap<>(); // size -> {count, signed, unsigned}
		for (AccessCollector.Access a : acc) {
			if (!mem.contains(a.to)) {
				continue;
			}
			int[] v = votes.computeIfAbsent(a.to, k -> new HashMap<>())
					.computeIfAbsent(a.size, k -> new int[3]);
			v[0]++;
			if (a.sign == AccessCollector.SIGNED) {
				v[1]++;
			}
			else if (a.sign == AccessCollector.UNSIGNED) {
				v[2]++;
			}
		}

		// strongest evidence first, so a variable read 40 times wins over a stray byte access
		List<Object[]> cand = new ArrayList<>(); // {Address, size, count, signed}
		for (Map.Entry<Address, Map<Integer, int[]>> e : votes.entrySet()) {
			int bestSize = 0, bestCount = -1;
			int[] best = null;
			for (Map.Entry<Integer, int[]> s : e.getValue().entrySet()) {
				int c = s.getValue()[0];
				if (c > bestCount || (c == bestCount && s.getKey() > bestSize)) {
					bestSize = s.getKey();
					bestCount = c;
					best = s.getValue();
				}
			}
			boolean signed = best[1] > best[2];
			cand.add(new Object[] { e.getKey(), bestSize, bestCount, signed });
		}
		cand.sort((x, y) -> Integer.compare((int) y[2], (int) x[2]));

		DataTypeManager dtm = program.getDataTypeManager();
		Map<String, DataType> types = new HashMap<>();
		Listing listing = program.getListing();
		SymbolTable st = program.getSymbolTable();
		monitor.setMessage("AX-Clarity: typing and naming globals");
		monitor.initialize(cand.size());
		for (Object[] c : cand) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			Address a = (Address) c[0];
			int size = (int) c[1];
			boolean signed = (boolean) c[3];
			MemoryBlock blk = mem.getBlock(a);
			if (blk == null) {
				continue;
			}
			if (listing.getInstructionContaining(a) != null) {
				continue; // code, not a variable
			}
			if (opt.typeGlobals && size <= 8) {
				Data d = listing.getDataContaining(a);
				boolean free = d == null || (!d.isDefined() || Undefined.isUndefined(d.getDataType()));
				if (d != null && d.isDefined() && !Undefined.isUndefined(d.getDataType())) {
					free = false; // keep the analyst's own type
				}
				if (free) {
					DataType dt = typeFor(program, dtm, types, size, signed);
					try {
						Address end = a.add(size - 1);
						if (blk.contains(end) && listing.getInstructions(
							new ghidra.program.model.address.AddressSet(a, end), true).hasNext() == false &&
							!hasDefinedDataIn(listing, a, end)) {
							listing.clearCodeUnits(a, end, false);
							listing.createData(a, dt);
							rep.typed++;
						}
						else {
							rep.conflicts++;
						}
					}
					catch (CodeUnitInsertionException | RuntimeException ex) {
						rep.conflicts++;
					}
				}
			}
			if (opt.nameGlobals) {
				Symbol s = st.getPrimarySymbol(a);
				if (s == null || s.getSource() == SourceType.DEFAULT) {
					String name = prefixFor(blk) + hex(a.getOffset());
					try {
						Symbol ns = st.createLabel(a, name, SourceType.ANALYSIS);
						ns.setPrimary();
						rep.named++;
					}
					catch (Exception ex) {
						// name clash with an existing label: leave it
					}
				}
			}
		}
	}

	private static boolean hasDefinedDataIn(Listing listing, Address s, Address e) {
		DataIterator it = listing.getDefinedData(new ghidra.program.model.address.AddressSet(s, e), true);
		while (it.hasNext()) {
			Data d = it.next();
			if (!Undefined.isUndefined(d.getDataType())) {
				return true;
			}
		}
		return false;
	}

	static String hex(long v) {
		String h = Long.toHexString(v);
		while (h.length() < 4) {
			h = "0" + h;
		}
		return h;
	}

	/** ram_ for writable RAM, io_ for volatile peripherals, cal_ for ROM data. */
	public static String prefixFor(MemoryBlock b) {
		String n = b.getName().toUpperCase(Locale.ROOT);
		if (b.isVolatile() || n.startsWith("IO") || n.contains("SFR") || n.contains("PERIPH")) {
			return "io_";
		}
		if (!b.isInitialized()) {
			return "ram_";
		}
		// Ghidra's raw binary loader names the ROM block "ram"; only a non-executable,
		// initialized block called RAM is treated as RAM
		if (n.contains("RAM") && !b.isExecute()) {
			return "ram_";
		}
		return "cal_";
	}

	/** u8, s8, u16, s16, u32, s32, u64, s64 typedefs in /AX-Clarity. */
	public static DataType typeFor(Program program, DataTypeManager dtm, Map<String, DataType> cache,
			int size, boolean signed) {
		String name = (signed ? "s" : "u") + (size * 8);
		DataType have = cache.get(name);
		if (have != null) {
			return have;
		}
		DataOrganization org = dtm.getDataOrganization();
		DataType base;
		switch (size) {
			case 1:
				base = signed ? SignedByteDataType.dataType : ByteDataType.dataType;
				break;
			case 2:
				base = org.getShortSize() == 2 ? (signed ? ShortDataType.dataType : UnsignedShortDataType.dataType)
						: (signed ? IntegerDataType.dataType : UnsignedIntegerDataType.dataType);
				break;
			case 4:
				base = org.getIntegerSize() == 4
						? (signed ? IntegerDataType.dataType : UnsignedIntegerDataType.dataType)
						: (signed ? LongDataType.dataType : UnsignedLongDataType.dataType);
				break;
			case 8:
				base = signed ? LongLongDataType.dataType : UnsignedLongLongDataType.dataType;
				break;
			default:
				base = Undefined.getUndefinedDataType(size);
				name = "undefined" + size;
		}
		DataType dt = new TypedefDataType(new CategoryPath(CATEGORY), name, base, dtm);
		dt = dtm.addDataType(dt, DataTypeConflictHandler.KEEP_HANDLER);
		cache.put(name, dt);
		return dt;
	}
}
