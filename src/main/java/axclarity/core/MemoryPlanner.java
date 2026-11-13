/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.core;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Plans RAM and peripheral (I/O) blocks for addresses that code accesses but
 * that are not mapped yet. Without a block the decompiler prints
 * {@code *(ushort *)0xfee00e02} instead of a named variable.
 */
public final class MemoryPlanner {

	public static final class Planned {
		public final Address start;
		public final Address end;
		public final Arch.Role role;
		public final int accesses;
		public boolean enabled = true;

		Planned(Address start, Address end, Arch.Role role, int accesses) {
			this.start = start;
			this.end = end;
			this.role = role;
			this.accesses = accesses;
		}

		public String name() {
			return (role == Arch.Role.IO ? "IO_" : "RAM_") +
				Long.toHexString(start.getOffset()).toUpperCase(Locale.ROOT);
		}

		public long length() {
			return end.subtract(start) + 1;
		}

		@Override
		public String toString() {
			return name() + " " + start + "-" + end + " (" + accesses + " accesses)";
		}
	}

	static final long GAP = 0x4000;
	static final long ALIGN = 0x1000;
	/** accesses needed before mapping an address range the CPU family does not normally use */
	static final int MIN_UNUSUAL = 64;

	private MemoryPlanner() {
	}

	public static List<Planned> plan(Program program, Arch arch, Collection<AccessCollector.Access> accesses) {
		Memory mem = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		TreeMap<Long, Integer> hits = new TreeMap<>();
		for (AccessCollector.Access a : accesses) {
			if (a.to.getAddressSpace() != space || mem.contains(a.to)) {
				continue;
			}
			hits.merge(a.to.getOffset(), 1, Integer::sum);
		}
		List<Planned> out = new ArrayList<>();
		if (hits.isEmpty()) {
			return out;
		}
		long max = space.getMaxAddress().getOffset();
		long[] bounds = arch.roleBoundaries();

		// cluster by gap and role
		List<long[]> clusters = new ArrayList<>(); // {lo, hi, count}
		long lo = -1, hi = -1, cnt = 0;
		Arch.Role role = null;
		for (Map.Entry<Long, Integer> e : hits.entrySet()) {
			long o = e.getKey();
			Arch.Role r = arch.roleOf(o);
			if (lo < 0) {
				lo = hi = o;
				cnt = e.getValue();
				role = r;
				continue;
			}
			if (o - hi > GAP || r != role) {
				clusters.add(new long[] { lo, hi, cnt });
				lo = o;
				cnt = 0;
				role = r;
			}
			hi = o;
			cnt += e.getValue();
		}
		clusters.add(new long[] { lo, hi, cnt });

		for (long[] c : clusters) {
			Arch.Role r = arch.roleOf(c[0]);
			long s = c[0] - (c[0] % ALIGN);
			long e = c[1] + 8; // room for the widest access
			e = e - (e % ALIGN) + ALIGN - 1;
			if (e > max || e < s) {
				e = max;
			}
			// never cross a role boundary
			for (long b : bounds) {
				if (s < b && e >= b) {
					if (c[0] < b) {
						e = b - 1;
					}
					else {
						s = b;
					}
				}
			}
			AddressSet want = new AddressSet(space.getAddress(s), space.getAddress(e));
			AddressSet free = want.subtract(mem);
			for (AddressRange ar : free) {
				int n = 0;
				for (Map.Entry<Long, Integer> h : hits.subMap(ar.getMinAddress().getOffset(), true,
					ar.getMaxAddress().getOffset(), true).entrySet()) {
					n += h.getValue();
				}
				boolean ok = arch.plausible(ar.getMinAddress().getOffset()) ? n > 0 : n >= MIN_UNUSUAL;
				if (ok) {
					out.add(new Planned(ar.getMinAddress(), ar.getMaxAddress(), r, n));
				}
			}
		}
		// merge touching blocks with the same role
		out.sort(Comparator.comparing(p -> p.start));
		List<Planned> merged = new ArrayList<>();
		for (Planned p : out) {
			if (!merged.isEmpty()) {
				Planned last = merged.get(merged.size() - 1);
				if (last.role == p.role && last.end.next() != null && last.end.next().equals(p.start)) {
					merged.set(merged.size() - 1,
						new Planned(last.start, p.end, p.role, last.accesses + p.accesses));
					continue;
				}
			}
			merged.add(p);
		}
		return merged;
	}

	/** Create the enabled blocks. Requires a transaction. */
	public static int create(Program program, List<Planned> plans) throws Exception {
		Memory mem = program.getMemory();
		int n = 0;
		for (Planned p : plans) {
			if (!p.enabled || mem.intersects(p.start, p.end)) {
				continue;
			}
			String name = p.name();
			int i = 2;
			while (mem.getBlock(name) != null) {
				name = p.name() + "_" + (i++);
			}
			MemoryBlock b = mem.createUninitializedBlock(name, p.start, p.length(), false);
			b.setRead(true);
			b.setWrite(true);
			b.setExecute(false);
			b.setVolatile(p.role == Arch.Role.IO);
			b.setComment("Created by AX-Clarity (" + p.accesses + " code accesses)");
			n++;
		}
		return n;
	}
}
