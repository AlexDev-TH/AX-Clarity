/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

/**
 * CPU family of the open program and the facts AX-Clarity needs about it:
 * which registers hold a global base pointer and how to classify an address
 * that is accessed by code but has no memory block yet.
 */
public final class Arch {

	public enum Family {
		V850("V850"), RH850("RH850"), M16C("M16C"), R8C("R8C"), PPC("PowerPC"), OTHER("Other");

		public final String label;

		Family(String label) {
			this.label = label;
		}
	}

	public enum Role {
		RAM, IO
	}

	public final Family family;
	public final List<Register> baseRegisters;
	public final String processor;

	private Arch(Family family, List<Register> baseRegisters, String processor) {
		this.family = family;
		this.baseRegisters = Collections.unmodifiableList(baseRegisters);
		this.processor = processor;
	}

	public static Arch detect(Program program) {
		Language lang = program.getLanguage();
		String proc = lang.getProcessor().toString();
		String p = proc.toUpperCase(Locale.ROOT);
		String id = lang.getLanguageID().getIdAsString().toUpperCase(Locale.ROOT);
		Family f;
		if (p.contains("RH850") || id.startsWith("RH850")) {
			f = Family.RH850;
		}
		else if (p.contains("V850")) {
			f = Family.V850;
		}
		else if (p.contains("R8C")) {
			f = Family.R8C;
		}
		else if (p.contains("M16C") || p.contains("M32C")) {
			f = Family.M16C;
		}
		else if (p.contains("POWERPC") || p.contains("PPC")) {
			f = Family.PPC;
		}
		else {
			f = Family.OTHER;
		}
		String[] names;
		switch (f) {
			case V850:
			case RH850:
				names = new String[] { "gp", "tp", "ep" };
				break;
			case M16C:
			case R8C:
				names = new String[] { "SB" };
				break;
			case PPC:
				names = new String[] { "r2", "r13" };
				break;
			default:
				names = new String[0];
		}
		List<Register> regs = new ArrayList<>();
		for (String n : names) {
			Register r = findRegister(lang, n);
			if (r != null && !regs.contains(r)) {
				regs.add(r);
			}
		}
		return new Arch(f, regs, proc);
	}

	public static Register findRegister(Language lang, String name) {
		Register r = lang.getRegister(name);
		if (r == null) {
			r = lang.getRegister(name.toUpperCase(Locale.ROOT));
		}
		if (r == null) {
			r = lang.getRegister(name.toLowerCase(Locale.ROOT));
		}
		return r;
	}

	/** Classify an unmapped address that code reads or writes. */
	public Role roleOf(long offset) {
		long o = offset & 0xFFFFFFFFL;
		switch (family) {
			case V850:
			case RH850:
				return o >= 0xFF000000L ? Role.IO : Role.RAM;
			case M16C:
			case R8C:
				return o < 0x400 ? Role.IO : Role.RAM;
			case PPC:
				return o >= 0xC0000000L ? Role.IO : Role.RAM;
			default:
				return Role.RAM;
		}
	}

	/**
	 * True when an unmapped address is where this CPU family normally has RAM or
	 * peripherals. Other addresses usually come from code that was disassembled
	 * from data, so they need more evidence before a block is created.
	 */
	public boolean plausible(long offset) {
		long o = offset & 0xFFFFFFFFL;
		switch (family) {
			case V850:
			case RH850:
				return o >= 0xF0000000L || (o >= 0x03FF0000L && o <= 0x03FFFFFFL);
			case M16C:
			case R8C:
				return o < 0x100000L;
			case PPC:
				return (o >= 0x40000000L && o < 0x50000000L) || o >= 0xC0000000L;
			default:
				return true;
		}
	}

	/** Addresses where the role changes; a planned block never crosses one. */
	public long[] roleBoundaries() {
		switch (family) {
			case V850:
			case RH850:
				return new long[] { 0xFF000000L };
			case M16C:
			case R8C:
				return new long[] { 0x400L };
			case PPC:
				return new long[] { 0xC0000000L };
			default:
				return new long[0];
		}
	}

	@Override
	public String toString() {
		return family.label + " (" + processor + ")";
	}
}
