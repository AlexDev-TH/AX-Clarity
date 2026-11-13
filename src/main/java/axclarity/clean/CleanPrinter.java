/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.clean;

import java.util.*;
import java.util.regex.Pattern;

import axclarity.clean.CLex.K;
import axclarity.clean.CLex.T;
import axclarity.core.EcuPrep;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Turns Ghidra decompiler output into shorter C that reads like the original
 * source. Every rewrite keeps the meaning of the code; anything that cannot be
 * proven equivalent from the text is left untouched.
 */
public final class CleanPrinter {

	public static final class Line {
		public final String text;
		public final Address addr;

		public Line(String text, Address addr) {
			this.text = text;
			this.addr = addr;
		}
	}

	public static final class Result {
		public final List<Line> lines = new ArrayList<>();
		public int origLines, origChars, cleanLines, cleanChars;
		public final Map<String, Integer> fixes = new TreeMap<>();

		public String text() {
			StringBuilder sb = new StringBuilder();
			for (Line l : lines) {
				sb.append(l.text).append('\n');
			}
			return sb.toString();
		}

		public int totalFixes() {
			int n = 0;
			for (int v : fixes.values()) {
				n += v;
			}
			return n;
		}
	}

	private static final Set<String> KEYWORDS = new HashSet<>(Arrays.asList("if", "while", "for",
		"switch", "return", "sizeof", "do", "else", "case", "goto", "break", "continue", "default"));

	private static final Pattern NOISE_WARNING = Pattern.compile(
		"^\\s*/\\* WARNING: (Globals starting with '_' overlap|Removing unreachable block|" +
			"Restarted to delay deadcode elimination|Heritage AFTER dead removal|" +
			"Inserting \\(|Variable defined which should be unmapped|" +
			"Type propagation algorithm not settling|Removing unreachable).*\\*/\\s*$");

	private static final Pattern LOCAL_VAR = Pattern.compile("^[a-z]{1,4}Var(\\d+)$");
	private static final Pattern PARAM = Pattern.compile("^param_(\\d+)$");
	private static final Pattern EXT = Pattern.compile("^([ZS]EXT)(\\d)(\\d)$");
	private static final Pattern SUBP = Pattern.compile("^SUB(\\d)(\\d)$");

	private final Program program;
	private final CleanOptions opt;
	private final Map<String, String> typeMap = new HashMap<>();
	private final Set<String> typeNames = new HashSet<>();
	private final int intSize;
	private final Map<String, String> globalType = new HashMap<>();
	private final Map<String, String> calValue = new HashMap<>();
	private final Map<String, Boolean> dtmTypeCache = new HashMap<>();

	public CleanPrinter(Program program, CleanOptions opt) {
		this.program = program;
		this.opt = opt;
		DataOrganization org = program.getDataTypeManager().getDataOrganization();
		intSize = org.getIntegerSize();
		int longSize = org.getLongSize();
		int shortSize = org.getShortSize();
		put("u8", "byte", "uchar", "undefined1", "uint1", "undefined", "ubyte");
		put("s8", "char", "sbyte", "int1", "schar");
		put(w(shortSize, false), "ushort");
		put(w(shortSize, true), "short");
		put("u16", "undefined2", "uint2", "word");
		put("s16", "int2");
		put("u24", "undefined3", "uint3");
		put("s24", "int3");
		put(w(intSize, false), "uint");
		put(w(intSize, true), "int");
		put(w(longSize, false), "ulong");
		put(w(longSize, true), "long");
		put("u32", "undefined4", "uint4", "dword");
		put("s32", "int4");
		put("u64", "undefined8", "uint8", "ulonglong", "qword");
		put("s64", "longlong", "int8");
		typeNames.addAll(typeMap.keySet());
		typeNames.addAll(typeMap.values());
		typeNames.addAll(Arrays.asList("void", "bool", "float", "double", "code", "float10",
			"wchar_t", "pointer", "string", "undefined5", "undefined6", "undefined7"));
	}

	private static String w(int bytes, boolean signed) {
		return (signed ? "s" : "u") + (bytes * 8);
	}

	private void put(String to, String... from) {
		for (String f : from) {
			typeMap.put(f, to);
		}
	}

	// ===== entry points =====

	public Result clean(DecompileResults res) {
		List<String> text = new ArrayList<>();
		List<Address> addrs = new ArrayList<>();
		ClangTokenGroup g = res.getCCodeMarkup();
		if (g == null) {
			Result r = new Result();
			r.lines.add(new Line("/* decompile failed: " + res.getErrorMessage() + " */", null));
			return r;
		}
		for (ClangLine line : DecompilerUtils.toLines(g)) {
			StringBuilder sb = new StringBuilder(line.getIndentString());
			Address a = null;
			for (ClangToken t : line.getAllTokens()) {
				sb.append(t.getText());
				if (a == null && t.getMinAddress() != null) {
					a = t.getMinAddress();
				}
			}
			text.add(sb.toString());
			addrs.add(a);
		}
		return clean(text, addrs);
	}

	public Result clean(List<String> in, List<Address> addrs) {
		Result r = new Result();
		for (String s : in) {
			if (!s.isBlank()) {
				r.origLines++;
				r.origChars += s.strip().length();
			}
		}
		List<String> lines = new ArrayList<>(in);
		List<Address> ad = new ArrayList<>(addrs);

		Map<String, String> rename = opt.shortNames ? buildRenames(lines) : Map.of();
		for (int i = 0; i < lines.size(); i++) {
			lines.set(i, tokenPass(lines.get(i), rename, r));
		}
		Map<String, String> decl = declarations(lines);

		for (int i = 0; i < lines.size(); i++) {
			String s = lines.get(i);
			if (isComment(s)) {
				continue;
			}
			if (opt.removeNoise) {
				s = loop(s, x -> extPass(x, decl, r));
				s = loop(s, x -> m16cPointerPass(x, r));
			}
			if (opt.bitMacros) {
				s = bitAssignPass(s, decl, r);
				s = loop(s, x -> bitTestPass(x, r));
			}
			if (opt.smartCasts) {
				s = loop(s, x -> castPass(x, r));
				s = loop(s, x -> promotePass(x, decl, r));
			}
			if (opt.compact) {
				s = compactPass(s, r);
				s = loop(s, x -> parenPass(x, r));
			}
			if (opt.smartNumbers) {
				s = numberPass(s, r);
			}
			if (opt.calValues) {
				s = calPass(s, r);
			}
			lines.set(i, s);
		}
		finish(lines, ad, r);
		return r;
	}

	private interface Pass {
		String apply(String s);
	}

	private static String loop(String s, Pass p) {
		for (int i = 0; i < 12; i++) {
			String n = p.apply(s);
			if (n.equals(s)) {
				return n;
			}
			s = n;
		}
		return s;
	}

	private static boolean isComment(String s) {
		String t = s.strip();
		return t.startsWith("/*") || t.startsWith("//");
	}

	private static void count(Result r, String k) {
		r.fixes.merge(k, 1, Integer::sum);
	}

	private static String splice(String s, int a, int b, String with) {
		return s.substring(0, a) + with + s.substring(b);
	}

	// ===== pass 1: tokens =====

	private Map<String, String> buildRenames(List<String> lines) {
		Set<String> ids = new HashSet<>();
		for (String l : lines) {
			for (T t : CLex.lex(l)) {
				if (t.k == K.ID) {
					ids.add(t.s);
				}
			}
		}
		Map<String, String> m = new HashMap<>();
		for (String id : ids) {
			java.util.regex.Matcher v = LOCAL_VAR.matcher(id);
			java.util.regex.Matcher p = PARAM.matcher(id);
			String to = null;
			if (v.matches()) {
				to = "v" + v.group(1);
			}
			else if (p.matches()) {
				to = "arg" + p.group(1);
			}
			if (to != null && !ids.contains(to) && !m.containsValue(to)) {
				m.put(id, to);
			}
		}
		return m;
	}

	private String tokenPass(String s, Map<String, String> rename, Result r) {
		if (opt.hideInfoWarnings && NOISE_WARNING.matcher(s).matches()) {
			return s;
		}
		List<T> toks = CLex.lex(s);
		StringBuilder sb = new StringBuilder();
		int pos = 0;
		for (T t : toks) {
			sb.append(s, pos, t.a);
			pos = t.b;
			String out = t.s;
			if (t.k == K.ID) {
				if (opt.shortTypes && typeMap.containsKey(t.s)) {
					out = typeMap.get(t.s);
					if (!out.equals(t.s)) {
						count(r, "types");
					}
				}
				else if (rename.containsKey(t.s)) {
					out = rename.get(t.s);
					count(r, "names");
				}
				else if (opt.removeNoise && t.s.matches("_(DAT|ram|cal|io)_[0-9a-fA-F]+")) {
					out = t.s.substring(1);
					count(r, "noise");
				}
			}
			else if (t.k == K.CHR && opt.removeNoise) {
				// ECU code compares bytes, not text: '\x04' is the number 4
				Long v = CLex.charValue(t.s);
				if (v != null && (t.s.startsWith("'\\") || v < 0x20 || v > 0x7e)) {
					out = Long.toString(v); // 'M' stays 'M'
					count(r, "noise");
				}
			}
			sb.append(out);
		}
		sb.append(s.substring(pos));
		return sb.toString();
	}

	/** name to declared type, from the signature and local declarations. */
	private Map<String, String> declarations(List<String> lines) {
		Map<String, String> m = new HashMap<>();
		for (String l : lines) {
			if (isComment(l)) {
				continue;
			}
			List<T> s = CLex.sig(CLex.lex(l));
			// "TYPE [*]name;" or "TYPE name[N];"
			if (s.size() >= 3 && s.get(s.size() - 1).is(";") && s.get(0).k == K.ID &&
				isTypeName(s.get(0).s)) {
				int i = 1;
				while (i < s.size() && s.get(i).is("*")) {
					i++;
				}
				if (i < s.size() && s.get(i).k == K.ID &&
					(i + 1 == s.size() - 1 || s.get(i + 1).is("["))) {
					String type = s.get(0).s + (i > 1 ? " *" : "");
					m.put(s.get(i).s, type);
				}
			}
			// parameters inside a signature line "RET NAME(T a, T *b)"
			if (!l.startsWith(" ") && l.contains("(") && !l.strip().endsWith(";")) {
				for (int i = 0; i + 1 < s.size(); i++) {
					if (s.get(i).k == K.ID && isTypeName(s.get(i).s)) {
						int j = i + 1;
						while (j < s.size() && s.get(j).is("*")) {
							j++;
						}
						if (j < s.size() && s.get(j).k == K.ID && j + 1 < s.size() &&
							(s.get(j + 1).is(",") || s.get(j + 1).is(")"))) {
							m.put(s.get(j).s, s.get(i).s + (j > i + 1 ? " *" : ""));
						}
					}
				}
			}
		}
		return m;
	}

	boolean isTypeName(String id) {
		if (typeNames.contains(id)) {
			return true;
		}
		Boolean c = dtmTypeCache.get(id);
		if (c == null) {
			List<DataType> found = new ArrayList<>();
			program.getDataTypeManager().findDataTypes(id, found);
			c = !found.isEmpty();
			dtmTypeCache.put(id, c);
		}
		return c;
	}

	/** Type of an identifier: local declaration first, then the global's data type. */
	private String typeOf(String id, Map<String, String> decl) {
		String t = decl.get(id);
		if (t != null) {
			return t;
		}
		if (globalType.containsKey(id)) {
			return globalType.get(id);
		}
		String res = null;
		Address a = globalAddress(id);
		if (a != null) {
			Data d = program.getListing().getDataAt(a);
			if (d != null && d.isDefined()) {
				String n = d.getDataType().getName();
				res = typeMap.getOrDefault(n, n);
			}
		}
		globalType.put(id, res);
		return res;
	}

	private Address globalAddress(String id) {
		SymbolTable st = program.getSymbolTable();
		if (id.startsWith("DAT_") || id.startsWith("_DAT_")) {
			String h = id.substring(id.indexOf("DAT_") + 4);
			try {
				AddressSpace sp = program.getAddressFactory().getDefaultAddressSpace();
				return sp.getAddress(Long.parseUnsignedLong(h, 16));
			}
			catch (Exception e) {
				return null;
			}
		}
		List<Symbol> l = st.getGlobalSymbols(id);
		for (Symbol s : l) {
			if (s.getAddress().isMemoryAddress()) {
				return s.getAddress();
			}
		}
		return null;
	}

	private static int bitsOf(String type) {
		if (type == null) {
			return 0;
		}
		String t = type.strip();
		if (t.endsWith("*")) {
			return 0;
		}
		if (t.matches("[us](8|16|24|32|64)")) {
			return Integer.parseInt(t.substring(1));
		}
		if (t.equals("bool")) {
			return 8;
		}
		return 0;
	}

	private static boolean isUnsigned(String type) {
		return type != null && (type.startsWith("u") || type.equals("bool"));
	}

	private static boolean isSigned(String type) {
		return type != null && type.matches("s(8|16|24|32|64)");
	}

	// ===== casts and parsing helpers =====

	/** s[i] is "(" starting "(TYPE)" or "(TYPE *)"; returns index of ")" or -1. */
	private int castClose(List<T> s, int i) {
		if (!s.get(i).is("(") || i + 2 >= s.size()) {
			return -1;
		}
		int j = i + 1;
		if (s.get(j).k != K.ID || !isTypeName(s.get(j).s)) {
			return -1;
		}
		j++;
		while (j < s.size() && s.get(j).is("*")) {
			j++;
		}
		return j < s.size() && s.get(j).is(")") ? j : -1;
	}

	private boolean isPointerCast(List<T> s, int open, int close) {
		return close - 1 > open && s.get(close - 1).is("*");
	}

	/** End index (exclusive) of the unary expression that starts at s[i], or -1. */
	private int unaryEnd(List<T> s, int i) {
		if (i >= s.size()) {
			return -1;
		}
		T t = s.get(i);
		if (t.k == K.OP && (t.s.equals("*") || t.s.equals("-") || t.s.equals("!") ||
			t.s.equals("~") || t.s.equals("&") || t.s.equals("++") || t.s.equals("--"))) {
			return unaryEnd(s, i + 1);
		}
		int j;
		if (t.is("(")) {
			int cc = castClose(s, i);
			if (cc > 0) {
				return unaryEnd(s, cc + 1);
			}
			int c = CLex.match(s, i);
			if (c < 0) {
				return -1;
			}
			j = c + 1;
		}
		else if (t.k == K.ID || t.k == K.NUM || t.k == K.CHR || t.k == K.STR) {
			if (t.k == K.ID && KEYWORDS.contains(t.s)) {
				return -1;
			}
			j = i + 1;
		}
		else {
			return -1;
		}
		while (j < s.size()) {
			T p = s.get(j);
			if (p.is("(") || p.is("[")) {
				int c = CLex.match(s, j);
				if (c < 0) {
					return -1;
				}
				j = c + 1;
			}
			else if (p.is(".") || p.is("->")) {
				j += 2;
			}
			else if (p.is("++") || p.is("--")) {
				j++;
			}
			else {
				break;
			}
		}
		return j;
	}

	private boolean isCallParen(List<T> s, int open) {
		if (open == 0) {
			return false;
		}
		T p = s.get(open - 1);
		return p.k == K.ID && !KEYWORDS.contains(p.s) && !isTypeName(p.s);
	}

	/** Remove a value cast that C performs anyway: x = (T)y; return (T)y; f((T)y). */
	private String castPass(String line, Result r) {
		List<T> s = CLex.sig(CLex.lex(line));
		Deque<Boolean> callStack = new ArrayDeque<>();
		for (int i = 0; i < s.size(); i++) {
			T t = s.get(i);
			if (t.is("(")) {
				int cc = castClose(s, i);
				if (cc > 0 && !isPointerCast(s, i, cc) && i > 0) {
					T prev = s.get(i - 1);
					boolean assign = prev.is("=") || (prev.k == K.ID && prev.s.equals("return"));
					boolean arg = (prev.is("(") && isCallParen(s, i - 1)) ||
						(prev.is(",") && !callStack.isEmpty() && callStack.peek());
					if (assign || arg) {
						int end = unaryEnd(s, cc + 1);
						boolean ok = end > 0 && end < s.size() &&
							(assign ? s.get(end).is(";") : (s.get(end).is(",") || s.get(end).is(")")));
						if (ok && arg && s.get(end).is(")")) {
							// the ')' must close the call, not something inside the argument
							ok = CLex.matchBack(s, end) == findCallOpen(s, i);
						}
						if (ok) {
							T after = s.get(cc + 1);
							String rebuilt;
							int a = t.a;
							int b = s.get(end - 1).b;
							String operand = line.substring(after.a, b);
							if (after.is("(") && CLex.match(s, cc + 1) == end - 1 &&
								!hasTopLevelComma(s, cc + 1, end - 1)) {
								operand = line.substring(after.b, s.get(end - 1).a).strip();
							}
							rebuilt = operand;
							count(r, "casts");
							return splice(line, a, b, rebuilt);
						}
					}
				}
				callStack.push(isCallParen(s, i));
			}
			else if (t.is(")")) {
				if (!callStack.isEmpty()) {
					callStack.pop();
				}
			}
		}
		return line;
	}

	/**
	 * (s32)(s16)x to (s16)x and (s32)v where v is u8/s16: C promotes every type narrower
	 * than int to (signed) int before using it, so a cast to signed int adds nothing.
	 */
	private String promotePass(String line, Map<String, String> decl, Result r) {
		List<T> s = CLex.sig(CLex.lex(line));
		String sint = "s" + (intSize * 8);
		// (s16)(u16)v where v is u8: every cast is wider than v, so the value never changes,
		// and the outer type is promoted to int anyway
		for (int i = 0; i + 3 < s.size(); i++) {
			if (!s.get(i).is("(") || (i > 0 && s.get(i - 1).is(")"))) {
				continue;
			}
			List<Integer> widths = new ArrayList<>();
			List<Boolean> signs = new ArrayList<>();
			int j = i;
			while (j < s.size() && s.get(j).is("(")) {
				int cc = castClose(s, j);
				if (cc < 0 || isPointerCast(s, j, cc) || cc != j + 2) {
					break;
				}
				widths.add(bitsOf(s.get(j + 1).s));
				signs.add(isSigned(s.get(j + 1).s));
				j = cc + 1;
			}
			if (widths.isEmpty() || j >= s.size() || s.get(j).k != K.ID ||
				(j + 1 < s.size() && (s.get(j + 1).is("(") || s.get(j + 1).is("[") ||
					s.get(j + 1).is(".") || s.get(j + 1).is("->")))) {
				continue;
			}
			String vt = typeOf(s.get(j).s, decl);
			int w = bitsOf(vt);
			if (w == 0 || widths.get(0) == 0 || widths.get(0) > intSize * 8 ||
				(widths.get(0) == intSize * 8 && !signs.get(0))) {
				continue;
			}
			boolean ok = true;
			for (int k = 0; k < widths.size(); k++) {
				if (widths.get(k) <= w || (isSigned(vt) && !signs.get(k))) {
					ok = false;
				}
			}
			if (ok) {
				count(r, "casts");
				return splice(line, s.get(i).a, s.get(j).a, "");
			}
		}
		for (int i = 0; i + 3 < s.size(); i++) {
			if (!s.get(i).is("(") || !sint.equals(s.get(i + 1).s) || !s.get(i + 2).is(")")) {
				continue;
			}
			// a cast directly on the left side of an assignment target is not a value cast
			int j = i + 3;
			T nx = s.get(j);
			boolean narrower = false;
			if (nx.is("(")) {
				int cc = castClose(s, j);
				if (cc > 0 && !isPointerCast(s, j, cc)) {
					int b = bitsOf(s.get(j + 1).s);
					narrower = b > 0 && b < intSize * 8;
				}
			}
			else if (nx.k == K.ID && (j + 1 >= s.size() || !(s.get(j + 1).is("(") ||
				s.get(j + 1).is("[") || s.get(j + 1).is(".") || s.get(j + 1).is("->")))) {
				int b = bitsOf(typeOf(nx.s, decl));
				narrower = b > 0 && b < intSize * 8;
			}
			if (narrower) {
				count(r, "casts");
				return splice(line, s.get(i).a, nx.a, "");
			}
		}
		return line;
	}

	private static int findCallOpen(List<T> s, int i) {
		int depth = 0;
		for (int j = i - 1; j >= 0; j--) {
			T t = s.get(j);
			if (t.is(")")) {
				depth++;
			}
			else if (t.is("(")) {
				if (depth == 0) {
					return j;
				}
				depth--;
			}
		}
		return -1;
	}

	private static boolean hasTopLevelComma(List<T> s, int open, int close) {
		int depth = 0;
		for (int j = open + 1; j < close; j++) {
			T t = s.get(j);
			if (t.is("(") || t.is("[")) {
				depth++;
			}
			else if (t.is(")") || t.is("]")) {
				depth--;
			}
			else if (depth == 0 && t.is(",")) {
				return true;
			}
		}
		return false;
	}

	// ===== ZEXT/SEXT/SUB and M16C =====

	private String extPass(String line, Map<String, String> decl, Result r) {
		List<T> s = CLex.sig(CLex.lex(line));
		for (int i = 0; i + 1 < s.size(); i++) {
			T t = s.get(i);
			if (t.k != K.ID || !s.get(i + 1).is("(")) {
				continue;
			}
			java.util.regex.Matcher e = EXT.matcher(t.s);
			java.util.regex.Matcher sub = SUBP.matcher(t.s);
			int close = CLex.match(s, i + 1);
			if (close < 0) {
				continue;
			}
			String inner = line.substring(s.get(i + 1).b, s.get(close).a).strip();
			if (e.matches()) {
				boolean signed = e.group(1).equals("SEXT");
				int from = Integer.parseInt(e.group(2)), to = Integer.parseInt(e.group(3));
				boolean simple = unaryEnd(s, i + 2) == close;
				String operand = simple ? inner : "(" + inner + ")";
				String it = simple && i + 2 == close - 1 && s.get(i + 2).k == K.ID
						? typeOf(s.get(i + 2).s, decl) : null;
				String rep;
				boolean inPtr = i >= 2 && s.get(i - 1).is(")") && s.get(i - 2).is("*");
				if (!signed && inPtr) {
					rep = operand; // near pointer widened to a far address (M16C)
				}
				else if (!signed && isUnsigned(it) && bitsOf(it) == from * 8 && to <= intSize) {
					rep = operand;
				}
				else if (signed && isSigned(it) && bitsOf(it) == from * 8 && to <= intSize) {
					rep = operand;
				}
				else if (!signed && isUnsigned(it) && bitsOf(it) == from * 8) {
					rep = "(u" + (to * 8) + ")" + operand;
				}
				else if (signed && isSigned(it) && bitsOf(it) == from * 8) {
					rep = "(s" + (to * 8) + ")" + operand;
				}
				else {
					String p = signed ? "s" : "u";
					rep = "(" + p + (to * 8) + ")(" + p + (from * 8) + ")" + operand;
				}
				count(r, "noise");
				return splice(line, t.a, s.get(close).b, rep);
			}
			if (sub.matches()) {
				int to = Integer.parseInt(sub.group(2));
				int comma = -1, depth = 0;
				for (int j = i + 2; j < close; j++) {
					if (s.get(j).is("(") || s.get(j).is("[")) {
						depth++;
					}
					else if (s.get(j).is(")") || s.get(j).is("]")) {
						depth--;
					}
					else if (depth == 0 && s.get(j).is(",")) {
						comma = j;
					}
				}
				if (comma < 0) {
					continue;
				}
				String x = line.substring(s.get(i + 1).b, s.get(comma).a).strip();
				Long off = comma + 1 < close && s.get(comma + 1).k == K.NUM
						? CLex.intValue(s.get(comma + 1).s) : null;
				if (off == null || comma + 2 != close) {
					continue;
				}
				boolean simple = unaryEnd(s, i + 2) == comma;
				String xs = simple ? x : "(" + x + ")";
				String rep = off == 0 ? "(u" + (to * 8) + ")" + xs
						: "(u" + (to * 8) + ")(" + xs + " >> " + (off * 8) + ")";
				count(r, "noise");
				return splice(line, t.a, s.get(close).b, rep);
			}
		}
		return line;
	}

	/** *(T *)(u24)x  to  *(T *)x : 16-bit near pointer widened to a 20/24-bit address. */
	private String m16cPointerPass(String line, Result r) {
		List<T> s = CLex.sig(CLex.lex(line));
		for (int i = 2; i < s.size(); i++) {
			if (!s.get(i).is("(") || !s.get(i - 1).is(")") || !s.get(i - 2).is("*")) {
				continue;
			}
			int cc = castClose(s, i);
			if (cc < 0 || isPointerCast(s, i, cc)) {
				continue;
			}
			String ty = s.get(i + 1).s;
			if (!ty.equals("u24") && !ty.equals("uint3") && !ty.equals("u32") && !ty.equals("u16") &&
				!ty.equals("ushort") && !ty.equals("uint")) {
				continue;
			}
			int open = CLex.matchBack(s, i - 1);
			if (open < 0 || !isPointerCast(s, open, i - 1)) {
				continue;
			}
			count(r, "noise");
			return splice(line, s.get(i).a, s.get(cc).b, "");
		}
		return line;
	}

	// ===== bits =====

	private static int singleBit(long v) {
		return v != 0 && (v & (v - 1)) == 0 ? Long.numberOfTrailingZeros(v) : -1;
	}

	private String bitTestPass(String line, Result r) {
		List<T> s = CLex.sig(CLex.lex(line));
		for (int k = 3; k + 3 < s.size(); k++) {
			T num = s.get(k);
			if (num.k != K.NUM || !s.get(k - 1).is("&") || !s.get(k + 1).is(")")) {
				continue;
			}
			T cmp = s.get(k + 2);
			T zero = s.get(k + 3);
			if (!(cmp.is("!=") || cmp.is("==")) || zero.k != K.NUM || !"0".equals(zero.s)) {
				continue;
			}
			Long mask = CLex.intValue(num.s);
			if (mask == null || singleBit(mask) < 0) {
				continue;
			}
			int open = CLex.matchBack(s, k + 1);
			if (open < 0 || open >= k - 2) {
				continue;
			}
			// the left operand must not contain operators that bind looser than '&'
			boolean ok = true;
			int depth = 0;
			for (int j = open + 1; j < k - 1; j++) {
				T t = s.get(j);
				if (t.is("(") || t.is("[")) {
					depth++;
				}
				else if (t.is(")") || t.is("]")) {
					depth--;
				}
				else if (depth == 0 && t.k == K.OP && (t.s.equals("&") || t.s.equals("|") ||
					t.s.equals("^") || t.s.equals("&&") || t.s.equals("||") || t.s.equals("?") ||
					t.s.equals(":") || t.s.equals(",") || t.s.equals("==") || t.s.equals("!=") ||
					t.s.equals("<") || t.s.equals(">") || t.s.equals("<=") || t.s.equals(">=") ||
					t.s.endsWith("="))) {
					ok = false;
				}
			}
			if (!ok) {
				continue;
			}
			String x = line.substring(s.get(open + 1).a, s.get(k - 2).b);
			String rep = (cmp.is("==") ? "!" : "") + "BIT(" + x + ", " + singleBit(mask) + ")";
			count(r, "bits");
			return splice(line, s.get(open).a, zero.b, rep);
		}
		return line;
	}

	/** x |= 0x20;  x &= 0xdf;  x = x | 0x20;  as SETBIT / CLRBIT. */
	private String bitAssignPass(String line, Map<String, String> decl, Result r) {
		List<T> s = CLex.sig(CLex.lex(line));
		int n = s.size();
		if (n < 4 || !s.get(n - 1).is(";")) {
			return line;
		}
		int opIdx = -1;
		String op = null;
		for (int i = 1; i < n - 2; i++) {
			if (s.get(i).is("|=") || s.get(i).is("&=")) {
				opIdx = i;
				op = s.get(i).s.substring(0, 1);
				break;
			}
			if (s.get(i).is("=")) {
				// x = x | M ;
				String lhs = line.substring(s.get(0).a, s.get(i - 1).b);
				if (n - 4 >= i + 1 && (s.get(n - 3).is("|") || s.get(n - 3).is("&")) &&
					line.substring(s.get(i + 1).a, s.get(n - 4).b).equals(lhs)) {
					opIdx = i;
					op = s.get(n - 3).s;
				}
				break;
			}
		}
		if (opIdx < 0 || s.get(n - 2).k != K.NUM) {
			return line;
		}
		Long mask = CLex.intValue(s.get(n - 2).s);
		if (mask == null) {
			return line;
		}
		String lhs = line.substring(s.get(0).a, s.get(opIdx - 1).b);
		String indent = line.substring(0, s.get(0).a);
		if (op.equals("|")) {
			int b = singleBit(mask);
			if (b < 0) {
				return line;
			}
			count(r, "bits");
			return indent + "SETBIT(" + lhs + ", " + b + ");" + trailing(line, s.get(n - 1).b);
		}
		int width = lhsWidth(s, opIdx, decl);
		if (width == 0) {
			// no declared width: trust a mask written in full width (0xfe, 0xffdf, 0xffffffdf)
			width = mask <= 0xff ? 8 : mask <= 0xffff ? 16 : mask <= 0xffffffffL ? 32 : 64;
			long top = 1L << (width - 1);
			if ((mask & top) == 0) {
				return line;
			}
		}
		long full = width >= 64 ? -1L : (1L << width) - 1;
		if ((mask & ~full) != 0) {
			return line;
		}
		int b = singleBit(~mask & full);
		if (b < 0) {
			return line;
		}
		count(r, "bits");
		return indent + "CLRBIT(" + lhs + ", " + b + ");" + trailing(line, s.get(n - 1).b);
	}

	private static String trailing(String line, int from) {
		return line.substring(from);
	}

	private int lhsWidth(List<T> s, int opIdx, Map<String, String> decl) {
		if (opIdx == 1 && s.get(0).k == K.ID) {
			return bitsOf(typeOf(s.get(0).s, decl));
		}
		// *(T *)(...)
		if (s.get(0).is("*") && s.size() > 3 && s.get(1).is("(")) {
			int cc = castClose(s, 1);
			if (cc > 0 && isPointerCast(s, 1, cc) && cc - 1 == 3) {
				return bitsOf(s.get(2).s);
			}
		}
		return 0;
	}

	// ===== compact / numbers / cal =====

	private static final Set<String> COMPOUND_OPS =
		new HashSet<>(Arrays.asList("+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"));

	private String compactPass(String line, Result r) {
		String s = line;
		String before = s;
		s = s.replaceAll("\\+ -(?=[0-9])", "- ");
		s = s.replaceAll("- -(?=[0-9])", "+ ");
		s = s.replaceAll("\\+= -(?=[0-9])", "-= ");
		s = s.replaceAll("-= -(?=[0-9])", "+= ");
		List<T> sig = CLex.sig(CLex.lex(s));
		int n = sig.size();
		// x = x + y;  to  x += y;  (y must be one operand so precedence cannot change)
		if (n >= 6 && sig.get(n - 1).is(";") && sig.get(0).k != K.NUM &&
			!(sig.get(0).k == K.ID && KEYWORDS.contains(sig.get(0).s))) {
			int eq = -1, depth = 0;
			for (int i = 0; i < n; i++) {
				T t = sig.get(i);
				if (t.is("(") || t.is("[")) {
					depth++;
				}
				else if (t.is(")") || t.is("]")) {
					depth--;
				}
				else if (depth == 0 && t.is("=")) {
					eq = i;
					break;
				}
			}
			if (eq > 0) {
				int lhsLen = eq;
				String lhs = s.substring(sig.get(0).a, sig.get(eq - 1).b);
				int opIdx = eq + 1 + lhsLen;
				if (opIdx < n - 2 && s.substring(sig.get(eq + 1).a, sig.get(opIdx - 1).b).equals(lhs) &&
					sig.get(opIdx).k == K.OP && COMPOUND_OPS.contains(sig.get(opIdx).s) &&
					unaryEnd(sig, opIdx + 1) == n - 1) {
					String rest = s.substring(sig.get(opIdx + 1).a, sig.get(n - 2).b);
					s = s.substring(0, sig.get(0).a) + lhs + " " + sig.get(opIdx).s + "= " + rest + ";" +
						s.substring(sig.get(n - 1).b);
					sig = CLex.sig(CLex.lex(s));
					n = sig.size();
				}
			}
		}
		// -1 < (s32)x  to  0 <= (s32)x
		for (int i = 0; i + 4 < n; i++) {
			if (sig.get(i).is("-") && "1".equals(sig.get(i + 1).s) && sig.get(i + 2).is("<") &&
				sig.get(i + 3).is("(") && sig.get(i + 4).k == K.ID && isSigned(sig.get(i + 4).s) &&
				(i == 0 || sig.get(i - 1).is("(") || sig.get(i - 1).is("&&") || sig.get(i - 1).is("||"))) {
				s = s.substring(0, sig.get(i).a) + "0 <=" + s.substring(sig.get(i + 2).b);
				sig = CLex.sig(CLex.lex(s));
				n = sig.size();
				break;
			}
		}
		if (n >= 4 && sig.get(n - 1).is(";") && sig.get(n - 2).k == K.NUM &&
			"1".equals(sig.get(n - 2).s) && (sig.get(n - 3).is("+=") || sig.get(n - 3).is("-="))) {
			String inc = sig.get(n - 3).is("+=") ? "++" : "--";
			s = s.substring(0, sig.get(n - 3).a).stripTrailing() + inc + ";" + s.substring(sig.get(n - 1).b);
		}
		if (!s.equals(before)) {
			count(r, "compact");
		}
		return s;
	}

	/** ((!BIT(x, 2)) &amp;&amp; y)  to  (!BIT(x, 2) &amp;&amp; y): parentheses around one operand. */
	private String parenPass(String line, Result r) {
		List<T> s = CLex.sig(CLex.lex(line));
		for (int i = 1; i < s.size(); i++) {
			if (!s.get(i).is("(") || castClose(s, i) > 0) {
				continue;
			}
			T prev = s.get(i - 1);
			boolean open = prev.is("(") && !isCallParen(s, i - 1);
			if (!(open || prev.is("&&") || prev.is("||") || prev.is(","))) {
				continue;
			}
			int c = CLex.match(s, i);
			if (c < 0 || c + 1 >= s.size() || unaryEnd(s, i + 1) != c) {
				continue;
			}
			T nx = s.get(c + 1);
			if (!(nx.is(")") || nx.is("&&") || nx.is("||") || nx.is(","))) {
				continue;
			}
			if (prev.is(",") != nx.is(",") && !(prev.is(",") && nx.is(")"))) {
				continue; // only inside one argument list or one && / || chain
			}
			if (open && nx.is(")")) {
				continue; // if ((x)) is left alone
			}
			count(r, "compact");
			return line.substring(0, s.get(i).a) + line.substring(s.get(i).b, s.get(c).a) +
				line.substring(s.get(c).b);
		}
		return line;
	}

	private String numberPass(String line, Result r) {
		List<T> all = CLex.lex(line);
		List<T> s = CLex.sig(all);
		Map<T, Integer> idx = new IdentityHashMap<>();
		for (int i = 0; i < s.size(); i++) {
			idx.put(s.get(i), i);
		}
		// mark tokens inside the address expression of *(T *)( ... )
		boolean[] inPtr = new boolean[s.size()];
		for (int i = 2; i < s.size(); i++) {
			if (s.get(i).is("(") && s.get(i - 1).is(")")) {
				int open = CLex.matchBack(s, i - 1);
				if (open >= 0 && isPointerCast(s, open, i - 1)) {
					int c = CLex.match(s, i);
					for (int j = i; c > 0 && j <= c; j++) {
						inPtr[j] = true;
					}
				}
			}
		}
		// p - 0x11ff160 on a 32-bit CPU is really p + 0xfee00ea0 (a RAM address)
		Map<T, String> flip = new IdentityHashMap<>();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		int bits = space.getSize();
		for (int i = 1; i + 1 < s.size() && bits >= 24 && bits <= 32; i++) {
			T prevTok = s.get(i - 1);
			if (!s.get(i).is("-") || s.get(i + 1).k != K.NUM ||
				!(prevTok.k == K.ID || prevTok.k == K.NUM || prevTok.is(")") || prevTok.is("]"))) {
				continue;
			}
			Long v = CLex.intValue(s.get(i + 1).s);
			if (v == null || v < 0x10000 || v >= (1L << bits)) {
				continue;
			}
			long addr = (1L << bits) - v;
			try {
				if (program.getMemory().contains(space.getAddress(addr))) {
					flip.put(s.get(i), "+");
					flip.put(s.get(i + 1), "0x" + Long.toHexString(addr));
				}
			}
			catch (Exception e) {
				// not an address
			}
		}
		StringBuilder sb = new StringBuilder();
		int pos = 0;
		boolean changed = false;
		for (T t : all) {
			sb.append(line, pos, t.a);
			pos = t.b;
			String out = t.s;
			if (flip.containsKey(t)) {
				out = flip.get(t);
				changed = true;
			}
			else if (t.k == K.NUM && idx.containsKey(t)) {
				int i = idx.get(t);
				Long v = CLex.intValue(t.s);
				if (v != null) {
					String prev = i > 0 ? s.get(i - 1).s : "";
					String prev2 = i > 1 ? s.get(i - 2).s : "";
					String next = i + 1 < s.size() ? s.get(i + 1).s : "";
					String next2 = i + 2 < s.size() ? s.get(i + 2).s : "";
					boolean hex;
					if (prev.equals("<<") || prev.equals(">>") || prev.equals("<<=") || prev.equals(">>=")) {
						hex = false;
					}
					else if (prev.equals("&") || prev.equals("|") || prev.equals("^") ||
						prev.equals("&=") || prev.equals("|=") || prev.equals("^=") || prev.equals("~") ||
						next.equals("&") || next.equals("|") || next.equals("^")) {
						hex = true;
					}
					else if (inPtr[i] && !prev.equals("*") && !next.equals("*")) {
						hex = true;
					}
					else if (v >= 0x80000000L) {
						hex = true;
					}
					else if (v >= 0x10000 && ((v & (v - 1)) == 0 || (v & (v + 1)) == 0)) {
						hex = true; // 0x10000, 0x7fffff, 0xffffff read better as hex
					}
					else if ((v == 0xffL || v == 0xffffL || v == 0xffffffL) &&
						(prev.equals("=") || prev.equals("==") || prev.equals("!=") ||
							prev.equals("return") || next.equals("==") || next.equals("!="))) {
						hex = true; // 0xffff as "invalid" marker
					}
					else if (v >= 0x10000 && isMapped(v)) {
						hex = true;
						String sym = symbolAt(v);
						boolean operand = (prev.equals(",") || prev.equals("(") || prev.equals("=")) &&
							(next.equals(",") || next.equals(")") || next.equals(";"));
						if (sym != null && operand) {
							out = "&" + sym;
							changed = true;
							sb.append(out);
							continue;
						}
					}
					else if (asciiTag(v)) {
						hex = true; // 0x4750 is "GP"
					}
					else if (prev2.startsWith("io_") || next2.startsWith("io_")) {
						hex = true;
					}
					else {
						hex = false;
					}
					String suffix = t.s.replaceAll("^(0[xX][0-9a-fA-F]+|[0-9]+)", "");
					String nv = (hex && v != 0 ? "0x" + Long.toHexString(v) : Long.toString(v)) + suffix;
					if (!nv.equals(t.s)) {
						out = nv;
						changed = true;
					}
				}
			}
			sb.append(out);
		}
		sb.append(line.substring(pos));
		if (changed) {
			count(r, "numbers");
		}
		return sb.toString();
	}

	/** 0x4750 ("GP"): every byte printable, a letter among them, not a round decimal. */
	static boolean asciiTag(long v) {
		if (v < 0x2020 || v > 0xffffffffL || v % 10 == 0) {
			return false;
		}
		boolean letter = false;
		for (long x = v; x != 0; x >>>= 8) {
			long b = x & 0xff;
			if (b < 0x20 || b > 0x7e) {
				return false;
			}
			letter |= Character.isLetter((int) b);
		}
		return letter;
	}

	private String symbolAt(long v) {
		try {
			Address a = program.getAddressFactory().getDefaultAddressSpace().getAddress(v);
			Symbol s = program.getSymbolTable().getPrimarySymbol(a);
			if (s != null && s.getSource() != ghidra.program.model.symbol.SourceType.DEFAULT &&
				program.getListing().getInstructionAt(a) == null) {
				return s.getName();
			}
		}
		catch (Exception e) {
			// not an address
		}
		return null;
	}

	private boolean isMapped(long v) {
		AddressSpace sp = program.getAddressFactory().getDefaultAddressSpace();
		if (v < 0 || v > sp.getMaxAddress().getOffset()) {
			return false;
		}
		try {
			return program.getMemory().contains(sp.getAddress(v));
		}
		catch (Exception e) {
			return false;
		}
	}

	private String calPass(String line, Result r) {
		List<T> all = CLex.lex(line);
		List<T> s = CLex.sig(all);
		StringBuilder sb = new StringBuilder();
		int pos = 0;
		boolean changed = false;
		for (int i = 0; i < s.size(); i++) {
			T t = s.get(i);
			if (t.k != K.ID) {
				continue;
			}
			if (i + 1 < s.size() && (s.get(i + 1).s.endsWith("=") && !s.get(i + 1).is("==") &&
				!s.get(i + 1).is("!=") && !s.get(i + 1).is("<=") && !s.get(i + 1).is(">=") ||
				s.get(i + 1).is("(") || s.get(i + 1).is("[") || s.get(i + 1).is("."))) {
				continue;
			}
			if (i > 0 && s.get(i - 1).is("&")) {
				// address-of only when unary
				if (i < 2 || s.get(i - 2).k == K.OP && !s.get(i - 2).is(")")) {
					continue;
				}
			}
			String v = calValueOf(t.s);
			if (v == null) {
				continue;
			}
			sb.append(line, pos, t.b).append("/*=").append(v).append("*/");
			pos = t.b;
			changed = true;
		}
		if (!changed) {
			return line;
		}
		sb.append(line.substring(pos));
		count(r, "calValues");
		return sb.toString();
	}

	private String calValueOf(String id) {
		if (calValue.containsKey(id)) {
			return calValue.get(id);
		}
		String res = null;
		if (!KEYWORDS.contains(id) && !typeNames.contains(id)) {
			Address a = globalAddress(id);
			if (a != null) {
				MemoryBlock b = program.getMemory().getBlock(a);
				if (b != null && b.isInitialized() && EcuPrep.prefixFor(b).equals("cal_")) {
					Data d = program.getListing().getDataAt(a);
					if (d != null && d.isDefined() && d.getLength() <= 4 && d.getValue() instanceof Scalar) {
						Scalar sc = (Scalar) d.getValue();
						DataType dt = d.getDataType();
						if (dt instanceof TypeDef) {
							dt = ((TypeDef) dt).getBaseDataType();
						}
						boolean signed = dt instanceof AbstractIntegerDataType &&
							((AbstractIntegerDataType) dt).isSigned();
						res = Long.toString(signed ? sc.getSignedValue() : sc.getUnsignedValue());
					}
				}
			}
		}
		calValue.put(id, res);
		return res;
	}

	// ===== function level =====

	private void finish(List<String> lines, List<Address> addrs, Result r) {
		List<Line> out = new ArrayList<>();
		for (int i = 0; i < lines.size(); i++) {
			String s = lines.get(i);
			if (opt.hideInfoWarnings && NOISE_WARNING.matcher(s).matches()) {
				count(r, "warnings");
				continue;
			}
			out.add(new Line(s, i < addrs.size() ? addrs.get(i) : null));
		}
		if (opt.compact) {
			// no blank line between the signature and "{"
			for (int i = 1; i + 1 < out.size(); i++) {
				if (out.get(i).text.isBlank() && out.get(i + 1).text.equals("{") &&
					!out.get(i - 1).text.isBlank()) {
					out.remove(i);
					break;
				}
			}
			// drop "return;" right before the function's closing brace
			int last = out.size() - 1;
			while (last >= 0 && out.get(last).text.isBlank()) {
				last--;
			}
			if (last > 0 && out.get(last).text.equals("}")) {
				int p = last - 1;
				while (p >= 0 && out.get(p).text.isBlank()) {
					p--;
				}
				if (p >= 0 && out.get(p).text.strip().equals("return;") &&
					out.get(p).text.indexOf('r') <= 2) {
					out.remove(p);
					count(r, "compact");
				}
			}
		}
		// trim leading blanks and collapse runs of blank lines
		List<Line> fin = new ArrayList<>();
		boolean blank = true;
		for (Line l : out) {
			if (l.text.isBlank()) {
				if (blank) {
					continue;
				}
				blank = true;
			}
			else {
				blank = false;
			}
			fin.add(l);
		}
		while (!fin.isEmpty() && fin.get(fin.size() - 1).text.isBlank()) {
			fin.remove(fin.size() - 1);
		}
		boolean bits = false;
		for (Line l : fin) {
			if (l.text.contains("BIT(")) {
				bits = true;
				break;
			}
		}
		if (bits) {
			fin.add(0, new Line("// BIT(x,n) = bit n of x   SETBIT/CLRBIT(x,n) = set/clear bit n", null));
		}
		r.lines.addAll(fin);
		for (Line l : fin) {
			if (!l.text.isBlank() && !l.text.startsWith("// BIT(")) {
				r.cleanLines++;
				r.cleanChars += l.text.strip().length();
			}
		}
	}
}
