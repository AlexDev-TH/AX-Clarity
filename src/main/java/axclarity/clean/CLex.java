/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.clean;

import java.util.ArrayList;
import java.util.List;

/** Small C lexer for one line of decompiler output. Keeps exact character spans. */
final class CLex {

	enum K {
		WS, ID, NUM, CHR, STR, CMT, OP
	}

	static final class T {
		final K k;
		final String s;
		final int a, b;

		T(K k, String s, int a, int b) {
			this.k = k;
			this.s = s;
			this.a = a;
			this.b = b;
		}

		boolean is(String x) {
			return (k == K.OP) && s.equals(x);
		}

		@Override
		public String toString() {
			return k + ":" + s;
		}
	}

	private static final String[] OPS3 = { "<<=", ">>=", "..." };
	private static final String[] OPS2 = { "->", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&",
		"||", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "::" };

	private CLex() {
	}

	static List<T> lex(String s) {
		List<T> out = new ArrayList<>();
		int i = 0, n = s.length();
		while (i < n) {
			char c = s.charAt(i);
			int st = i;
			if (c == ' ' || c == '\t') {
				while (i < n && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) {
					i++;
				}
				out.add(new T(K.WS, s.substring(st, i), st, i));
			}
			else if (c == '/' && i + 1 < n && s.charAt(i + 1) == '*') {
				int e = s.indexOf("*/", i + 2);
				i = e < 0 ? n : e + 2;
				out.add(new T(K.CMT, s.substring(st, i), st, i));
			}
			else if (c == '/' && i + 1 < n && s.charAt(i + 1) == '/') {
				i = n;
				out.add(new T(K.CMT, s.substring(st, i), st, i));
			}
			else if (Character.isLetter(c) || c == '_') {
				while (i < n && (Character.isLetterOrDigit(s.charAt(i)) || s.charAt(i) == '_')) {
					i++;
				}
				out.add(new T(K.ID, s.substring(st, i), st, i));
			}
			else if (Character.isDigit(c)) {
				if (c == '0' && i + 1 < n && (s.charAt(i + 1) == 'x' || s.charAt(i + 1) == 'X')) {
					i += 2;
					while (i < n && Character.digit(s.charAt(i), 16) >= 0) {
						i++;
					}
				}
				else {
					while (i < n && (Character.isDigit(s.charAt(i)) || s.charAt(i) == '.')) {
						i++;
					}
				}
				while (i < n && "uUlLfF".indexOf(s.charAt(i)) >= 0) {
					i++;
				}
				out.add(new T(K.NUM, s.substring(st, i), st, i));
			}
			else if (c == '\'' || c == '"') {
				i++;
				while (i < n && s.charAt(i) != c) {
					if (s.charAt(i) == '\\') {
						i++;
					}
					i++;
				}
				i = Math.min(n, i + 1);
				out.add(new T(c == '\'' ? K.CHR : K.STR, s.substring(st, i), st, i));
			}
			else {
				String op = null;
				for (String o : OPS3) {
					if (s.startsWith(o, i)) {
						op = o;
						break;
					}
				}
				if (op == null) {
					for (String o : OPS2) {
						if (s.startsWith(o, i)) {
							op = o;
							break;
						}
					}
				}
				if (op == null) {
					op = String.valueOf(c);
				}
				i += op.length();
				out.add(new T(K.OP, op, st, i));
			}
		}
		return out;
	}

	/** Tokens without whitespace and comments. */
	static List<T> sig(List<T> all) {
		List<T> out = new ArrayList<>();
		for (T t : all) {
			if (t.k != K.WS && t.k != K.CMT) {
				out.add(t);
			}
		}
		return out;
	}

	/** Index of the bracket matching s[i] ( '(' or '[' ), or -1. */
	static int match(List<T> s, int i) {
		String open = s.get(i).s;
		String close = open.equals("(") ? ")" : open.equals("[") ? "]" : null;
		if (close == null) {
			return -1;
		}
		int depth = 0;
		for (int j = i; j < s.size(); j++) {
			T t = s.get(j);
			if (t.k != K.OP) {
				continue;
			}
			if (t.s.equals(open)) {
				depth++;
			}
			else if (t.s.equals(close)) {
				depth--;
				if (depth == 0) {
					return j;
				}
			}
		}
		return -1;
	}

	/** Index of the '(' matching the ')' at s[i], or -1. */
	static int matchBack(List<T> s, int i) {
		int depth = 0;
		for (int j = i; j >= 0; j--) {
			T t = s.get(j);
			if (t.k != K.OP) {
				continue;
			}
			if (t.s.equals(")")) {
				depth++;
			}
			else if (t.s.equals("(")) {
				depth--;
				if (depth == 0) {
					return j;
				}
			}
		}
		return -1;
	}

	/** Parse a C integer literal, or null. */
	static Long intValue(String num) {
		String t = num;
		while (!t.isEmpty() && "uUlL".indexOf(t.charAt(t.length() - 1)) >= 0) {
			t = t.substring(0, t.length() - 1);
		}
		try {
			if (t.startsWith("0x") || t.startsWith("0X")) {
				return Long.parseUnsignedLong(t.substring(2), 16);
			}
			if (t.contains(".") || t.isEmpty()) {
				return null;
			}
			return Long.parseLong(t);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	/** Value of a C character literal such as '\x04', '\0', 'U', or null. */
	static Long charValue(String lit) {
		if (lit.length() < 3 || lit.charAt(0) != '\'' || lit.charAt(lit.length() - 1) != '\'') {
			return null;
		}
		String b = lit.substring(1, lit.length() - 1);
		if (b.length() == 1) {
			return (long) b.charAt(0);
		}
		if (b.charAt(0) != '\\') {
			return null;
		}
		String e = b.substring(1);
		switch (e) {
			case "0":
				return 0L;
			case "a":
				return 7L;
			case "b":
				return 8L;
			case "t":
				return 9L;
			case "n":
				return 10L;
			case "v":
				return 11L;
			case "f":
				return 12L;
			case "r":
				return 13L;
			case "\\":
				return 92L;
			case "'":
				return 39L;
			case "\"":
				return 34L;
			default:
		}
		try {
			if (e.startsWith("x")) {
				return Long.parseLong(e.substring(1), 16);
			}
			return Long.parseLong(e, 8);
		}
		catch (NumberFormatException ex) {
			return null;
		}
	}
}
