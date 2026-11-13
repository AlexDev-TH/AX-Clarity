/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.ui;

import java.util.*;

import javax.swing.text.*;

/** Colors one line of C into a StyledDocument. */
final class SyntaxColor {

	private static final Set<String> KEYWORDS = new HashSet<>(Arrays.asList("if", "else", "while",
		"for", "do", "switch", "case", "default", "return", "break", "continue", "goto", "sizeof",
		"struct", "union", "enum", "typedef", "const", "volatile", "static", "extern"));
	private static final Set<String> TYPES = new HashSet<>(Arrays.asList("u8", "s8", "u16", "s16",
		"u24", "s24", "u32", "s32", "u64", "s64", "void", "bool", "char", "short", "int", "long",
		"uint", "ushort", "uchar", "byte", "ulong", "float", "double", "code", "undefined",
		"undefined1", "undefined2", "undefined3", "undefined4", "undefined8", "uint3", "sbyte",
		"longlong", "ulonglong", "true", "false", "NULL"));
	private static final Set<String> MACROS = new HashSet<>(Arrays.asList("BIT", "SETBIT", "CLRBIT",
		"CONCAT11", "CONCAT12", "CONCAT21", "CONCAT22", "CONCAT13", "CONCAT31", "CONCAT14",
		"CONCAT41", "CONCAT44", "CARRY1", "CARRY2", "CARRY4", "SCARRY1", "SCARRY2", "SCARRY4",
		"SBORROW1", "SBORROW2", "SBORROW4"));

	private SyntaxColor() {
	}

	static void append(StyledDocument doc, String line, Palette p) throws BadLocationException {
		int i = 0, n = line.length();
		while (i < n) {
			char c = line.charAt(i);
			int st = i;
			AttributeSet a = p.plain;
			if (c == '/' && i + 1 < n && (line.charAt(i + 1) == '*' || line.charAt(i + 1) == '/')) {
				if (line.charAt(i + 1) == '/') {
					i = n;
				}
				else {
					int e = line.indexOf("*/", i + 2);
					i = e < 0 ? n : e + 2;
				}
				a = line.startsWith("/*=", st) ? p.number : p.comment;
			}
			else if (Character.isLetter(c) || c == '_') {
				while (i < n && (Character.isLetterOrDigit(line.charAt(i)) || line.charAt(i) == '_')) {
					i++;
				}
				String id = line.substring(st, i);
				int j = i;
				while (j < n && line.charAt(j) == ' ') {
					j++;
				}
				boolean call = j < n && line.charAt(j) == '(';
				if (KEYWORDS.contains(id)) {
					a = p.keyword;
				}
				else if (MACROS.contains(id)) {
					a = p.macro;
				}
				else if (TYPES.contains(id)) {
					a = p.type;
				}
				else if (id.startsWith("cal_")) {
					a = p.cal;
				}
				else if (id.startsWith("ram_") || id.startsWith("DAT_")) {
					a = p.ram;
				}
				else if (id.startsWith("io_")) {
					a = p.io;
				}
				else if (id.startsWith("unaff_") || id.startsWith("in_") || id.startsWith("extraout_")) {
					a = p.warn;
				}
				else if (call) {
					a = p.func;
				}
			}
			else if (Character.isDigit(c)) {
				while (i < n && (Character.isLetterOrDigit(line.charAt(i)) || line.charAt(i) == '.')) {
					i++;
				}
				a = p.number;
			}
			else {
				i++;
			}
			doc.insertString(doc.getLength(), line.substring(st, i), a);
		}
	}
}
