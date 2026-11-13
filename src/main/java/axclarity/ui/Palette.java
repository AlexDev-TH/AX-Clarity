/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.ui;

import java.awt.Color;

import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

/** Syntax colors for light and dark Ghidra themes. */
final class Palette {
	final SimpleAttributeSet plain, keyword, type, number, comment, cal, ram, io, func, macro, warn;

	private Palette(boolean dark) {
		plain = style(dark ? 0xD4D4D4 : 0x1E1E1E, false);
		keyword = style(dark ? 0xC586C0 : 0x8E24AA, true);
		type = style(dark ? 0x4EC9B0 : 0x00796B, false);
		number = style(dark ? 0xB5CEA8 : 0x2E7D32, false);
		comment = style(dark ? 0x6A9955 : 0x7A7A7A, false);
		cal = style(dark ? 0xFFB454 : 0xC25E00, true);
		ram = style(dark ? 0x9CDCFE : 0x0D47A1, false);
		io = style(dark ? 0xFF7B9C : 0xC2185B, true);
		func = style(dark ? 0xDCDCAA : 0x795E26, false);
		macro = style(dark ? 0xFFD166 : 0xB8860B, true);
		warn = style(dark ? 0xFF5555 : 0xD32F2F, false);
		StyleConstants.setUnderline(warn, true);
	}

	private static SimpleAttributeSet style(int rgb, boolean bold) {
		SimpleAttributeSet s = new SimpleAttributeSet();
		StyleConstants.setForeground(s, new Color(rgb));
		StyleConstants.setBold(s, bold);
		return s;
	}

	static Palette forBackground(Color bg) {
		boolean dark = bg != null && (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) < 128;
		return new Palette(dark);
	}
}
