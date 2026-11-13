/* AX-Clarity by AlexDev-TH. MIT License. */
// Smoke test: plugin metadata, prepare dialog construction, clean printer rules on fixed input.
//@category AX-Clarity
import java.util.*;

import axclarity.AXClarityPlugin;
import axclarity.clean.CleanOptions;
import axclarity.clean.CleanPrinter;
import axclarity.core.Arch;
import axclarity.core.BaseRegisterFinder;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.program.model.address.Address;

public class AXClaritySmokeTest extends GhidraScript {

	private int fails;

	private void check(String name, String got, String want) {
		if (!got.equals(want)) {
			fails++;
			println("FAIL " + name + "\n   got : " + got + "\n   want: " + want);
		}
		else {
			println("ok   " + name);
		}
	}

	private String clean(String... lines) {
		List<Address> a = new ArrayList<>();
		for (int i = 0; i < lines.length; i++) {
			a.add(null);
		}
		CleanPrinter.Result r = new CleanPrinter(currentProgram, new CleanOptions()).clean(Arrays.asList(lines), a);
		StringBuilder sb = new StringBuilder();
		for (CleanPrinter.Line l : r.lines) {
			if (l.text.startsWith("// BIT(")) {
				continue;
			}
			sb.append(l.text).append("\n");
		}
		return sb.toString();
	}

	@Override
	protected void run() throws Exception {
		PluginDescription pd = PluginDescription.getPluginDescription(AXClarityPlugin.class);
		println("plugin: " + pd.getName() + " package=" + pd.getPluginPackage().getName() + " status=" +
			pd.getStatus());

		Arch arch = Arch.detect(currentProgram);
		List<BaseRegisterFinder.Result> found = new ArrayList<>();
		try {
			new axclarity.ui.PrepDialog(arch, found);
			println("ok   PrepDialog constructs");
		}
		catch (java.awt.HeadlessException e) {
			println("skip PrepDialog (headless JVM)");
		}

		boolean m16 = currentProgram.getDataTypeManager().getDataOrganization().getIntegerSize() == 2;
		String s32 = m16 ? "s16" : "s32";
		String u32 = m16 ? "u16" : "u32";

		check("types + names", clean("void f(void)", "{", "  ushort uVar1;", "  uVar1 = 3;", "  return;", "}"),
			"void f(void)\n{\n  u16 v1;\n  v1 = 3;\n}\n");
		check("bit test", clean("  if ((bVar1 & 0x20) != 0) {"), "  if (BIT(v1, 5)) {\n");
		check("bit test zero", clean("  if ((DAT_00000700 & 4) == 0) {"), "  if (!BIT(DAT_00000700, 2)) {\n");
		check("set bit", clean("  bVar1 |= 0x20;"), "  SETBIT(v1, 5);\n");
		check("clear bit full width mask", clean("  bVar1 &= 0xdf;"), "  CLRBIT(v1, 5);\n");
		check("clear bit needs width", clean("  bVar1 &= 0x7f;"), "  v1 &= 0x7f;\n");
		check("clear bit with declared width",
			clean("  byte bVar1;", "  bVar1 &= 0x7f;"), "  u8 v1;\n  CLRBIT(v1, 7);\n");
		check("assign cast removed", clean("  uVar1 = (ushort)uVar3;"), "  v1 = v3;\n");
		check("assign cast + parens removed", clean("  uVar1 = (ushort)(a + b);"), "  v1 = a + b;\n");
		check("partial cast kept", clean("  uVar1 = (ushort)uVar3 >> 3;"), "  v1 = (u16)v3 >> 3;\n");
		check("arg cast removed", clean("  FUN_1234((ushort)uVar3,(char)x);"), "  FUN_1234(v3,x);\n");
		check("if cast kept", clean("  if ((char)uVar3) {"), "  if ((s8)v3) {\n");
		check("compound", clean("  DAT_00000412 = DAT_00000412 + 1;"), "  DAT_00000412++;\n");
		check("compound keeps precedence", clean("  x = x - a + b;"), "  x = x - a + b;\n");
		check("plus minus", clean("  x = y + -1;"), "  x = y - 1;\n");
		check("char literal", clean("  if (cVar1 == '\\x04') {"), "  if (v1 == 4) {\n");
		check("shift decimal", clean("  x = y >> 0x15;"), "  x = y >> 21;\n");
		check("mask hex", clean("  x = y & 0x3f;"), "  x = y & 0x3f;\n");
		check("arith decimal", clean("  x = y * 0x3e8;"), "  x = y * 1000;\n");
		check("promotion cast", clean("  short sVar2;", "  x = (" + (m16 ? "int" : "int") + ")sVar2 * y;"),
			"  s16 v2;\n  x = " + (m16 ? "(s16)v2" : "v2") + " * y;\n");
		check("widening chain on u8 dropped", clean("  byte bVar1;", "  x = (short)(ushort)bVar1 * y;"),
			"  u8 v1;\n  x = v1 * y;\n");
		check("chain on s8 kept", clean("  char cVar1;", "  x = (short)(ushort)cVar1 * y;"),
			"  s8 v1;\n  x = (s16)(u16)v1 * y;\n");
		check("redundant parens in &&", clean("  if (((bVar1 & 4) == 0) && (x == 1)) {"),
			"  if (!BIT(v1, 2) && (x == 1)) {\n");
		check("ascii tag stays hex", clean("  if (x != 0x4750) {"), "  if (x != 0x4750) {\n");
		check("printable char kept", clean("  if (cVar1 != 'M') {"), "  if (v1 != 'M') {\n");
		check("sub piece", clean("  x = SUB42(y,0);"), "  x = y;\n");
		check("sub piece in expr", clean("  x = SUB42(y,2) + 1;"), "  x = (u16)(y >> 16) + 1;\n");
		check("ge zero", clean("  if (-1 < (int)(x - 2)) {"), "  if (0 <= (" + s32 + ")(x - 2)) {\n");
		check("noise warning dropped",
			clean("/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */",
				"void f(void)", "{", "  _DAT_00000412 = 1;", "}"),
			"void f(void)\n{\n  DAT_00000412 = 1;\n}\n");
		check("comments untouched", clean("  /* 0x15 (char)x '\\x04' */"), "  /* 0x15 (char)x '\\x04' */\n");
		println(fails == 0 ? "ALL PASSED" : fails + " FAILED");
		println("u32=" + u32);
	}
}
