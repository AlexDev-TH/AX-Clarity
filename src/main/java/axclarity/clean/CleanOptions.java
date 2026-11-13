/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.clean;

/** Switches for each rewrite of the Clean Code view. All are display only. */
public final class CleanOptions {
	/** byte/ushort/uint/undefined2 to u8/u16/u32 (sizes from the program's data organization) */
	public boolean shortTypes = true;
	/** uVar3/iVar7 to v3/v7 and param_1 to arg1 */
	public boolean shortNames = true;
	/** drop casts that C applies anyway (assignment, return, call argument) */
	public boolean smartCasts = true;
	/** (x &amp; 0x20) != 0 to BIT(x, 5); x |= 0x20 to SETBIT(x, 5) */
	public boolean bitMacros = true;
	/** decimal for arithmetic, hex for masks, addresses and struct offsets */
	public boolean smartNumbers = true;
	/** show the ROM value of calibration scalars inline: cal_1a7cf/*=12*&#47; */
	public boolean calValues = true;
	/** ZEXT/SEXT/SUB, M16C (uint3) pointer noise, '\x04' char literals */
	public boolean removeNoise = true;
	/** x += 1 to x++, a + -1 to a - 1, trailing return; */
	public boolean compact = true;
	/** drop informational decompiler warnings that do not affect meaning */
	public boolean hideInfoWarnings = true;

	public CleanOptions copy() {
		CleanOptions o = new CleanOptions();
		o.shortTypes = shortTypes;
		o.shortNames = shortNames;
		o.smartCasts = smartCasts;
		o.bitMacros = bitMacros;
		o.smartNumbers = smartNumbers;
		o.calValues = calValues;
		o.removeNoise = removeNoise;
		o.compact = compact;
		o.hideInfoWarnings = hideInfoWarnings;
		return o;
	}

	public static CleanOptions none() {
		CleanOptions o = new CleanOptions();
		o.shortTypes = o.shortNames = o.smartCasts = o.bitMacros = o.smartNumbers = o.calValues =
			o.removeNoise = o.compact = o.hideInfoWarnings = false;
		return o;
	}
}
