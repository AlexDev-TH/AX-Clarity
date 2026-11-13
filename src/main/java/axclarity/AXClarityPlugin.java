/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity;

import java.io.File;
import java.util.List;

import axclarity.clean.CleanExporter;
import axclarity.clean.CleanOptions;
import axclarity.core.*;
import axclarity.ui.CleanCodeProvider;
import axclarity.ui.PrepDialog;
import docking.action.builder.ActionBuilder;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.MiscellaneousPluginPackage;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = MiscellaneousPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "AX-Clarity: clean ECU decompiler output",
	description = "Makes Ghidra decompiler output of ECU firmware short and readable: " +
		"resolves gp/tp/ep/SB global base registers, maps RAM and I/O, types and names " +
		"globals, and shows a Clean Code view (u8/u16 types, BIT() macros, inline " +
		"calibration values). By AlexDev-TH.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class AXClarityPlugin extends ProgramPlugin {

	public static final String VERSION = "1.0.0";
	public static final String MENU = "AX-Clarity";
	public static final String URL = "https://github.com/AlexDev-TH/AX-Clarity";

	private CleanCodeProvider provider;

	public AXClarityPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		provider = new CleanCodeProvider(this);

		new ActionBuilder("AX-Clarity Prepare", getName())
				.menuPath(MENU, "1. เตรียมโปรแกรม ECU (คลิกเดียว)...")
				.menuGroup("ax", "1")
				.description("ตั้งค่า gp/tp/ep/SB, สร้าง RAM/IO, ใส่ชนิดและชื่อตัวแปร global")
				.enabledWhen(c -> currentProgram != null)
				.onAction(c -> prepare())
				.buildAndInstall(tool);

		new ActionBuilder("AX-Clarity Clean Code", getName())
				.menuPath(MENU, "2. เปิดหน้าต่าง Clean Code")
				.menuGroup("ax", "2")
				.description("แสดงฟังก์ชันปัจจุบันเป็นโค้ด C ที่สั้นและอ่านง่าย")
				.onAction(c -> provider.setVisible(true))
				.buildAndInstall(tool);

		new ActionBuilder("AX-Clarity Export", getName())
				.menuPath(MENU, "3. ส่งออก Clean C ทั้งโปรแกรม...")
				.menuGroup("ax", "3")
				.description("บันทึกทุกฟังก์ชันเป็นไฟล์ .c ไฟล์เดียว ค้นหาและเทียบเวอร์ชันได้")
				.enabledWhen(c -> currentProgram != null)
				.onAction(c -> exportAll())
				.buildAndInstall(tool);

		new ActionBuilder("AX-Clarity About", getName())
				.menuPath(MENU, "เกี่ยวกับ AX-Clarity")
				.menuGroup("axz", "9")
				.onAction(c -> about())
				.buildAndInstall(tool);
	}

	@Override
	protected void programActivated(Program p) {
		provider.setProgram(p);
	}

	@Override
	protected void programDeactivated(Program p) {
		provider.setProgram(null);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		provider.setLocation(loc);
	}

	@Override
	protected void dispose() {
		provider.dispose();
		super.dispose();
	}

	public ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	/** The user's own decompiler settings from the tool, so the clean view matches them. */
	public DecompileOptions toolDecompileOptions(Program p) {
		DecompileOptions o = new DecompileOptions();
		try {
			ToolOptions field = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
			ToolOptions dec = tool.getOptions("Decompiler");
			o.grabFromToolAndProgram(field, dec, p);
		}
		catch (Exception e) {
			o.grabFromProgram(p);
		}
		return o;
	}

	// ===== actions =====

	private void prepare() {
		final Program p = currentProgram;
		if (p == null) {
			return;
		}
		final Arch arch = Arch.detect(p);
		@SuppressWarnings("unchecked")
		final List<BaseRegisterFinder.Result>[] found = new List[1];
		TaskLauncher.launchModal("AX-Clarity: ค้นหา base register", monitor -> {
			try {
				found[0] = BaseRegisterFinder.find(p, arch, monitor);
			}
			catch (CancelledException e) {
				// user cancelled
			}
		});
		if (found[0] == null) {
			return;
		}
		PrepDialog d = new PrepDialog(arch, found[0]);
		tool.showDialog(d);
		if (!d.isAccepted()) {
			return;
		}
		final EcuPrep.Options opt = d.getOptions();
		final EcuPrep.Report[] rep = new EcuPrep.Report[1];
		final Exception[] err = new Exception[1];
		TaskLauncher.launchModal("AX-Clarity: เตรียมโปรแกรม", monitor -> {
			int tx = p.startTransaction("AX-Clarity Prepare");
			boolean ok = false;
			try {
				rep[0] = EcuPrep.run(p, opt, monitor);
				ok = true;
			}
			catch (CancelledException e) {
				// rolled back below
			}
			catch (Exception e) {
				err[0] = e;
			}
			finally {
				p.endTransaction(tx, ok);
			}
		});
		if (err[0] != null) {
			Msg.showError(this, null, "AX-Clarity", "เตรียมโปรแกรมไม่สำเร็จ: " + err[0].getMessage(), err[0]);
			return;
		}
		if (rep[0] != null) {
			Msg.showInfo(this, null, "AX-Clarity", rep[0].toHtml());
			provider.setVisible(true);
			provider.refresh(true);
		}
	}

	private void exportAll() {
		final Program p = currentProgram;
		GhidraFileChooser fc = new GhidraFileChooser(tool.getActiveWindow());
		fc.setTitle("ส่งออก Clean C ทั้งโปรแกรม");
		fc.setSelectedFile(new File(p.getName().replaceAll("[^A-Za-z0-9._-]", "_") + "_clean.c"));
		File f = fc.getSelectedFile();
		fc.dispose();
		if (f == null) {
			return;
		}
		final DecompileOptions base = toolDecompileOptions(p);
		final String[] msg = new String[1];
		TaskLauncher.launchModal("AX-Clarity: ส่งออก Clean C", monitor -> {
			try {
				CleanExporter.Summary s = CleanExporter.export(p, base, new CleanOptions(), f, monitor);
				msg[0] = s.toString();
			}
			catch (CancelledException e) {
				msg[0] = null;
			}
			catch (Exception e) {
				msg[0] = "ผิดพลาด: " + e.getMessage();
			}
		});
		if (msg[0] != null) {
			Msg.showInfo(this, null, "AX-Clarity", "บันทึกแล้ว: " + f + "\n" + msg[0]);
		}
	}

	private void about() {
		Msg.showInfo(this, null, "AX-Clarity " + VERSION,
			"<html><h2>AX-Clarity " + VERSION + "</h2>" +
				"Ghidra extension สำหรับงาน Reverse ECU<br>" +
				"ทำให้โค้ดหลัง decompile สั้น กระชับ อ่านง่าย ใกล้เคียงต้นฉบับ<br><br>" +
				"พัฒนาโดย <b>AlexDev-TH</b><br>" + URL + "</html>");
	}
}
