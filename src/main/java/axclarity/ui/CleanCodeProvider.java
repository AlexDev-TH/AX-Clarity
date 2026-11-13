/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.ui;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;
import javax.swing.text.*;

import axclarity.AXClarityPlugin;
import axclarity.clean.*;
import docking.WindowPosition;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/** Dockable window that shows the current function as clean C. */
public class CleanCodeProvider extends ComponentProviderAdapter implements DomainObjectListener {

	private final AXClarityPlugin plugin;
	private final JPanel root = new JPanel(new BorderLayout());
	private final JTextPane pane = new JTextPane();
	private final JLabel status = new JLabel(" ");
	private final CleanOptions options = new CleanOptions();
	private final Map<String, JCheckBox> toggles = new LinkedHashMap<>();
	private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
		Thread t = new Thread(r, "AX-Clarity decompiler");
		t.setDaemon(true);
		return t;
	});
	private final AtomicInteger generation = new AtomicInteger();
	private final javax.swing.Timer changeTimer;

	private Program program;
	private CleanDecompiler decompiler; // used only on the worker thread
	private Function shownFunction;
	private long shownModNumber = -1;
	private List<CleanPrinter.Line> shownLines = new ArrayList<>();
	private Palette palette;

	public CleanCodeProvider(AXClarityPlugin plugin) {
		super(plugin.getTool(), "AX-Clarity Clean Code", plugin.getName());
		this.plugin = plugin;
		setTitle("AX-Clarity Clean Code");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		setWindowMenuGroup("AX-Clarity");
		loadPrefs();
		buildUi();
		changeTimer = new javax.swing.Timer(700, e -> refresh(true));
		changeTimer.setRepeats(false);
		addToTool();
	}

	// ===== UI =====

	private void buildUi() {
		pane.setEditable(false);
		pane.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
		pane.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					goToClickedLine(e.getPoint());
				}
			}
		});
		JScrollPane scroll = new JScrollPane(pane);

		JPanel bar = new JPanel(new WrapLayout(FlowLayout.LEFT, 6, 2));
		addToggle(bar, "shortTypes", "u8/u16", "ชนิดสั้นแบบ ECU: byte/ushort/undefined2 เป็น u8/u16");
		addToggle(bar, "shortNames", "v1/arg1", "ชื่อตัวแปรสั้น: uVar3 เป็น v3, param_1 เป็น arg1");
		addToggle(bar, "smartCasts", "ตัด cast", "ตัด cast ที่ภาษา C ทำให้อยู่แล้ว (ตอนกำหนดค่า/return/ส่งพารามิเตอร์)");
		addToggle(bar, "bitMacros", "BIT()", "(x & 0x20) != 0 เป็น BIT(x, 5), x |= 0x20 เป็น SETBIT(x, 5)");
		addToggle(bar, "smartNumbers", "เลขฐาน", "เลขคำนวณเป็นฐานสิบ, mask/address/offset เป็นฐานสิบหก");
		addToggle(bar, "calValues", "ค่า cal", "แสดงค่าจริงในรอมของตัวแปร cal_ ต่อท้าย เช่น cal_1a7cf/*=12*/");
		addToggle(bar, "removeNoise", "ตัด noise", "ZEXT/SEXT/SUB, (uint3) ของ M16C, '\\x04' เป็นตัวเลข");
		addToggle(bar, "compact", "กระชับ", "x += 1 เป็น x++, a + -1 เป็น a - 1, ตัด return; ท้ายฟังก์ชัน");
		addToggle(bar, "hideInfoWarnings", "ซ่อน warning", "ซ่อน WARNING ที่ไม่มีผลต่อความหมายของโค้ด");

		JButton copy = new JButton("คัดลอก");
		copy.setToolTipText("คัดลอกโค้ดทั้งหมดในหน้าต่างนี้");
		copy.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard()
				.setContents(new StringSelection(pane.getText()), null));
		JButton save = new JButton("บันทึก .c");
		save.setToolTipText("บันทึกฟังก์ชันนี้เป็นไฟล์ .c");
		save.addActionListener(e -> saveCurrent());
		JButton reload = new JButton("รีเฟรช");
		reload.addActionListener(e -> refresh(true));
		bar.add(copy);
		bar.add(save);
		bar.add(reload);

		status.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
		root.add(bar, BorderLayout.NORTH);
		root.add(scroll, BorderLayout.CENTER);
		root.add(status, BorderLayout.SOUTH);
		applyPaneColors();
	}

	private void addToggle(JPanel bar, String key, String label, String tip) {
		JCheckBox cb = new JCheckBox(label, get(key));
		cb.setToolTipText(tip);
		cb.addActionListener(e -> {
			set(key, cb.isSelected());
			savePrefs();
			refresh(true);
		});
		toggles.put(key, cb);
		bar.add(cb);
	}

	private boolean get(String key) {
		switch (key) {
			case "shortTypes":
				return options.shortTypes;
			case "shortNames":
				return options.shortNames;
			case "smartCasts":
				return options.smartCasts;
			case "bitMacros":
				return options.bitMacros;
			case "smartNumbers":
				return options.smartNumbers;
			case "calValues":
				return options.calValues;
			case "removeNoise":
				return options.removeNoise;
			case "compact":
				return options.compact;
			case "hideInfoWarnings":
				return options.hideInfoWarnings;
			default:
				return false;
		}
	}

	private void set(String key, boolean v) {
		switch (key) {
			case "shortTypes":
				options.shortTypes = v;
				break;
			case "shortNames":
				options.shortNames = v;
				break;
			case "smartCasts":
				options.smartCasts = v;
				break;
			case "bitMacros":
				options.bitMacros = v;
				break;
			case "smartNumbers":
				options.smartNumbers = v;
				break;
			case "calValues":
				options.calValues = v;
				break;
			case "removeNoise":
				options.removeNoise = v;
				break;
			case "compact":
				options.compact = v;
				break;
			case "hideInfoWarnings":
				options.hideInfoWarnings = v;
				break;
			default:
		}
	}

	private static final String[] KEYS = { "shortTypes", "shortNames", "smartCasts", "bitMacros",
		"smartNumbers", "calValues", "removeNoise", "compact", "hideInfoWarnings" };

	private void loadPrefs() {
		for (String k : KEYS) {
			String v = Preferences.getProperty("AXClarity." + k);
			if (v != null) {
				set(k, Boolean.parseBoolean(v));
			}
		}
	}

	private void savePrefs() {
		for (String k : KEYS) {
			Preferences.setProperty("AXClarity." + k, Boolean.toString(get(k)));
		}
		Preferences.store();
	}

	private void applyPaneColors() {
		palette = Palette.forBackground(pane.getBackground());
	}

	@Override
	public JComponent getComponent() {
		return root;
	}

	// ===== program tracking =====

	public void setProgram(Program p) {
		if (program == p) {
			return;
		}
		if (program != null) {
			program.removeListener(this);
		}
		program = p;
		shownFunction = null;
		shownModNumber = -1;
		final CleanDecompiler old = decompiler;
		decompiler = null;
		worker.submit(() -> {
			if (old != null) {
				old.close();
			}
		});
		if (p != null) {
			p.addListener(this);
		}
		else {
			showText(Collections.singletonList(new CleanPrinter.Line("// ยังไม่ได้เปิดโปรแกรม", null)), " ");
		}
	}

	public void setLocation(ProgramLocation loc) {
		if (program == null || loc == null || !isVisible()) {
			return;
		}
		Function f = program.getFunctionManager().getFunctionContaining(loc.getAddress());
		if (f == null) {
			return;
		}
		if (f.equals(shownFunction) && program.getModificationNumber() == shownModNumber) {
			return;
		}
		shownFunction = f;
		refresh(false);
	}

	@Override
	public void componentShown() {
		ProgramLocation loc = plugin.getCurrentLocation();
		if (loc != null) {
			shownFunction = null;
			setLocation(loc);
		}
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (isVisible()) {
			changeTimer.restart();
		}
	}

	public void refresh(boolean force) {
		if (program == null || shownFunction == null || !isVisible()) {
			return;
		}
		final Program p = program;
		final Function f = shownFunction;
		final CleanOptions o = options.copy();
		final int gen = generation.incrementAndGet();
		final DecompileOptions base = plugin.toolDecompileOptions(p);
		status.setText("กำลัง decompile " + f.getName() + " ...");
		worker.submit(() -> {
			if (gen != generation.get()) {
				return;
			}
			try {
				if (decompiler == null || decompiler.getProgram() != p) {
					if (decompiler != null) {
						decompiler.close();
					}
					decompiler = new CleanDecompiler(p, base, true);
				}
				long mod = p.getModificationNumber();
				CleanPrinter.Result r = decompiler.clean(f, o, TaskMonitor.DUMMY);
				CleanPrinter.Result raw = new CleanPrinter(p, CleanOptions.none())
						.clean(decompiler.decompile(f, 60, TaskMonitor.DUMMY));
				String st = String.format(
					"%s   Ghidra %d บรรทัด / %,d ตัวอักษร   AX-Clarity %d บรรทัด / %,d ตัวอักษร   สั้นลง %d%%   แก้ %d จุด",
					f.getName(), raw.origLines, raw.origChars, r.cleanLines, r.cleanChars,
					raw.origChars == 0 ? 0 : Math.round(100.0 * (raw.origChars - r.cleanChars) / raw.origChars),
					r.totalFixes());
				SwingUtilities.invokeLater(() -> {
					if (gen == generation.get()) {
						shownModNumber = mod;
						showText(r.lines, st);
					}
				});
			}
			catch (Throwable t) {
				Msg.error(this, "AX-Clarity decompile failed", t);
				SwingUtilities.invokeLater(() -> status.setText("decompile ไม่สำเร็จ: " + t.getMessage()));
			}
		});
	}

	// ===== rendering =====

	private void showText(List<CleanPrinter.Line> lines, String st) {
		applyPaneColors();
		shownLines = new ArrayList<>(lines);
		StyledDocument doc = new DefaultStyledDocument();
		try {
			for (CleanPrinter.Line l : lines) {
				SyntaxColor.append(doc, l.text, palette);
				doc.insertString(doc.getLength(), "\n", palette.plain);
			}
		}
		catch (BadLocationException e) {
			// not reachable: always appending at the end
		}
		pane.setDocument(doc);
		pane.setCaretPosition(0);
		status.setText(st);
	}

	private void goToClickedLine(Point p) {
		int off = pane.viewToModel2D(p);
		if (off < 0) {
			return;
		}
		Element rootEl = pane.getDocument().getDefaultRootElement();
		int line = rootEl.getElementIndex(off);
		Address a = null;
		for (int i = line; i >= 0 && i < shownLines.size(); i--) {
			a = shownLines.get(i).addr;
			if (a != null) {
				break;
			}
		}
		if (a != null) {
			GoToService gs = tool.getService(GoToService.class);
			if (gs != null) {
				gs.goTo(a);
			}
		}
	}

	private void saveCurrent() {
		if (shownFunction == null) {
			return;
		}
		GhidraFileChooser fc = new GhidraFileChooser(root);
		fc.setTitle("บันทึก Clean C");
		fc.setSelectedFile(new File(shownFunction.getName() + ".c"));
		File f = fc.getSelectedFile();
		fc.dispose();
		if (f == null) {
			return;
		}
		try {
			Files.writeString(f.toPath(), pane.getText(), StandardCharsets.UTF_8);
		}
		catch (Exception e) {
			Msg.showError(this, root, "AX-Clarity", "บันทึกไม่สำเร็จ: " + e.getMessage());
		}
	}

	public void dispose() {
		if (program != null) {
			program.removeListener(this);
		}
		final CleanDecompiler d = decompiler;
		worker.submit(() -> {
			if (d != null) {
				d.close();
			}
		});
		worker.shutdown();
		removeFromTool();
	}
}
