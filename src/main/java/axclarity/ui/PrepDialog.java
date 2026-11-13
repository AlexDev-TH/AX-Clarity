/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.ui;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import axclarity.core.Arch;
import axclarity.core.BaseRegisterFinder;
import axclarity.core.EcuPrep;
import docking.DialogComponentProvider;

/** Confirms base register values and the preparation steps before anything is changed. */
public class PrepDialog extends DialogComponentProvider {

	private final List<BaseRegisterFinder.Result> found;
	private final List<JCheckBox> regUse = new ArrayList<>();
	private final List<JTextField> regValue = new ArrayList<>();
	private final JCheckBox blocks = new JCheckBox("สร้าง memory block RAM / I/O ที่โค้ดใช้แต่ยังไม่มี", true);
	private final JCheckBox refs = new JCheckBox("เพิ่ม xref ทุกจุดที่อ่าน/เขียนตัวแปร (ใช้ Show References ได้)", true);
	private final JCheckBox types = new JCheckBox("ใส่ชนิดตัวแปรจากคำสั่งจริง (ld.h = s16, ld.hu = u16, ...)", true);
	private final JCheckBox names = new JCheckBox("ตั้งชื่อตามหน้าที่ของหน่วยความจำ: ram_ / cal_ / io_", true);
	private boolean accepted;

	public PrepDialog(Arch arch, List<BaseRegisterFinder.Result> found) {
		super("AX-Clarity: เตรียมโปรแกรม ECU", true, true, true, false);
		this.found = found;

		JPanel main = new JPanel();
		main.setLayout(new BoxLayout(main, BoxLayout.Y_AXIS));
		main.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

		JLabel head = new JLabel("<html><b>CPU:</b> " + arch + "<br>" +
			"AX-Clarity จะแก้ที่ต้นเหตุให้ Decompiler ของ Ghidra เอง อ่านง่ายขึ้นทันที<br>" +
			"ทุกอย่างทำใน transaction เดียว กด <b>Undo</b> ครั้งเดียวย้อนได้หมด</html>");
		head.setAlignmentX(Component.LEFT_ALIGNMENT);
		main.add(head);
		main.add(Box.createVerticalStrut(10));

		JPanel regs = new JPanel(new GridBagLayout());
		regs.setAlignmentX(Component.LEFT_ALIGNMENT);
		regs.setBorder(BorderFactory.createTitledBorder("Base register (ตัวชี้ตัวแปร global)"));
		GridBagConstraints g = new GridBagConstraints();
		g.insets = new Insets(2, 4, 2, 4);
		g.anchor = GridBagConstraints.WEST;
		if (found.isEmpty()) {
			g.gridx = 0;
			g.gridy = 0;
			regs.add(new JLabel("CPU นี้ไม่มี base register ที่ต้องตั้ง"), g);
		}
		int row = 0;
		for (BaseRegisterFinder.Result r : found) {
			g.gridy = row++;
			g.gridx = 0;
			Long v = r.existing != null ? r.existing : r.chosen;
			boolean use = r.existing == null && r.chosen != null && r.confident;
			JCheckBox cb = new JCheckBox(r.reg.getName(), use);
			regs.add(cb, g);
			g.gridx = 1;
			JTextField tf = new JTextField(v == null ? "" : "0x" + Long.toHexString(v), 12);
			regs.add(tf, g);
			g.gridx = 2;
			String note = r.existing != null ? "ตั้งไว้แล้ว (ไม่แก้)" :
				r.chosen == null ? "ไม่พบค่าคงที่" :
				r.confident ? "พบ " + r.siteCount(r.chosen) + " จุด ค่าเดียวกัน" :
				"พบหลายค่า (" + r.values.size() + ") ตรวจก่อนใช้";
			regs.add(new JLabel(note), g);
			regUse.add(cb);
			regValue.add(tf);
		}
		main.add(regs);
		main.add(Box.createVerticalStrut(8));

		JPanel steps = new JPanel();
		steps.setLayout(new BoxLayout(steps, BoxLayout.Y_AXIS));
		steps.setAlignmentX(Component.LEFT_ALIGNMENT);
		steps.setBorder(BorderFactory.createTitledBorder("ขั้นตอน"));
		for (JCheckBox c : new JCheckBox[] { blocks, refs, types, names }) {
			c.setAlignmentX(Component.LEFT_ALIGNMENT);
			steps.add(c);
		}
		main.add(steps);

		addWorkPanel(main);
		addOKButton();
		setOkButtonText("เริ่ม");
		addCancelButton();
		setCancelButtonText("ยกเลิก");
		setRememberSize(false);
	}

	@Override
	protected void okCallback() {
		for (int i = 0; i < regUse.size(); i++) {
			if (regUse.get(i).isSelected() && parse(regValue.get(i).getText()) == null) {
				setStatusText("ค่า " + found.get(i).reg.getName() + " ไม่ถูกต้อง (ใส่เป็นเลขฐานสิบหก เช่น 0xFEBF0000)");
				return;
			}
		}
		accepted = true;
		close();
	}

	public boolean isAccepted() {
		return accepted;
	}

	public EcuPrep.Options getOptions() {
		EcuPrep.Options o = new EcuPrep.Options();
		for (int i = 0; i < regUse.size(); i++) {
			if (regUse.get(i).isSelected()) {
				o.baseValues.put(found.get(i).reg, parse(regValue.get(i).getText()));
			}
		}
		o.createBlocks = blocks.isSelected();
		o.createReferences = refs.isSelected();
		o.typeGlobals = types.isSelected();
		o.nameGlobals = names.isSelected();
		return o;
	}

	static Long parse(String s) {
		String t = s.trim().toLowerCase();
		try {
			if (t.startsWith("0x")) {
				return Long.parseUnsignedLong(t.substring(2), 16);
			}
			if (t.endsWith("h")) {
				return Long.parseUnsignedLong(t.substring(0, t.length() - 1), 16);
			}
			return t.isEmpty() ? null : Long.parseUnsignedLong(t, 16);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}
}
