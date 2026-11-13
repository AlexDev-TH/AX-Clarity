/* AX-Clarity by AlexDev-TH. MIT License. */
package axclarity.ui;

import java.awt.*;

import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

/** FlowLayout that wraps its rows when the window is narrow. */
final class WrapLayout extends FlowLayout {

	WrapLayout(int align, int hgap, int vgap) {
		super(align, hgap, vgap);
	}

	@Override
	public Dimension preferredLayoutSize(Container target) {
		return layoutSize(target, true);
	}

	@Override
	public Dimension minimumLayoutSize(Container target) {
		Dimension d = layoutSize(target, false);
		d.width -= (getHgap() + 1);
		return d;
	}

	private Dimension layoutSize(Container target, boolean preferred) {
		synchronized (target.getTreeLock()) {
			int targetWidth = target.getSize().width;
			Container container = target;
			while (container.getSize().width == 0 && container.getParent() != null) {
				container = container.getParent();
			}
			targetWidth = container.getSize().width;
			if (targetWidth == 0) {
				targetWidth = Integer.MAX_VALUE;
			}
			int hgap = getHgap(), vgap = getVgap();
			Insets insets = target.getInsets();
			int maxWidth = targetWidth - (insets.left + insets.right + hgap * 2);
			Dimension dim = new Dimension(0, 0);
			int rowWidth = 0, rowHeight = 0;
			for (int i = 0; i < target.getComponentCount(); i++) {
				Component m = target.getComponent(i);
				if (!m.isVisible()) {
					continue;
				}
				Dimension d = preferred ? m.getPreferredSize() : m.getMinimumSize();
				if (rowWidth + d.width > maxWidth) {
					dim.width = Math.max(dim.width, rowWidth);
					dim.height += rowHeight + vgap;
					rowWidth = 0;
					rowHeight = 0;
				}
				if (rowWidth != 0) {
					rowWidth += hgap;
				}
				rowWidth += d.width;
				rowHeight = Math.max(rowHeight, d.height);
			}
			dim.width = Math.max(dim.width, rowWidth);
			dim.height += rowHeight;
			dim.width += insets.left + insets.right + hgap * 2;
			dim.height += insets.top + insets.bottom + vgap * 2;
			Container scrollPane = SwingUtilities.getAncestorOfClass(JScrollPane.class, target);
			if (scrollPane != null && target.isValid()) {
				dim.width -= (hgap + 1);
			}
			return dim;
		}
	}
}
