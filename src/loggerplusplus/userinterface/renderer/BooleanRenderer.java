package loggerplusplus.userinterface.renderer;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.UIResource;
import javax.swing.table.TableCellRenderer;
import java.awt.*;

/**
 * Created by corey on 07/09/17.
 */
public class BooleanRenderer extends JCheckBox implements TableCellRenderer, UIResource {
    private static final Border noFocusBorder = new EmptyBorder(1, 1, 1, 1);

    public BooleanRenderer() {
        this.setHorizontalAlignment(0);
        this.setBorderPainted(true);
        this.setOpaque(true);
    }

    public Component getTableCellRendererComponent(JTable var1, Object var2, boolean var3, boolean var4, int var5, int var6) {
        if(var3) {
            this.setForeground(var1.getSelectionForeground());
            super.setBackground(var1.getSelectionBackground());
        } else {
            this.setForeground(var1.getForeground());
            this.setBackground(var1.getBackground());
        }

        this.setSelected(var2 != null && ((Boolean)var2).booleanValue());
        if(var4) {
            this.setBorder(UIManager.getBorder("LogTable.focusCellHighlightBorder"));
        } else {
            this.setBorder(noFocusBorder);
        }

        return this;
    }

}
