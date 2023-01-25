package com.nccgroup.loggerplusplus.util.userinterface.renderer;

import com.nccgroup.loggerplusplus.filter.tag.Tag;
import org.jdesktop.swingx.HorizontalLayout;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Created by corey on 22/08/17.
 */
public class TagRenderer implements TableCellRenderer {
    @Override public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        JPanel tagWrapper = new JPanel();
        tagWrapper.setLayout(new HorizontalLayout(2));
        tagWrapper.setBorder(BorderFactory.createEmptyBorder(2,2,2,2));

        if(value instanceof Collection){
            for (Object o : ((Collection<Tag>) value).toArray()) {
                JButton c = new JButton(((Tag) o).getName());
                c.putClientProperty("JButton.buttonType", "roundRect");
                c.setMargin(new Insets(7,4,7,4));
                c.setBackground(((Tag) o).getBackgroundColor());
                c.setForeground(((Tag) o).getForegroundColor());
                tagWrapper.add(c);
            }
        }

        return tagWrapper;
    }
}
