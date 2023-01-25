package com.nccgroup.loggerplusplus.util.userinterface.renderer;

import com.nccgroup.loggerplusplus.filter.FilterExpression;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.ColorFilterTable;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.ColorFilterTableModel;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.TagTable;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.TagTableModel;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Created by corey on 22/08/17.
 */
public class FilterRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        boolean validFilter;
        if (table instanceof ColorFilterTable) {
            validFilter = ((ColorFilterTableModel) table.getModel()).validFilterAtRow(row);
        } else if (table instanceof TagTable) {
            validFilter = ((TagTableModel) table.getModel()).validFilterAtRow(row);
        } else {
            validFilter = (value instanceof FilterExpression);
        }

        if(validFilter){
            c.setBackground(new Color(76,255, 155));
            c.setForeground(Color.BLACK);
        }else{
            c.setBackground(new Color(221, 70, 57));
            c.setForeground(Color.WHITE);
        }

        return c;
    }
}
