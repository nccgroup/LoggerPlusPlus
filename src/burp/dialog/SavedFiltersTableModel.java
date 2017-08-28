package burp.dialog;

import burp.BurpExtender;
import burp.filter.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

/**
 * Created by corey on 22/08/17.
 */
public class SavedFiltersTableModel extends AbstractTableModel {
    private final ArrayList<SavedFilter> filters;
    private final String[] columnNames = {"Title", "Filter", ""};
    private final JButton applyButton = new JButton("Apply");

    SavedFiltersTableModel(ArrayList<SavedFilter> filters){
        this.filters = filters;
    }

    @Override
    public int getRowCount() {
        return filters.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int i) {
        return columnNames[i];
    }

    @Override
    public Object getValueAt(int row, int col) {
        switch (col) {
            case 0:
                return (filters.get(row).getName() == null ? "" : filters.get(row).getName());
            case 1:
                return (filters.get(row).getFilterString() == null ? "" : filters.get(row).getFilterString());
            case 2:
                return applyButton;
            default:
                return false;
        }
    }

    public void setValueAt(Object value, int row, int col) {
        switch (col) {
            case 0:
                filters.get(row).setName((String) value);
                break;
            case 1: {
                SavedFilter filter = filters.get(row);
                filter.setFilterString((String) value);
                try {
                    filter.setFilter(FilterCompiler.parseString((String) value));
                } catch (Filter.FilterException e) {
                    filter.setFilter(null);
                }
                break;
            }
            default:
                return;
        }
    }



    @Override
    public Class<?> getColumnClass(int columnIndex){
        switch (columnIndex) {
            case 0: return String.class;
            case 1: return String.class;
            case 2: return JButton.class;
            default: return String.class;
        }
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col < 2;
    }

    public void addFilter(SavedFilter filter){
        int i = filters.size();
        filters.add(filter);
        this.fireTableRowsInserted(i, i);
    }

    public void onClick(int row, int column) {
        if(row != -1 && row < filters.size() && column == 2) {
            Filter filter = this.filters.get(row).getFilter();
            BurpExtender.getInstance().setFilter(filter);
        }
    }

    public void removeAll() {
        this.filters.clear();
        this.fireTableDataChanged();
    }

    public void removeAtIndex(int row) {
        if(row < filters.size() || row >= filters.size()) return;
        filters.remove(row);
        this.fireTableRowsDeleted(row, row);
    }

    public boolean validFilterAtRow(int row) {
        return this.filters.get(row).getFilter() != null;
    }
}
