package burp;

import burp.filter.ColorFilter;
import burp.filter.Filter;
import burp.filter.FilterCompiler;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;

/**
 * Created by corey on 19/07/17.
 */
public class ColorFilterTableModel extends AbstractTableModel{

    private ArrayList<ColorFilter> filters;
    private String[] columnNames = {"Title", "Filter", "Foreground Color", "Background Color", "Enabled", ""};
    private JButton removeButton = new JButton("Remove");

    ColorFilterTableModel(ArrayList<ColorFilter> filters){
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
                return (filters.get(row).getForegroundColor() == null ? Color.BLACK : filters.get(row).getForegroundColor());
            case 3:
                return (filters.get(row).getBackgroundColor() == null ? Color.WHITE : filters.get(row).getBackgroundColor());
            case 4:
                return filters.get(row).isEnabled();
            case 5:
                return removeButton;
            default:
                return false;
        }
    }

    public Filter getFilterAtRow(int row){
        return filters.get(row).getFilter();
    }

    public void setValueAt(Object value, int row, int col) {
        switch (col) {
            case 0:
                filters.get(row).setName((String) value);
                break;
            case 1: {
                ColorFilter filter = filters.get(row);
                filter.setFilterString((String) value);
                try {
                    filter.setFilter(FilterCompiler.parseString((String) value));
                } catch (Filter.FilterException e) {
                    filter.setFilter(null);
                }
                break;
            }
            case 2:
                filters.get(row).setForegroundColor((Color) value);
                break;
            case 3:
                filters.get(row).setBackgroundColor((Color) value);
                break;
            case 4:
                filters.get(row).setEnabled((Boolean) value);
                break;
            default:
                return;
        }
    }



    @Override
    public Class<?> getColumnClass(int columnIndex){
        switch (columnIndex) {
            case 0: return String.class;
            case 1: return String.class;
            case 2: return Color.class;
            case 3: return Color.class;
            case 4: return Boolean.class;
            case 5: return JButton.class;
            default: return String.class;
        }
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return col != 5;
    }

    public void addFilter(ColorFilter filter){
        filters.add(filter);
        this.fireTableDataChanged();
    }

    public void onClick(int row, int column) {
        if(row < filters.size() && column == 5) {
            this.filters.remove(row);
            this.fireTableDataChanged();
        }
    }

    public void removeAll() {
        this.filters.clear();
        this.fireTableDataChanged();
    }
}
