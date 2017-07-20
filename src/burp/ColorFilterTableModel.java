package burp;

import burp.filter.ColorFilter;
import burp.filter.Filter;
import burp.filter.FilterCompiler;
import burp.filter.FilterListener;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;

/**
 * Created by corey on 19/07/17.
 */
public class ColorFilterTableModel extends AbstractTableModel{

    private Map<Integer, UUID> rowUUIDs = new HashMap<Integer, UUID>();
    private Map<UUID, ColorFilter> filters;
    private ArrayList<FilterListener> filterListeners;
    private String[] columnNames = {"Title", "Filter", "Foreground Color", "Background Color", "Enabled", ""};
    private JButton removeButton = new JButton("Remove");

    ColorFilterTableModel(Map<UUID, ColorFilter> filters, ArrayList<FilterListener> filterListeners){
        this.filters = filters;
        this.filterListeners = filterListeners;
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
                return (filters.get(rowUUIDs.get(row)).getName() == null ? "" : filters.get(rowUUIDs.get(row)).getName());
            case 1:
                return (filters.get(rowUUIDs.get(row)).getFilterString() == null ? "" : filters.get(rowUUIDs.get(row)).getFilterString());
            case 2:
                return (filters.get(rowUUIDs.get(row)).getForegroundColor() == null ? Color.BLACK : filters.get(rowUUIDs.get(row)).getForegroundColor());
            case 3:
                return (filters.get(rowUUIDs.get(row)).getBackgroundColor() == null ? Color.WHITE : filters.get(rowUUIDs.get(row)).getBackgroundColor());
            case 4:
                return filters.get(rowUUIDs.get(row)).isEnabled();
            case 5:
                return removeButton;
            default:
                return false;
        }
    }

    public Filter getFilterAtRow(int row){
        return filters.get(rowUUIDs.get(row)).getFilter();
    }

    public void setValueAt(Object value, int row, int col) {
        switch (col) {
            case 0:
                filters.get(rowUUIDs.get(row)).setName((String) value);
                break;
            case 1: {
                ColorFilter filter = filters.get(rowUUIDs.get(row));
                filter.setFilterString((String) value);
                try {
                    filter.setFilter(FilterCompiler.parseString((String) value));
                } catch (Filter.FilterException e) {
                    filter.setFilter(null);
                }
                break;
            }
            case 2:
                filters.get(rowUUIDs.get(row)).setForegroundColor((Color) value);
                break;
            case 3:
                filters.get(rowUUIDs.get(row)).setBackgroundColor((Color) value);
                break;
            case 4:
                filters.get(rowUUIDs.get(row)).setEnabled((Boolean) value);
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
        int i = filters.size();
        rowUUIDs.put(i, filter.getUid());
        filters.put(filter.getUid(), filter);
        this.fireTableRowsInserted(i, i);
    }

    public void onClick(int row, int column) {
        if(row != -1 && row < filters.size() && column == 5) {
            synchronized (rowUUIDs) {
                this.filters.remove(rowUUIDs.get(row));
                this.fireTableRowsDeleted(row, row);
                rowUUIDs.remove(row);
                for (int i = row + 1; i <= rowUUIDs.size(); i++) {
                    rowUUIDs.put(i - 1, rowUUIDs.get(i));
                    rowUUIDs.remove(i);
                }
            }
        }
    }

    public void removeAll() {
        this.filters.clear();
        for(FilterListener listener : filterListeners){
            listener.onRemoveAll();
        }
        this.fireTableDataChanged();
    }

    
}
