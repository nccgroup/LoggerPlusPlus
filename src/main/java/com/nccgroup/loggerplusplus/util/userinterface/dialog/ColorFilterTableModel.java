package com.nccgroup.loggerplusplus.util.userinterface.dialog;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.List;
import java.util.*;

/**
 * Created by corey on 19/07/17.
 */
public class ColorFilterTableModel extends AbstractTableModel {

    private final Map<Short, UUID> rowUUIDs = new HashMap<Short, UUID>();
    private final Map<UUID, TableColorRule> filters;
    private final String[] columnNames = {"Title", "LogFilter", "Foreground Color", "Background Color", "Enabled", ""};
    private final JButton removeButton = new JButton("Remove");
    private final FilterLibraryController filterLibraryController;

    ColorFilterTableModel(FilterLibraryController filterLibraryController){
        this.filterLibraryController = filterLibraryController;
        //Sort existing filters by their priority before adding to table.
        filters = filterLibraryController.getColorFilters();
        List<TableColorRule> sorted = new ArrayList<TableColorRule>(filters.values());
        Collections.sort(sorted);
        for (TableColorRule filter : sorted) {
            rowUUIDs.put((short) rowUUIDs.size(), filter.getUuid());
        }
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
        UUID rowUid = rowUUIDs.get((short) row);
        switch (col) {
            case 0:
                return (filters.get(rowUid).getName() == null ? "" : filters.get(rowUid).getName());
            case 1:
                return (filters.get(rowUid).getFilterString() == null ? "" : filters.get(rowUid).getFilterString());
            case 2:
                return (filters.get(rowUid).getForegroundColor() == null ? Color.BLACK : filters.get(rowUid).getForegroundColor());
            case 3:
                return (filters.get(rowUid).getBackgroundColor() == null ? Color.WHITE : filters.get(rowUid).getBackgroundColor());
            case 4:
                return filters.get(rowUid).isEnabled();
            case 5:
                return removeButton;
            default:
                return false;
        }
    }

    public boolean validFilterAtRow(int row) {
        return getFilterAtRow(row).getFilterExpression() != null;
    }

//    public LogFilter getFilterAtRow(int row){
//        return filters.get(rowUUIDs.get((short) row)).getFilter();
//    }

    public TableColorRule getFilterAtRow(int row){
        return filters.get(rowUUIDs.get((short) row));
    }

    public void setValueAt(Object value, int row, int col) {
        UUID rowUid = rowUUIDs.get((short) row);
        TableColorRule filter = filters.get(rowUid);
        switch (col) {
            case 0:
                filter.setName((String) value);
                break;
            case 1: {
                filter.trySetFilter((String) value);
                break;
            }
            case 2:
                filter.setForegroundColor((Color) value);
                break;
            case 3:
                filter.setBackgroundColor((Color) value);
                break;
            case 4:
                filter.setEnabled((Boolean) value);
                break;
            default:
                return;
        }

        this.filterLibraryController.updateColorFilter(filter);
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

    public void addFilter(TableColorRule filter){
        int i = filters.size();
        filterLibraryController.addColorFilter(filter);
        rowUUIDs.put((short) i, filter.getUuid());
        filter.setPriority((short) i);
        this.fireTableRowsInserted(i, i);
    }

    public void onClick(int row, int column) {
        if(row != -1 && row < filters.size() && column == 5) {
            synchronized (rowUUIDs) {
                TableColorRule removedFilter = filters.get(rowUUIDs.get((short) row));
                filterLibraryController.removeColorFilter(removedFilter);
                this.fireTableRowsDeleted(row, row);
                rowUUIDs.remove((short) row);

                for (int i = row + 1; i <= rowUUIDs.size(); i++) {
                    rowUUIDs.put((short) (i - 1), rowUUIDs.get((short) i));
                    filters.get(rowUUIDs.get((short) i)).setPriority((short) (i-1));
                    rowUUIDs.remove((short) i);
                }
            }
        }
    }

    public void switchRows(int from, int to) {
        UUID toUid = this.rowUUIDs.get((short) to);
        rowUUIDs.put((short) to, rowUUIDs.get((short) from));
        rowUUIDs.put((short) from, toUid);
        TableColorRule toFilter = filters.get(rowUUIDs.get((short) to));
        toFilter.setPriority((short) to);
        TableColorRule fromFilter = filters.get(rowUUIDs.get((short) from));
        fromFilter.setPriority((short) from);
        filterLibraryController.updateColorFilter(toFilter);
        filterLibraryController.updateColorFilter(fromFilter);
        this.fireTableRowsUpdated(from, from);
        this.fireTableRowsUpdated(to, to);
    }

    public void removeAll() {
        for (TableColorRule filter : new ArrayList<>(filterLibraryController.getColorFilters().values())) {
            filterLibraryController.removeColorFilter(filter);
        }

        this.rowUUIDs.clear();
        this.fireTableDataChanged();
    }
}
