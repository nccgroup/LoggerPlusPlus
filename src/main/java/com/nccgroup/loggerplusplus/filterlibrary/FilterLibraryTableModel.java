package com.nccgroup.loggerplusplus.filterlibrary;

import burp.BurpExtender;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.userinterface.dialog.ColorFilterDialog;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

public class FilterLibraryTableModel extends AbstractTableModel implements FilterLibraryListener {

    private final FilterLibraryController controller;
    JButton btnApplyFilter;
    JButton btnSetColorFilter;
    private final String[] columnNames = {"Alias", "LogFilter", "", ""};

    public FilterLibraryTableModel(FilterLibraryController controller){
        this.controller = controller;
        this.controller.addFilterListener(this);
        btnApplyFilter = new JButton("Set as LogFilter");
        btnSetColorFilter = new JButton("Use as Color LogFilter");
    }

    @Override
    public int getRowCount() {
        return controller.getSavedFilters().size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public Object getValueAt(int row, int column) {
        if(row >= controller.getSavedFilters().size()) return null;
        SavedFilter savedFilter = controller.getSavedFilters().get(row);
        switch (column){
            case 0: return savedFilter.getName();
            case 1: {
                if(savedFilter.getFilter() == null) return savedFilter.getFilterString();
                else return savedFilter.getFilter();
            }
            case 2: return btnApplyFilter;
            case 3: return btnSetColorFilter;
        }
        return null;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0 || columnIndex == 1;
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        SavedFilter savedFilter = controller.getSavedFilters().get(row);
        if(savedFilter == null) return;
        if(column == 0) {
            savedFilter.setName((String) value);
            if(!((String) value).equalsIgnoreCase(savedFilter.getName())){
                JOptionPane.showMessageDialog(BurpExtender.instance.getUiComponent(), "Alias names may only contain alphanumeric characters and the symbols period (.) and underscore (_)\n" +
                        "Invalid characters have been replaced with an underscore.", "Alias Error", JOptionPane.WARNING_MESSAGE);
            }
        }
        if(column == 1){
            try{
                savedFilter.setFilter(new LogFilter(LoggerPlusPlus.instance.getLibraryController(), (String) value));
            }catch (ParseException e){
                //Not a valid filter...
                savedFilter.setFilterString((String) value);
                savedFilter.setFilter(null);
                JOptionPane.showMessageDialog(BurpExtender.instance.getUiComponent(), e.getMessage(), "Filter Exception", JOptionPane.ERROR_MESSAGE);
            }
        }
        controller.saveFilters();
    }

    public void onClick(int row, int col) {
        if(row < 0 || row >= controller.getSavedFilters().size()) return;
        SavedFilter savedFilter = controller.getSavedFilters().get(row);
        if(col == 2){
            LoggerPlusPlus.instance.getLogFilterController().setFilter(savedFilter.getFilterString());
            LoggerPlusPlus.instance.getTabbedPane().setSelectedIndex(0);
            return;
        }
        if(col == 3){
            LoggerPlusPlus.instance.getLibraryController().addColorFilter(savedFilter.getName(), savedFilter.getFilter());
            ColorFilterDialog dialog = new ColorFilterDialog(LoggerPlusPlus.instance.getLibraryController());
            dialog.setVisible(true);
        }
    }

    @Override
    public void onFilterAdded(SavedFilter savedFilter) {
        int rows = getRowCount();
        SwingUtilities.invokeLater(() -> {
            this.fireTableRowsInserted(rows-1, rows-1);
        });
    }

    @Override
    public void onFilterModified(SavedFilter savedFilter) {
        SwingUtilities.invokeLater(() -> {
            int index = controller.getSavedFilters().indexOf(savedFilter);
            if (index > 0) this.fireTableRowsUpdated(index, index);
        });
    }

    @Override
    public void onFilterRemoved(SavedFilter savedFilter) {
        SwingUtilities.invokeLater(() -> {
            int index = controller.getSavedFilters().indexOf(savedFilter);
            if (index > 0) this.fireTableRowsDeleted(index, index);
        });
    }
}
