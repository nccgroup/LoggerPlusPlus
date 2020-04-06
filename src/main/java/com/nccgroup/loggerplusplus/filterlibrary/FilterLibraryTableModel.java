package com.nccgroup.loggerplusplus.filterlibrary;

import burp.BurpExtender;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.ColorFilterDialog;
import com.nccgroup.loggerplusplus.util.MoreHelp;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

public class FilterLibraryTableModel extends AbstractTableModel implements FilterLibraryListener {

    private final FilterLibraryController controller;
    JButton btnApplyFilter;
    JButton btnSetColorFilter;
    private final String[] columnNames = {"Alias", "Snippet", "", ""};

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
                JOptionPane.showMessageDialog(LoggerPlusPlus.instance.getMainViewController().getUiComponent(), "Alias names may only contain alphanumeric characters and the symbols period (.) and underscore (_)\n" +
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
                MoreHelp.showLargeOutputDialog("Filter Exception", "<html>" + e.getMessage().replaceAll("\n", "<br>") + "</html>");
//                JOptionPane.showMessageDialog(LoggerPlusPlus.instance.getMainViewController().getUiComponent(), "<html><body style=\"max-height: 400px; max-width: 400px;\">" + e.getMessage().replaceAll("\n", "<br>") + "</html>", "Filter Exception", JOptionPane.ERROR_MESSAGE);
            }
        }
        controller.saveFilters();
    }

    public void onClick(int row, int col) {
        if(row < 0 || row >= controller.getSavedFilters().size()) return;
        SavedFilter savedFilter = controller.getSavedFilters().get(row);
        if(col == 2){
            controller.getLoggerPlusPlus().getLogViewController().getLogFilterController().setFilter(savedFilter.getFilterString());
            controller.getLoggerPlusPlus().getMainViewController().getTabbedPanel().setSelectedIndex(0);
            return;
        }
        if(col == 3){
            controller.addColorFilter(savedFilter.getName(), savedFilter.getFilter());
            ColorFilterDialog dialog = new ColorFilterDialog(LoggerPlusPlus.instance.getLibraryController());
            dialog.setVisible(true);
        }
    }

    @Override
    public void onFilterAdded(SavedFilter savedFilter, int index) {
        int rows = getRowCount();
        SwingUtilities.invokeLater(() -> {
            this.fireTableRowsInserted(index, index);
        });
    }

    @Override
    public void onFilterModified(SavedFilter savedFilter, int index) {
        SwingUtilities.invokeLater(() -> {
            this.fireTableRowsUpdated(index, index);
        });
    }

    @Override
    public void onFilterRemoved(SavedFilter savedFilter, int index) {
        SwingUtilities.invokeLater(() -> {
            this.fireTableRowsDeleted(index, index);
        });
    }
}
