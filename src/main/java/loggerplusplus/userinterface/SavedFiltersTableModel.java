package loggerplusplus.userinterface;

import loggerplusplus.Globals;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.MoreHelp;
import loggerplusplus.filter.LogFilter;
import loggerplusplus.filter.SavedFilter;
import loggerplusplus.filter.parser.ParseException;
import loggerplusplus.userinterface.dialog.ColorFilterDialog;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class SavedFiltersTableModel extends AbstractTableModel {

    JButton btnApplyFilter;
    JButton btnSetColorFilter;
    ArrayList<SavedFilter> savedFilters;
    private final String[] columnNames = {"Title", "LogFilter", "", ""};

    public SavedFiltersTableModel(ArrayList<SavedFilter> savedFilters){
        this.savedFilters = savedFilters;
        btnApplyFilter = new JButton("Set as LogFilter");
        btnSetColorFilter = new JButton("Use as Color LogFilter");
    }

    @Override
    public int getRowCount() {
        return savedFilters == null ? 0 : savedFilters.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public Object getValueAt(int row, int column) {
        if(savedFilters == null || row >= savedFilters.size()) return null;
        switch (column){
            case 0: return savedFilters.get(row).getName();
            case 1: {
                SavedFilter savedFilter = savedFilters.get(row);
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
        SavedFilter savedFilter = this.savedFilters.get(row);
        if(savedFilter == null) return;
        if(column == 0) savedFilter.setName((String) value);
        if(column == 1){
            try{
                savedFilter.setFilter(new LogFilter((String) value));
            }catch (ParseException e){
                //Not a valid filter...
                savedFilter.setFilterString((String) value);
                savedFilter.setFilter(null);
            }
        }
        saveFilters();
    }

    public void onClick(int row, int col) {
        if(savedFilters == null || row < 0 || row >= savedFilters.size() || savedFilters.get(row) == null) return;
        if(col == 2){
            LoggerPlusPlus.instance.getFilterController().setFilter(savedFilters.get(row).getFilterString());
            LoggerPlusPlus.instance.getTabbedPane().setSelectedIndex(0);
            return;
        }
        if(col == 3){
            ColorFilterDialog dialog = new ColorFilterDialog(LoggerPlusPlus.instance.getColorFilterListeners());
            SavedFilter savedFilter = savedFilters.get(row);
            try {
                dialog.addColorFilter(savedFilter.getName(), savedFilter.getFilter());
                dialog.setVisible(true);
            } catch (ParseException e) {
                MoreHelp.showMessage("Could not apply Color LogFilter.");
            }
        }
    }

    public void addRow() throws ParseException {
        this.savedFilters.add(new SavedFilter("Example Filter", "Request.Body CONTAINS \"Example\""));
        this.fireTableRowsInserted(this.savedFilters.size()-1, this.savedFilters.size()-1);
        saveFilters();
    }

    public void removeRowAtIndex(int index){
        this.savedFilters.remove(index);
        this.fireTableRowsDeleted(index, index);
        saveFilters();
    }

    private void saveFilters(){
        LoggerPlusPlus.preferences.setSetting(Globals.PREF_SAVED_FILTERS, this.savedFilters);
    }
}
