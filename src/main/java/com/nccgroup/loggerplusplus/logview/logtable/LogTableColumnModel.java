//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Developed by Soroush Dalili (@irsdl)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package com.nccgroup.loggerplusplus.logview.logtable;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.TagRenderer;

import javax.swing.event.TableColumnModelEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.TableColumn;
import java.util.*;

//The visible columns are stored in the underlying class.

public class LogTableColumnModel extends DefaultTableColumnModel {

    private final LogTableController controller;
    private final Preferences preferences;
    private final ArrayList<LogTableColumn> allColumns;

    public LogTableColumnModel(LogTableController controller) {
        super();
        this.controller = controller;
        this.preferences = controller.getPreferences();

        ArrayList<LogTableColumn> columnList = preferences.getSetting(Globals.PREF_LOG_TABLE_SETTINGS);
        // Sorting based on order number
        Collections.sort(columnList);
        this.allColumns = columnList;

        for (int i = 0; i < allColumns.size(); i++) {
            LogTableColumn column = allColumns.get(i);

            if (column.isVisible()) {
                addColumn(column);
            }
        }

        Optional<LogTableColumn> tagColumn = this.allColumns.stream().filter(logTableColumn -> logTableColumn.getName().equals("Tags")).findFirst();
        if((boolean) preferences.getSetting(Globals.PREF_TABLE_PILL_STYLE) && tagColumn.isPresent()){
            tagColumn.get().setCellRenderer(new TagRenderer());
        }

        initialize();
    }

    private void initialize(){

    }

    @Override
    public int getColumnCount() {
        return tableColumns.size();
    }

    @Override
    public void addColumn(TableColumn column) {
        //We should add the column at the correct position based on its order value.
        if (column == null) {
            throw new IllegalArgumentException("Object is null");
        } else {
            //Find the first element with a greater order than the one to be added and add it before it.
            int newPosition = -1;
            for (int i = 0; i < this.tableColumns.size(); i++) {
                int currentOrderAtIndex = ((LogTableColumn) this.tableColumns.get(i)).getOrder();
                if (currentOrderAtIndex > ((LogTableColumn) column).getOrder()){
                    newPosition = i;
                    break;
                }
            }
            if(newPosition == -1){ //No elements with a greater order value. Add it to the end.
                newPosition = this.tableColumns.size();
            }

            this.tableColumns.add(newPosition, column);
            //Adjust model index for new and subsequent columns
            for (int i = newPosition; i < tableColumns.size(); i++) {
                tableColumns.get(i).setModelIndex(i);
            }

            column.addPropertyChangeListener(this);
            this.fireColumnAdded(new TableColumnModelEvent(this, 0, this.getColumnCount() - 1));
        }
    }

    public int getViewIndex(int modelIndex){
        return this.tableColumns.indexOf(this.allColumns.get(modelIndex));
    }

    public void saveLayout() {
        preferences.setSetting(Globals.PREF_LOG_TABLE_SETTINGS, this.allColumns);
    }

    @Override
    public void moveColumn(int viewFrom, int viewTo) {
//		viewToModelMap
        super.moveColumn(viewFrom, viewTo);
        if(viewFrom == viewTo) return;

        int leftIndex = Math.min(viewFrom, viewTo);
        int rightIndex = Math.max(viewFrom, viewTo);

        for (int index = leftIndex; index <= rightIndex; index++) {
            LogTableColumn col = (LogTableColumn) getColumn(index);
            col.setOrder(index);
            col.setModelIndex(index);
        }

        saveLayout();
        this.fireColumnMoved(new TableColumnModelEvent(this, viewFrom, viewTo));
    }

    @Override
    public void removeColumn(TableColumn column) {
        int columnIndex = tableColumns.indexOf(column);

        if (columnIndex != -1) {
            // Adjust for the selection
            if (selectionModel != null) {
                selectionModel.removeIndexInterval(columnIndex,columnIndex);
            }

            column.removePropertyChangeListener(this);
            tableColumns.removeElementAt(columnIndex);

            //Update model index for subsequent columns
            for (int index = columnIndex; index < tableColumns.size(); index++) {
                tableColumns.get(index).setModelIndex(index);
            }

            // Post columnAdded event notification.  (JTable and JTableHeader
            // listens so they can adjust size and redraw)
            fireColumnRemoved(new TableColumnModelEvent(this,
                    columnIndex, 0));
        }
    }

    public void toggleHidden(LogTableColumn logTableColumn) {
        logTableColumn.setVisible(!logTableColumn.isVisible());
        if(logTableColumn.isVisible()){ //&& logTableColumn.isEnabled()){
            //Add the column to the view
            addColumn(logTableColumn);
        }else{
            //Remove the column from the view and adjust others to fit.
            removeColumn(logTableColumn);
        }
        saveLayout();
    }

    public void showColumn(LogTableColumn column){
        if(!column.isVisible()){
            column.setVisible(true);
            addColumn(column);
        }
    }

    public void hideColumn(LogTableColumn column){
        if(column.isVisible()){
            column.setVisible(false);
            removeColumn(column);
        }
    }

    public List<LogTableColumn> getAllColumns() {
        return this.allColumns;
    }
}
