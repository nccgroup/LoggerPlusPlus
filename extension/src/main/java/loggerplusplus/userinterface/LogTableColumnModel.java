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

package loggerplusplus.userinterface;

import loggerplusplus.LoggerPlusPlus;

import javax.swing.event.TableColumnModelEvent;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.TableColumn;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;

import static loggerplusplus.Globals.PREF_LOG_TABLE_SETTINGS;

//The visible columns are stored in the underlying class.

public class LogTableColumnModel extends DefaultTableColumnModel {

    private final ArrayList<LogTableColumn> allColumns;

    public LogTableColumnModel() {
        super();
        allColumns = new ArrayList<>();
        setup();
    }

    private void setup(){
        ArrayList<LogTableColumn> columnList = (ArrayList<LogTableColumn>)
                LoggerPlusPlus.preferences.getSetting(PREF_LOG_TABLE_SETTINGS);

        // Sorting based on order number
        Collections.sort(columnList);

        for (int i = 0; i < columnList.size(); i++) {
            LogTableColumn column = columnList.get(i);
            column.setModelIndex(i);
            allColumns.add(column);
            if (column.isVisible())
                addColumn(column);
        }
    }

    @Override
    public void addColumn(TableColumn column) {
        //We should add the column at the correct position based on its order value.
        if (column == null) {
            throw new IllegalArgumentException("Object is null");
        } else {
            if(this.tableColumns.size() == 0){
                this.tableColumns.addElement(column);
            }else {
                //Find the first element with a greater order than the one to be added and add it before it.
                boolean added = false;
                for (int i = 0; i < this.tableColumns.size(); i++) {
                    if (((LogTableColumn) this.tableColumns.get(i)).getOrder() > ((LogTableColumn) column).getOrder()){
                        this.tableColumns.add(Math.max(i-1,0), column);
                        added = true;
                        break;
                    }
                }
                if(!added){ //No elements with a greater order value. Add it to the end.
                    this.tableColumns.addElement(column);
                }
            }
            column.addPropertyChangeListener(this);
            this.fireColumnAdded(new TableColumnModelEvent(this, 0, this.getColumnCount() - 1));
        }
    }


    //TableModel gets the column from the model index, not the view index.
    //If we dont do this all the values are wrong!
    public LogTableColumn getModelColumn(int modelIndex){
        return allColumns.get(modelIndex);
    }

    public void resetToDefaultVariables() {
        LoggerPlusPlus.preferences.resetSetting(PREF_LOG_TABLE_SETTINGS);
        Enumeration<TableColumn> columns = this.getColumns();
        while(columns.hasMoreElements()){
            this.removeColumn(columns.nextElement());
        }
        allColumns.clear();
        setup();
    }

    public void saveLayout() {
        LoggerPlusPlus.preferences.setSetting(PREF_LOG_TABLE_SETTINGS, this.allColumns);
    }

    @Override
    public void moveColumn(int viewFrom, int viewTo) {
//		viewToModelMap
        super.moveColumn(viewFrom, viewTo);
        ((LogTableColumn) getColumn(viewFrom)).setOrder(viewTo);
        if(viewFrom < viewTo) {
            for (int i = viewFrom + 1; i <= viewTo; i++) {
                ((LogTableColumn) getColumn(i)).setOrder(i-1);
            }
            //Save the changes
            saveLayout();
        }else if(viewFrom > viewTo){
            for (int i = viewFrom-1; i >= viewTo; i--) {
                ((LogTableColumn) getColumn(i)).setOrder(i+1);
            }
            //Save the changes
            saveLayout();
        }else{
            //no change
        }
        this.fireColumnMoved(new TableColumnModelEvent(this, viewFrom, viewTo));
    }

    public void toggleDisabled(LogTableColumn logTableColumn) {
//		logTableColumn.setEnabled(!logTableColumn.isEnabled());
//		if(logTableColumn.isEnabled()){
//			logTableColumn.setVisible(true); // when a field is enabled, then it becomes visible automatically
//			//Add column to view
//			addColumn(logTableColumn);
//		}else{
//			//Remove column from view
//			removeColumn(logTableColumn);
//		}
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
    }

    public Enumeration<LogTableColumn> getAllColumns() {
        return Collections.enumeration(this.allColumns);
    }
}
