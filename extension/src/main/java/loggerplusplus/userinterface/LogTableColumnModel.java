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


// To keep the header descriptor JSON objects and to converts them to list objects

public class LogTableColumnModel extends DefaultTableColumnModel {

    private final HashMap<Integer, LogTableColumn> allColumns;

    public LogTableColumnModel() {
        super();
        allColumns = new HashMap<>();

        ArrayList<LogTableColumn> columnList = (ArrayList<LogTableColumn>)
                LoggerPlusPlus.preferences.getSetting(PREF_LOG_TABLE_SETTINGS);

        // Sorting based on order number
        Collections.sort(columnList);

        for(LogTableColumn column : columnList){
            allColumns.put(column.getModelIndex(), column);
            addColumn(column);
        }
    }

    @Override
    public TableColumn getColumn(int modelIndex) {
        return allColumns.get(modelIndex);
    }

    public void resetToDefaultVariables() {
        LoggerPlusPlus.preferences.resetSetting(PREF_LOG_TABLE_SETTINGS);
        Enumeration<TableColumn> columns = this.getColumns();
        while(columns.hasMoreElements()){
            this.removeColumn(columns.nextElement());
        }
    }

    public void saveLayout() {
        LoggerPlusPlus.preferences.setSetting(PREF_LOG_TABLE_SETTINGS, this.allColumns.values());
    }

    @Override
    public void moveColumn(int modelFrom, int modelTo) {
        super.moveColumn(modelFrom, modelTo);

//        We've moved the columns around in the model.
//        We must loop over them and update their model indexes.

        LogTableColumn movedColumn = (LogTableColumn) this.getColumn(modelFrom);
        movedColumn.setModelIndex(modelTo);
        if(modelFrom < modelTo) { //Moving right
            for (int i = modelFrom + 1; i <= modelTo; i++) { //From original pos to new pos
                LogTableColumn nextCol = (LogTableColumn) getColumn(i);
                nextCol.setModelIndex(i-1); //Move left one place
                this.allColumns.put(i-1, nextCol);
            }
            this.allColumns.put(modelTo, movedColumn);
            saveLayout();
            this.fireColumnMoved(new TableColumnModelEvent(this, modelFrom, modelTo));
        }else if(modelFrom > modelTo){ //Moving left
            for (int i = modelTo; i < modelFrom; i++) { //From original pos to new pos
                LogTableColumn nextCol = (LogTableColumn) getColumn(i);
                nextCol.setModelIndex(i+1); //Move right one place.
                this.allColumns.put(i+1, nextCol);
            }
            this.allColumns.put(modelTo, movedColumn);
            saveLayout();
            this.fireColumnMoved(new TableColumnModelEvent(this, modelFrom, modelTo));
        }else{
            //no change
        }
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

}
