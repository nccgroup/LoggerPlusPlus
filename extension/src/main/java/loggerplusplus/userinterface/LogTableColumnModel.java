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

import com.google.gson.*;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.userinterface.renderer.LeftTableCellRenderer;

import javax.swing.event.TableColumnModelEvent;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.TableColumn;
import java.beans.PropertyChangeEvent;
import java.util.*;

import static loggerplusplus.Globals.PREF_LOG_TABLE_SETTINGS;


// To keep the header descriptor JSON objects and to converts them to list objects

public class LogTableColumnModel extends DefaultTableColumnModel {
	private Map<Integer, LogTableColumn> columnMap;
	private Map<String, Integer> nameToModelIndexMap;
	private ArrayList<Integer> viewToModelMap;

	public LogTableColumnModel() {
		super();
		populateHeaders();
	}

	private void populateHeaders(){
		ArrayList<LogTableColumn> logTableColumns = (ArrayList<LogTableColumn>)
				LoggerPlusPlus.preferences.getSetting(PREF_LOG_TABLE_SETTINGS);


		// Sorting based on order number
		Collections.sort(logTableColumns);

		columnMap = new HashMap<>();
		nameToModelIndexMap = new HashMap<>();
		viewToModelMap = new ArrayList<>();
		for(LogTableColumn column : logTableColumns){
			column.setModelIndex(columnMap.size());
			columnMap.put(column.getIdentifier(), column);
			nameToModelIndexMap.put(column.getName().toUpperCase(), column.getIdentifier());
			if(column.isEnabled() && column.isVisible()){
				super.addColumn(column);
				addColumnToViewMap(column.getIdentifier(), false);
			}
			if(column.getType().equals("int")
					|| column.getType().equals("short")
					|| column.getType().equals("double")
					|| column.getType().equals("long"))
				column.setCellRenderer(new LeftTableCellRenderer());
		}
	}

	public void resetToDefaultVariables() {
		LoggerPlusPlus.preferences.resetSetting(PREF_LOG_TABLE_SETTINGS);
		populateHeaders();
	}

	public void saveLayout() {
		ArrayList<LogTableColumn> columns = new ArrayList<LogTableColumn>(columnMap.values());
		LoggerPlusPlus.preferences.setSetting(PREF_LOG_TABLE_SETTINGS, columns);
	}

	public LogTableColumn getColumnByName(String colName){
		return columnMap.get(nameToModelIndexMap.get(colName.toUpperCase()));
	}

	public Integer getColumnIndexByName(String colName){
		return nameToModelIndexMap.get(colName.toUpperCase());
	}

	public boolean isColumnEnabled(String colName){
		Integer modelColumnIndex = nameToModelIndexMap.get(colName.toUpperCase());
		if(modelColumnIndex == null){
			LoggerPlusPlus.callbacks.printError("Column Enabled check on nonexistent column! Corrupted column set? \"" + colName + "\"");
			return false;
		}else {
			return columnMap.get(modelColumnIndex).isEnabled();
		}
	}

	@Override
	public void addColumn(TableColumn tableColumn) {
		super.addColumn(tableColumn);
		addColumnToViewMap((Integer) tableColumn.getIdentifier(), true);
	}

	private void removeColumnFromViewMap(int viewColumn, boolean saveToPrefs){
		viewToModelMap.remove(viewColumn);
		reorderViewColumns(saveToPrefs);
	}

	private void addColumnToViewMap(int modelColumn, boolean saveToPrefs){
		viewToModelMap.add(modelColumn);
		reorderViewColumns(saveToPrefs);
	}

	@Override
	public void removeColumn(TableColumn tableColumn) {
		int viewLoc = getColumnViewLocation(tableColumn.getModelIndex());
		removeColumnFromViewMap(viewLoc, true);
		super.removeColumn(tableColumn);
	}

	@Override
	public int getColumnCount() {
		//DefaultRowSorter implies this is model column count but causes errors if so.
		return viewToModelMap.size();
//		return columnMap.size();
	}

	@Override
	public Enumeration<TableColumn> getColumns() {
		ArrayList<TableColumn> columns = new ArrayList<TableColumn>();
		for (Integer colIndex : viewToModelMap) {
			columns.add(columnMap.get(colIndex));
		}
		return Collections.enumeration(columns);
	}

	public ArrayList<LogTableColumn> getAllColumns(){
		return new ArrayList<LogTableColumn>(columnMap.values());
	}

	@Override
	public int getColumnIndex(Object o) {
		if(o instanceof LogTableColumn){
			return ((LogTableColumn) o).getIdentifier();
		}
		return -1;
	}

	@Override
	public LogTableColumn getColumn(int viewColumn) {
		return columnMap.get(viewToModelMap.get(viewColumn));
	}

	public LogTableColumn getModelColumn(int modelColumn) {
		return columnMap.get(modelColumn);
	}

	public int getColumnViewLocation(int modelColumnIndex) {
		return viewToModelMap.indexOf(modelColumnIndex);
	}

	private void reorderViewColumns(boolean saveToPrefs){
		Collections.sort(viewToModelMap, new Comparator<Integer>() {
			@Override
			public int compare(Integer colModelId, Integer otherColModelId) {
				return columnMap.get(colModelId).compareTo(columnMap.get(otherColModelId));
			}
		});
		if(saveToPrefs) {
			saveLayout();
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent propertyChangeEvent) {
		super.propertyChange(propertyChangeEvent);
	}

	@Override
	public void moveColumn(int viewFrom, int viewTo) {
//		viewToModelMap
		columnMap.get(viewToModelMap.get(viewFrom)).setOrder(viewTo);
		if(viewFrom < viewTo) {
			for (int i = viewFrom + 1; i <= viewTo; i++) {
				columnMap.get(viewToModelMap.get(i)).setOrder(i-1);
			}
			reorderViewColumns(true);
		}else if(viewFrom > viewTo){
			for (int i = viewFrom-1; i >= viewTo; i--) {
				columnMap.get(viewToModelMap.get(i)).setOrder(i+1);
			}
			reorderViewColumns(true);
		}else{
			//no change
		}
		this.fireColumnMoved(new TableColumnModelEvent(this, viewFrom, viewTo));
	}

	public void toggleDisabled(LogTableColumn logTableColumn) {
		logTableColumn.setEnabled(!logTableColumn.isEnabled());
		if(logTableColumn.isEnabled()){
			logTableColumn.setVisible(true); // when a field is enabled, then it becomes visible automatically
			//Add column to view
			addColumn(logTableColumn);
		}else{
			//Remove column from view
			removeColumn(logTableColumn);
		}
	}

	public void toggleHidden(LogTableColumn logTableColumn) {
		logTableColumn.setVisible(!logTableColumn.isVisible());
		if(logTableColumn.isVisible() && logTableColumn.isEnabled()){
			//Add the column to the view
			addColumn(logTableColumn);
		}else{
			//Remove the column from the view and adjust others to fit.
			removeColumn(logTableColumn);
		}
	}

	public TableColumn getColumnByViewLocation(int viewColumn) {
		return columnMap.get(viewToModelMap.get(viewColumn));
	}

	public int getModelColumnCount() {
		return columnMap.size();
	}

}
