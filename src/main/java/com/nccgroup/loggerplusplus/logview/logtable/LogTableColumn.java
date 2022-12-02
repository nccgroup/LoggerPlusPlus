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

// To define a structure for table headers
// This will provide a high degree of customisation
// a sample JSON object which will be converted to this object is as follows:
// "{'columnsDefinition':[{'id':'number','visibleName':'#','width':50,'type':'int','readonly':true,'order':1,'visible':true,'description':'Item index number','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}}]}";

import com.google.gson.*;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;

import javax.swing.table.TableColumn;
import java.lang.reflect.Type;

public class LogTableColumn extends TableColumn implements Comparable<LogTableColumn>{

	private String name;
    private int order;
	private String visibleName;
	private boolean visible;
	private boolean readOnly;
	private String description;
	private String defaultVisibleName;

	@Override
	public void setPreferredWidth(int width){
		super.setPreferredWidth(width);
	}
	@Override
	public void setWidth(int width){
		super.setWidth(width);
		this.setPreferredWidth(width);
	}

	@Override
	public LogEntryField getIdentifier() { return (LogEntryField) this.identifier; }
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getVisibleName() {
		return visibleName;
	}
	public void setVisibleName(String visibleName) {
		this.visibleName = visibleName;
	}

	public boolean isReadOnly() {
		return readOnly;
	}
	public void setReadOnly(boolean readOnly) {
		this.readOnly = readOnly;
	}

	public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	public boolean isVisible() {
		return visible;
	}
	public void setVisible(boolean visible) {
		this.visible = visible;
	}
	public String getDescription() {
		return description;
	}

	public String getDefaultVisibleName() {
		return defaultVisibleName;
	}


	@Override
	public Object getHeaderValue() {
		return this.getVisibleName();
	}

	@Override
	public int compareTo(LogTableColumn logTableColumn) {
		return Integer.compare(this.order, logTableColumn.order);
	}

	public static class ColumnSerializer implements JsonDeserializer<LogTableColumn>, JsonSerializer<LogTableColumn> {
		//id, name, enabled, defaultVisibleName, visibleName, width, type, readonly, order, visible, description, isRegEx, regExData
		@Override
		public JsonElement serialize(LogTableColumn column, Type type, JsonSerializationContext jsonSerializationContext) {
			JsonObject object = new JsonObject();
			object.addProperty("id", String.valueOf(column.identifier));
			object.addProperty("order", column.order);
			object.addProperty("name", column.name);
			object.addProperty("defaultVisibleName", column.defaultVisibleName);
			object.addProperty("visibleName", column.visibleName);
			object.addProperty("preferredWidth", column.width);
			object.addProperty("readonly", column.readOnly);
			object.addProperty("visible", column.visible);
			object.addProperty("description", column.description);
			return object;
		}

		@Override
		public LogTableColumn deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
			LogTableColumn column = null;
			JsonObject object = jsonElement.getAsJsonObject();
            column = new LogTableColumn();
            column.identifier = LogEntryField.getByFullyQualifiedName(object.get("id").getAsString());
			column.name = object.get("name").getAsString();
			column.order = object.get("order").getAsInt();
			column.defaultVisibleName = object.get("defaultVisibleName").getAsString();
			column.visibleName = object.get("visibleName").getAsString();
			column.setWidth(object.get("preferredWidth").getAsInt());
			column.readOnly = object.get("readonly").getAsBoolean();
			column.visible = object.get("visible").getAsBoolean();
			column.description = object.get("description").getAsString();

			return column;
		}
	}

    @Override
    public String toString() {
        return "LogTableColumn[" + identifier + "]";
    }
}
