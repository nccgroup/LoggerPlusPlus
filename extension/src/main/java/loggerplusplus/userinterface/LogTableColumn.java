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

// To define a structure for table headers
// This will provide a high degree of customisation
// a sample JSON object which will be converted to this object is as follows:
// "{'columnsDefinition':[{'id':'number','visibleName':'#','width':50,'type':'int','readonly':true,'order':1,'visible':true,'description':'Item index number','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}}]}";

import com.google.gson.*;

import javax.swing.table.TableColumn;
import java.lang.reflect.Type;

public class LogTableColumn extends TableColumn implements Comparable<LogTableColumn>{
	private String name;
	private boolean enabled;
	private String visibleName;
	private String type;
	private boolean readonly;
	private Integer order;
	private boolean visible;
	private String description;
	private boolean isRegEx;
	private RegExData regExData;
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
	public int getModelIndex() {
		return this.getIdentifier();
	}

	@Override
	public Integer getIdentifier() { return (Integer) this.identifier; }
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public boolean isEnabled() {
		return enabled;
	}
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}
	public String getVisibleName() {
		return visibleName;
	}
	public void setVisibleName(String visibleName) {
		this.visibleName = visibleName;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public boolean isReadonly() {
		return readonly;
	}
	public void setReadonly(boolean readonly) {
		this.readonly = readonly;
	}
	public Integer getOrder() {
		return order;
	}
	public void setOrder(Integer order) {
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
	public boolean isRegEx() {
		return isRegEx;
	}
	public void setRegEx(boolean isRegEx) {
		this.isRegEx = isRegEx;
	}
	public RegExData getRegExData() {
		return regExData;
	}
	public void setRegExData(RegExData regExData) {
		this.regExData = regExData;
	}

	public String getDefaultVisibleName() {
		return defaultVisibleName;
	}

	public void setDefaultVisibleName(String defaultVisibleName) {
		this.defaultVisibleName = defaultVisibleName;
	}

	public void setIsRegEx(boolean isRegEx) {
		this.isRegEx = isRegEx;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public static class RegExData{
		private String regExString;
		private boolean regExCaseSensitive;

		public String getRegExString() {
			return regExString;
		}
		public void setRegExString(String regExString) {
			this.regExString = regExString;
		}
		public boolean isRegExCaseSensitive() {
			return regExCaseSensitive;
		}
		public void setRegExCaseSensitive(boolean regExCaseSensitive) {
			this.regExCaseSensitive = regExCaseSensitive;
		}
	}


	@Override
	public Object getHeaderValue() {
		return this.getVisibleName();
	}

	@Override
	public int compareTo(LogTableColumn logTableColumn) {
		return this.getOrder().compareTo(logTableColumn.getOrder());
	}

	public static class ColumnSerializer implements JsonDeserializer<LogTableColumn>, JsonSerializer<LogTableColumn> {
		//id, name, enabled, defaultVisibleName, visibleName, width, type, readonly, order, visible, description, isRegEx, regExData
		@Override
		public JsonElement serialize(LogTableColumn column, Type type, JsonSerializationContext jsonSerializationContext) {
			JsonObject object = new JsonObject();
			object.addProperty("id", column.getIdentifier());
			object.addProperty("name", column.getName());
			object.addProperty("enabled", column.isEnabled());
			object.addProperty("defaultVisibleName", column.getDefaultVisibleName());
			object.addProperty("visibleName", column.getVisibleName());
			object.addProperty("preferredWidth", column.getPreferredWidth());
			object.addProperty("type", column.getType());
			object.addProperty("readonly", column.isReadonly());
			object.addProperty("order", column.getOrder());
			object.addProperty("visible", column.isVisible());
			object.addProperty("description", column.getDescription());
			object.addProperty("isRegEx", column.isRegEx());
			object.addProperty("regExString", column.getRegExData().getRegExString());
			object.addProperty("regExCaseSensitive", column.getRegExData().isRegExCaseSensitive());
			return object;
		}

		@Override
		public LogTableColumn deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
			LogTableColumn column = null;
			column = new LogTableColumn();
			JsonObject object = jsonElement.getAsJsonObject();
			column.setIdentifier(object.get("id").getAsInt());
			column.setName(object.get("name").getAsString());
			column.setEnabled(object.get("enabled").getAsBoolean());
			column.setDefaultVisibleName(object.get("defaultVisibleName").getAsString());
			column.setVisibleName(object.get("visibleName").getAsString());
			column.setWidth(object.get("preferredWidth").getAsInt());
			column.setType(object.get("type").getAsString());
			column.setReadonly(object.get("readonly").getAsBoolean());
			column.setOrder(object.get("order").getAsInt());
			column.setVisible(object.get("visible").getAsBoolean());
			column.setDescription(object.get("description").getAsString());
			column.setIsRegEx(object.get("isRegEx").getAsBoolean());
			LogTableColumn.RegExData regExData = new LogTableColumn.RegExData();
			if(object.has("regExData")) {
				regExData.setRegExString(object.getAsJsonObject("regExData").get("regExString").getAsString());
				regExData.setRegExCaseSensitive(object.getAsJsonObject("regExData").get("regExCaseSensitive").getAsBoolean());
			}else{
				regExData.setRegExString(object.get("regExString").getAsString());
				regExData.setRegExCaseSensitive(object.get("regExCaseSensitive").getAsBoolean());
			}
			column.setRegExData(regExData);
			return column;
		}
	}

}
