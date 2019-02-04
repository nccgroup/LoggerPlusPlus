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
import loggerplusplus.userinterface.renderer.LeftTableCellRenderer;

import javax.swing.table.TableColumn;
import java.lang.reflect.Type;

public class LogTableColumn extends TableColumn implements Comparable<LogTableColumn>{

    public enum ColumnIdentifier {
        NUMBER, TOOL, URL, PATH, QUERY, STATUS, PROTOCOL, HOSTNAME, HOST, MIMETYPE, RESPONSELENGTH, TARGETPORT,
        METHOD, RESPONSETIME, REQUESTTIME, RTT, COMMENT, REQUESTCONTENTTYPE, URLEXTENSION, REFERRER,
        HASQUERYSTRINGPARAM, HASBODYPARAM, HASCOOKIEPARAM, REQUESTLENGTH, RESPONSECONTENTTYPE, INFERREDTYPE,
        HASSETCOOKIES, PARAMS, TITLE, ISSSL, TARGETIP, NEWCOOKIES, LISTENERINTERFACE, CLIENTIP, COMPLETE,
        SENTCOOKIES, USESCOOKIEJAR, REGEX1REQ, REGEX2REQ, REGEX3REQ, REGEX4REQ, REGEX5REQ, REGEX1RESP,
        REGEX2RESP, REGEX3RESP, REGEX4RESP, REGEX5RESP, REQUEST, RESPONSE, REQUESTHEADERS, RESPONSEHEADERS;
    }

	private String name;
    private int order;
	private boolean enabled;
	private String visibleName;
	private String type;
	private boolean visible;
	private boolean readOnly;
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
	public ColumnIdentifier getIdentifier() { return (ColumnIdentifier) this.identifier; }
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
	public boolean isRegEx() {
		return isRegEx;
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

	public static class RegExData{
		private String regExString;
		private boolean regExCaseSensitive;

		public String getRegExString() {
			return regExString;
		}
		public boolean isRegExCaseSensitive() {
			return regExCaseSensitive;
		}

		public void setRegExCaseSensitive(boolean caseSensitive) {
			regExCaseSensitive = caseSensitive;
		}

		public void setRegExString(String regExString) {
			this.regExString = regExString;
		}
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
			object.addProperty("enabled", column.enabled);
			object.addProperty("defaultVisibleName", column.defaultVisibleName);
			object.addProperty("visibleName", column.visibleName);
			object.addProperty("preferredWidth", column.width);
			object.addProperty("type", column.type);
			object.addProperty("readonly", column.readOnly);
			object.addProperty("visible", column.visible);
			object.addProperty("description", column.description);
			object.addProperty("isRegEx", column.isRegEx);
			object.addProperty("regExString", column.regExData.regExString);
			object.addProperty("regExCaseSensitive", column.regExData.regExCaseSensitive);
			return object;
		}

		@Override
		public LogTableColumn deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
			LogTableColumn column = null;
			JsonObject object = jsonElement.getAsJsonObject();
            column = new LogTableColumn();
            column.identifier = ColumnIdentifier.valueOf(object.get("id").getAsString());
			column.name = object.get("name").getAsString();
			column.order = object.get("order").getAsInt();
//			column.enabled = object.get("enabled").getAsBoolean();
			column.enabled = true;
			column.defaultVisibleName = object.get("defaultVisibleName").getAsString();
			column.visibleName = object.get("visibleName").getAsString();
			column.width = object.get("preferredWidth").getAsInt();
			column.type = object.get("type").getAsString();
			column.readOnly = object.get("readonly").getAsBoolean();
			column.visible = object.get("visible").getAsBoolean();
			column.description = object.get("description").getAsString();
			column.isRegEx = object.get("isRegEx").getAsBoolean();
			LogTableColumn.RegExData regExData = new LogTableColumn.RegExData();
			if(object.has("regExData")) {
				regExData.regExString = object.getAsJsonObject("regExData").get("regExString").getAsString();
				regExData.regExCaseSensitive = object.getAsJsonObject("regExData").get("regExCaseSensitive").getAsBoolean();
			}else{
				regExData.regExString = object.get("regExString").getAsString();
				regExData.regExCaseSensitive = object.get("regExCaseSensitive").getAsBoolean();
			}
			column.setRegExData(regExData);

			if(column.getType().equals("int") || column.getType().equals("short")
					|| column.getType().equals("double") || column.getType().equals("long")){
				column.setCellRenderer(new LeftTableCellRenderer());
			}
			return column;
		}
	}

    @Override
    public String toString() {
        return "LogTableColumn[" + identifier + "]";
    }
}
