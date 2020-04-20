//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Originally Developed by Soroush Dalili (@irsdl)
// Maintained by Corey Arthur (@CoreyD97)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package com.nccgroup.loggerplusplus.logentry;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.List;

public class LogEntrySerializer implements JsonSerializer<LogEntry> {

	private final List<LogEntryField> excludedFields = Arrays.asList(LogEntryField.NUMBER);

	@Override
	public JsonElement serialize(LogEntry src, Type typeOfSrc, JsonSerializationContext context) {
		JsonObject entry = new JsonObject();
		for (FieldGroup group : FieldGroup.values()) {
			JsonObject groupEntries = new JsonObject();
			for (LogEntryField fieldInGroup : LogEntryField.getFieldsInGroup(group)) {
				if(excludedFields.contains(fieldInGroup)) continue;
				groupEntries.add(fieldInGroup.getLabels()[0], context.serialize(src.getValueByKey(fieldInGroup)));
			}
			entry.add(group.getLabel(), groupEntries);
		}
		return entry;
	}
}
