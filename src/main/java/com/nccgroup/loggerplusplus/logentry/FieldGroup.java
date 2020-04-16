package com.nccgroup.loggerplusplus.logentry;

import java.util.HashMap;

public enum FieldGroup {
    PROXY("Proxy"),
    REQUEST("Request"),
    RESPONSE("Response");
    private String label;

    private static final HashMap<String, FieldGroup> groupLabelMap = new HashMap<>();
    static {
        for (FieldGroup fieldGroup : FieldGroup.values()) {
            groupLabelMap.put(fieldGroup.label.toUpperCase(), fieldGroup);
        }
    }

    FieldGroup(String label){
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public static FieldGroup findByLabel(String label){
        return groupLabelMap.get(label.toUpperCase());
    }
}
