package com.nccgroup.loggerplusplus.logentry;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public enum FieldGroup {
    ENTRY("Entry", "Log", "Proxy"),
    REQUEST("Request"),
    RESPONSE("Response");
    private String label;
    private List<String> additionalLabels;

    private static final HashMap<String, FieldGroup> groupLabelMap = new HashMap<>();

    static {
        for (FieldGroup fieldGroup : FieldGroup.values()) {
            groupLabelMap.put(fieldGroup.label.toUpperCase(), fieldGroup);
            fieldGroup.additionalLabels.forEach(label -> groupLabelMap.put(label.toUpperCase(), fieldGroup));
        }
    }

    FieldGroup(String primaryLabel, String... labels) {
        this.label = primaryLabel;
        additionalLabels = Arrays.asList(labels);
    }

    public String getLabel() {
        return label;
    }

    public static FieldGroup findByLabel(String label) {
        return groupLabelMap.get(label.toUpperCase());
    }
}
