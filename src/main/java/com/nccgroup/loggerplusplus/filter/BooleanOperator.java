package com.nccgroup.loggerplusplus.filter;

public enum BooleanOperator {
    AND("AND"), OR("OR"), XOR("XOR");

    private final String label;

    BooleanOperator(String label){
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
