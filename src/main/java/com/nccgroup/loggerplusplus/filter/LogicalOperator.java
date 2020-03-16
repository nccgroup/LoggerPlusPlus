package com.nccgroup.loggerplusplus.filter;

public enum LogicalOperator {
    AND("AND"), OR("OR"), XOR("XOR");

    private final String label;

    LogicalOperator(String label){
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
