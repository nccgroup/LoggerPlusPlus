package com.nccgroup.loggerplusplus.filter;

public enum BooleanOperator {
    AND("&&"), OR("||"), XOR("^");

    private final String label;

    BooleanOperator(String label){
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}
