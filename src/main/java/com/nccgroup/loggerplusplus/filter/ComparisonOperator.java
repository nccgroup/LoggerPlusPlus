package com.nccgroup.loggerplusplus.filter;

public enum ComparisonOperator {
    EQUAL("=="), NOT_EQUAL("!="), GREATER_THAN(">"), LESS_THAN("<"),
    GREATER_THAN_EQUAL(">="), LESS_THAN_EQUAL("<="), CONTAINS("CONTAINS"), IN("IN"), MATCHES("MATCHES");

    private final String label;

    ComparisonOperator(String label) {
        this.label = label;
    }

    public String getLabel() {
        return this.label;
    }

    @Override
    public String toString() {
        return label;
    }
}
