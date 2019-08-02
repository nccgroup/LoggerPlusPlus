package loggerplusplus.filter;

public enum Operator {
    EQUAL("=="), NOT_EQUAL("!="), GREATER_THAN(">"), LESS_THAN("<"),
    GREATER_THAN_EQUAL(">="), LESS_THAN_EQUAL("<="), CONTAINS("CONTAINS");

    private final String label;

    Operator(String label){
        this.label = label;
    }

    public String getLabel() {
        return this.label;
    }
}
