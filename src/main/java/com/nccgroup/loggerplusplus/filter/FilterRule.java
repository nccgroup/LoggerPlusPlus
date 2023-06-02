package com.nccgroup.loggerplusplus.filter;

import com.google.gson.annotations.SerializedName;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import lombok.Getter;

import java.util.UUID;

public abstract class FilterRule {

    @Getter @SerializedName("uid")
    private UUID uuid;
    @Getter
    private String name;
    @Getter
    private String filterString;
    @Getter @SerializedName("filter")
    private FilterExpression filterExpression;

    public FilterRule(String name){
        this.name = name;
        this.uuid = UUID.randomUUID();
    }

    public FilterRule(String name, FilterExpression filterExpression){
        this(name);
        this.filterExpression = filterExpression;
        this.filterString = filterExpression.toString();
    }

    public FilterRule(String name, String filterString){
        this(name);
        trySetFilter(filterString);
    }

    protected void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public void setFilter(FilterExpression expression) {
        this.filterExpression = expression;
        if(expression != null) this.filterString = expression.toString();
    }

    public void setName(String name){
        this.name = name;
    }

    public boolean trySetFilter(String filterString){
        this.filterString = filterString;
        try{
            parseAndSetFilter(filterString);
        }catch (ParseException e){
            return false;
        }

        return true;
    }

    public void parseAndSetFilter(String filterString) throws ParseException {
        this.filterString = filterString;
        try {
            this.filterExpression = new FilterExpression(name, filterString);
        }catch (ParseException e){
            this.filterExpression = null;
            throw e;
        }
    }
}
