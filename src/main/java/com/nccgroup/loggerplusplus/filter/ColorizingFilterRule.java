package com.nccgroup.loggerplusplus.filter;

import com.google.gson.annotations.JsonAdapter;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import lombok.Getter;
import lombok.Setter;

import java.awt.*;

public abstract class ColorizingFilterRule extends FilterRule {

    @Getter @Setter
    private Color backgroundColor;
    @Getter @Setter
    private Color foregroundColor;
    @Getter @Setter
    private short priority;
    @Getter @Setter
    private boolean enabled;

    protected ColorizingFilterRule(String name){
        super(name);
    }

    protected ColorizingFilterRule(String name, FilterExpression filterExpression){
        super(name, filterExpression);
    }

    protected ColorizingFilterRule(String name, String filter){
        super(name, filter);
    }

    @Override
    public boolean equals(Object obj) {
        if(obj instanceof ColorizingFilterRule){
            return ((ColorizingFilterRule) obj).getUuid().equals(this.getUuid());
        }else{
            return super.equals(obj);
        }
    }
}
