package com.nccgroup.loggerplusplus.filter.colorfilter;

import com.nccgroup.loggerplusplus.filter.ColorizingFilterRule;
import com.nccgroup.loggerplusplus.filter.FilterExpression;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import lombok.AccessLevel;
import lombok.Getter;
import org.elasticsearch.common.Table;

import java.awt.*;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Created by corey on 19/07/17.
 */
public class TableColorRule extends ColorizingFilterRule implements Comparable<TableColorRule>{

    @Getter(AccessLevel.PUBLIC)
    private boolean shouldRetest = true;

    public TableColorRule(){
        super("", "");
    }

    public TableColorRule(String title, String filterString) {
        super(title, filterString);
    }

    public TableColorRule(String title, FilterExpression filterExpression) {
        super(title, filterExpression);
    }

    @Override
    public boolean trySetFilter(String filterString){
        boolean success = super.trySetFilter(filterString);
        if(success) shouldRetest = true;
        return success;
    }

    @Override
    public void setFilter(FilterExpression filter) {
        super.setFilter(filter);
        shouldRetest = true;
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        shouldRetest = true;
    }

    @Override
    public int compareTo(TableColorRule tableColorRule) {
        return ((Comparable) this.getPriority()).compareTo(tableColorRule.getPriority());
    }

    @Override
    public String toString() {
        return "ColorFilter[" + (this.getFilterExpression() != null ? this.getFilterExpression().toString() : getFilterString()) + "]";
    }
}
