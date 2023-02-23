package com.nccgroup.loggerplusplus.filter.tag;

import com.nccgroup.loggerplusplus.filter.ColorizingFilterRule;
import com.nccgroup.loggerplusplus.filter.FilterExpression;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import lombok.Getter;

import java.awt.*;
import java.util.UUID;

/**
 * Created by corey on 19/07/17.
 */
public class Tag extends ColorizingFilterRule implements Comparable<Tag> {

    @Getter
    private boolean shouldRetest = true;

    public Tag(){
        super("", "");
    }

    public Tag(String title, String filterString) {
        super(title, filterString);
    }

    public Tag(String title, FilterExpression filterExpression) {
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
    public void setPriority(short priority) {
        super.setPriority(priority);
        shouldRetest = true;
    }

    @Override
    public int compareTo(Tag tag) {
        return ((Comparable) this.getPriority()).compareTo(tag.getPriority());
    }

    public boolean shouldRetest() {
        return shouldRetest;
    }

    @Override
    public String toString() {
        return this.getName();
    }
}
