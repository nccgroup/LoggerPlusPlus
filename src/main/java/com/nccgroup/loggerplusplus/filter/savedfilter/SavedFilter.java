package com.nccgroup.loggerplusplus.filter.savedfilter;

import com.nccgroup.loggerplusplus.filter.FilterExpression;
import com.nccgroup.loggerplusplus.filter.FilterRule;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;

/**
 * Created by corey on 19/07/17.
 */
public class SavedFilter extends FilterRule {

    public SavedFilter(String name, String filterString) {
        super(name.replaceAll("[^a-zA-Z0-9_.]", "_"));
        this.trySetFilter(filterString);
    }

    public SavedFilter(String name, FilterExpression filterExpression){
        super(name, filterExpression);
    }

    @Override
    public void setName(String name) {
        name = name.replaceAll("[^a-zA-Z0-9_.]", "_");
        super.setName(name);
    }

    @Override
    public boolean equals(Object o) {
        if(o instanceof SavedFilter){
            SavedFilter other = (SavedFilter) o;
            return other.getName().equals(getName()) && other.getFilterString().equals(getFilterString());
        }else{
            return super.equals(o);
        }
    }

    @Override
    public String toString() {
        return "SavedFilter[" + this.getName() + ", " + (this.getFilterExpression() == null ? this.getFilterString() : this.getFilterExpression()) + "]";
    }
}
