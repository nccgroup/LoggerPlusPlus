package com.nccgroup.loggerplusplus.filter.savedfilter;

import com.nccgroup.loggerplusplus.filter.logfilter.LogFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;

/**
 * Created by corey on 19/07/17.
 */
public class SavedFilter {
    private String name;
    private LogFilter filter;
    private String filterString;

    public SavedFilter(FilterLibraryController filterLibraryController, String name, String filterString) throws ParseException {
        this.name = name.replaceAll("[^a-zA-Z0-9_.]", "_");
        this.setFilter(new LogFilter(filterLibraryController, filterString));
    }

    public LogFilter getFilter() {
        return filter;
    }

    public void setFilter(LogFilter filter) {
        this.filter = filter;
        if(filter != null)
            this.filterString = filter.toString();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        name = name.replaceAll("[^a-zA-Z0-9_.]", "_");
        this.name = name;
    }

    public String getFilterString() {
        return filterString;
    }

    public void setFilterString(String filterString) {
        this.filterString = filterString;
    }

    @Override
    public boolean equals(Object o) {
        if(o instanceof SavedFilter){
            SavedFilter other = (SavedFilter) o;
            return other.name.equals(name) && other.filterString.equals(filterString);
        }else{
            return super.equals(o);
        }
    }

    @Override
    public String toString() {
        return "SavedFilter[" + this.name + ", " + (this.filter == null ? this.filterString : this.filter) + "]";
    }
}
