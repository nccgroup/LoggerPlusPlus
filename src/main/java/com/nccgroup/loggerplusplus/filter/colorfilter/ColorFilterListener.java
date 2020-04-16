package com.nccgroup.loggerplusplus.filter.colorfilter;

/**
 * Created by corey on 20/07/17.
 */
public interface ColorFilterListener {

    void onFilterChange(ColorFilter filter);
    void onFilterAdd(ColorFilter filter);
    void onFilterRemove(ColorFilter filter);
}
