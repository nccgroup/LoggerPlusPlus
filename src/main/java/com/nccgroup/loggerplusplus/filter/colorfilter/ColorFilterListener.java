package com.nccgroup.loggerplusplus.filter.colorfilter;

/**
 * Created by corey on 20/07/17.
 */
public interface ColorFilterListener {

    void onColorFilterChange(ColorFilter filter);

    void onColorFilterAdd(ColorFilter filter);

    void onColorFilterRemove(ColorFilter filter);
}
