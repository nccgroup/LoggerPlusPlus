package com.nccgroup.loggerplusplus.filter.colorfilter;

/**
 * Created by corey on 20/07/17.
 */
public interface ColorFilterListener {

    void onColorFilterChange(TableColorRule filter);

    void onColorFilterAdd(TableColorRule filter);

    void onColorFilterRemove(TableColorRule filter);
}
