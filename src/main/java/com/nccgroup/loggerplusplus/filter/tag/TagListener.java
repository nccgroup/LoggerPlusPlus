package com.nccgroup.loggerplusplus.filter.tag;

/**
 * Created by corey on 20/07/17.
 */
public interface TagListener {

    void onTagChange(Tag filter);

    void onTagAdd(Tag filter);

    void onTagRemove(Tag filter);
}
