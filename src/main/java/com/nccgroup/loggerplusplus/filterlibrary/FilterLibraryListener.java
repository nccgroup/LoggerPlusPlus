package com.nccgroup.loggerplusplus.filterlibrary;

import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;

public interface FilterLibraryListener {
    void onFilterAdded(SavedFilter savedFilter, int index);
    void onFilterRemoved(SavedFilter savedFilter, int index);
    void onFilterModified(SavedFilter savedFilter, int index);
}
