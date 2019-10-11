package com.nccgroup.loggerplusplus.filterlibrary;

import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;

public interface FilterLibraryListener {
    void onFilterAdded(SavedFilter savedFilter);
    void onFilterRemoved(SavedFilter savedFilter);
    void onFilterModified(SavedFilter savedFilter);
}
