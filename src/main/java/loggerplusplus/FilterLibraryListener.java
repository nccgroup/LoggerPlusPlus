package loggerplusplus;

import loggerplusplus.filter.SavedFilter;

public interface FilterLibraryListener {
    void onFilterAdded(SavedFilter savedFilter);
    void onFilterRemoved(SavedFilter savedFilter);
    void onFilterModified(SavedFilter savedFilter);
}
