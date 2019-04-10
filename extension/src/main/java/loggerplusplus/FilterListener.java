package loggerplusplus;

import loggerplusplus.filter.LogFilter;

public interface FilterListener {
    void onFilterSet(LogFilter filter);
    void onFilterError(String invalidFilter);
    void onFilterCleared();
}
