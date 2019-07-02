package loggerplusplus;

import loggerplusplus.filter.LogFilter;
import loggerplusplus.filter.parser.ParseException;

public interface FilterListener {
    void onFilterSet(LogFilter filter);
    void onFilterError(String invalidFilter, ParseException exception);
    void onFilterCleared();
}
