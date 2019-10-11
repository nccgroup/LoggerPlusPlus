package com.nccgroup.loggerplusplus.filter.logfilter;

import com.nccgroup.loggerplusplus.filter.parser.ParseException;

public interface LogFilterListener {
    void onFilterSet(LogFilter filter);
    void onFilterError(String invalidFilter, ParseException exception);
    void onFilterCleared();
}
