package com.nccgroup.loggerplusplus.filter.logfilter;

import com.nccgroup.loggerplusplus.filter.FilterExpression;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableModel;
import lombok.Getter;

import javax.swing.*;
import javax.swing.table.TableModel;

public class LogTableFilter extends RowFilter<TableModel, Integer> {

    @Getter
    private FilterExpression filterExpression;

    public LogTableFilter(String filterString) throws ParseException {
        this.filterExpression = new FilterExpression(filterString);
    }

    public LogTableFilter(FilterExpression filterExpression){
        this.filterExpression = filterExpression;
    }

    @Override
    public boolean include(RowFilter.Entry entry) {
        int index = (int) entry.getIdentifier();
        TableModel tableModel = (TableModel) entry.getModel();
        if(tableModel instanceof LogTableModel){
            LogEntry logEntry = ((LogTableModel) tableModel).getRow(index);
            return filterExpression.matches(logEntry);
        }
        return false;
    }
}
