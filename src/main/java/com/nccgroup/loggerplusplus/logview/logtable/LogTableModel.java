package com.nccgroup.loggerplusplus.logview.logtable;

import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilterListener;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.filter.tag.TagListener;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logview.processor.LogProcessor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.*;

/* Extending AbstractTableModel to design the logTable behaviour based on the array list */
public class LogTableModel extends AbstractTableModel implements ColorFilterListener, TagListener {

    private final LogTableController controller;
    private final List<LogEntry> entries;
    private LogTableColumnModel columnModel;

    public LogTableModel(LogTableController controller, LogTableColumnModel columnModel) {
        this.controller = controller;
        this.columnModel = columnModel;
        this.entries = Collections.synchronizedList(new ArrayList<>());
    }

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return this.columnModel.getColumnCount();
    }

    @Override
    public boolean isCellEditable(int rowModelIndex, int columnModelIndex) {
        return !((LogTableColumn) this.columnModel.getColumn(columnModelIndex)).isReadOnly();
    }

    @Override
    public void setValueAt(Object value, int rowModelIndex, int columnModelIndex) {
        LogEntry logEntry = entries.get(rowModelIndex);
        if (this.columnModel.getColumn(columnModelIndex).getIdentifier() == LogEntryField.COMMENT) {
            logEntry.setComment(String.valueOf(value));
        }
        fireTableCellUpdated(rowModelIndex, columnModelIndex);
    }

    @Override
    public Class<?> getColumnClass(int columnModelIndex) {
        Object val = getValueAt(0, columnModelIndex);
        return val == null ? Object.class : val.getClass();
    }

    private int getMaxEntries() {
        return this.controller.getMaximumEntries();
    }

    public void removeLogEntry(LogEntry logEntry) {
        removeLogEntries(Arrays.asList(logEntry));
    }

    public void removeLogEntries(List<LogEntry> logEntry) {
        synchronized (entries) {
            for (LogEntry entry : logEntry) {
                int index = entries.indexOf(entry);
                removeEntryAtRow(index);
            }
        }
    }

    public synchronized void removeEntryAtRow(int row) {
        entries.remove(row);
        this.fireTableRowsDeleted(row, row);
    }

    public synchronized void addEntry(LogEntry logEntry) {
        int index = entries.size();
        entries.add(logEntry);
        this.fireTableRowsInserted(index, index);

        int excess = Math.max(entries.size() - controller.getMaximumEntries(), 0);
        for (int excessIndex = 0; excessIndex < excess; excessIndex++) {
            removeEntryAtRow(0); // Always remove the oldest entry
        }
    }

    public synchronized void updateEntry(LogEntry logEntry) {
        int index = entries.indexOf(logEntry);
        fireTableRowsUpdated(index, index);
    }

    @Override
    public Object getValueAt(int rowIndex, int colModelIndex) {
        if (rowIndex >= entries.size())
            return null;

        LogTableColumn column = (LogTableColumn) columnModel.getColumn(colModelIndex);

        if (column.getIdentifier() == LogEntryField.NUMBER) {
            return rowIndex + 1;
        }

        Object value = entries.get(rowIndex).getValueByKey(column.getIdentifier());

        if (value instanceof Date) {
            return LogProcessor.LOGGER_DATE_FORMAT.format(value);
        }
        return value;
    }

    public List<LogEntry> getData() {
        return this.entries;
    }

    public LogEntry getRow(int row) {
        return this.entries.get(row);
    }

    public void reset() {
        this.entries.clear();
        this.fireTableDataChanged();
    }

    // FilterListeners
    @Override
    public void onColorFilterChange(final TableColorRule filter) {
        createFilterTestingWorker(filter, filter.isShouldRetest()).execute();
    }

    @Override
    public void onColorFilterAdd(final TableColorRule filter) {
        if (!filter.isEnabled() || filter.getFilterExpression() == null)
            return;
        createFilterTestingWorker(filter, false);
    }

    @Override
    public void onColorFilterRemove(final TableColorRule filter) {
        if (!filter.isEnabled() || filter.getFilterExpression() == null)
            return;
        new SwingWorker<Void, Integer>() {
            @Override
            protected Void doInBackground() {
                for (int i = 0; i < entries.size(); i++) {
                    boolean wasPresent = entries.get(i).getMatchingColorFilters().remove(filter.getUuid());
                    if (wasPresent) {
                        publish(i);
                    }
                }
                return null;
            }

            @Override
            protected void process(List<Integer> rows) {
                for (Integer row : rows) {
                    fireTableRowsUpdated(row, row);
                }
            }
        }.execute();
    }

    private SwingWorker<Void, Integer> createFilterTestingWorker(final TableColorRule filter, boolean retestExisting) {
        return new SwingWorker<Void, Integer>() {

            @Override
            protected Void doInBackground() {
                for (int i = 0; i < entries.size(); i++) {
                    boolean testResultChanged = entries.get(i).testColorFilter(filter, retestExisting);
                    if (testResultChanged) {
                        publish(i);
                    }
                }

                return null;
            }

            @Override
            protected void process(List<Integer> updatedRows) {
                for (Integer row : updatedRows) {
                    fireTableRowsUpdated(row, row);
                }
            }
        };
    }

    //TagListeners
    @Override
    public void onTagChange(final Tag filter) {
        createTagTestingWorker(filter, filter.shouldRetest()).execute();
    }

    @Override
    public void onTagAdd(final Tag filter) {
        if (!filter.isEnabled() || filter.getFilterExpression() == null)
            return;
        createTagTestingWorker(filter, false).execute();
    }

    @Override
    public void onTagRemove(final Tag filter) {
        if (!filter.isEnabled() || filter.getFilterExpression() == null)
            return;
        new SwingWorker<Void, Integer>() {
            @Override
            protected Void doInBackground() {
                for (int i = 0; i < entries.size(); i++) {
                    boolean wasPresent = entries.get(i).getMatchingTags().remove(filter);
                    if (wasPresent) {
                        publish(i);
                    }
                }
                return null;
            }

            @Override
            protected void process(List<Integer> rows) {
                for (Integer row : rows) {
                    fireTableRowsUpdated(row, row);
                }
            }
        }.execute();
    }

    private SwingWorker<Void, Integer> createTagTestingWorker(final Tag filter, boolean retestExisting) {
        return new SwingWorker<Void, Integer>() {

            @Override
            protected Void doInBackground() {
                for (int i = 0; i < entries.size(); i++) {
                    boolean testResultChanged = entries.get(i).testTag(filter, retestExisting);
                    if (testResultChanged) {
                        publish(i);
                    }
                }

                return null;
            }

            @Override
            protected void process(List<Integer> updatedRows) {
                for (Integer row : updatedRows) {
                    fireTableRowsUpdated(row, row);
                }
            }
        };
    }
}