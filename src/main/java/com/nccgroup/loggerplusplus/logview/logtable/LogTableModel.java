package com.nccgroup.loggerplusplus.logview.logtable;

import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilterListener;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.filter.tag.TagListener;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logview.processor.LogProcessor;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.RandomAccess;
import java.util.function.IntSupplier;
import java.util.function.Predicate;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;

/**
 * The rows of the log table: the entries in the order they arrived, at most a maximum number of
 * them, the oldest dropped first.
 *
 * <p>Rows change on the event dispatch thread, where the table hears of each change. Other threads
 * (searches, exports, filter tests) only read, through the same lock. Every operation a logged
 * message causes costs the same however many rows there are: appending moves one index of a ring,
 * and an entry's row is found by its arrival number.
 */
public class LogTableModel extends AbstractTableModel implements ColorFilterListener, TagListener {

    private final IntSupplier maximumEntries;
    private final EntryRing entries = new EntryRing();
    private final LogTableColumnModel columnModel;
    private final Map<LogEntryField, Class<?>> columnClasses = new EnumMap<>(LogEntryField.class);
    private final List<LogEntry> view = new EntriesView();
    private long nextArrivalNumber;

    public LogTableModel(LogTableController controller, LogTableColumnModel columnModel) {
        this(controller::getMaximumEntries, columnModel);
    }

    /**
     * A model that holds at most {@code maximumEntries} rows, read again on every insertion. It
     * needs no controller, so it can be created without the user interface.
     */
    public LogTableModel(IntSupplier maximumEntries, LogTableColumnModel columnModel) {
        this.maximumEntries = maximumEntries;
        this.columnModel = columnModel;
    }

    @Override
    public synchronized int getRowCount() {
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
        LogEntry logEntry = getRow(rowModelIndex);
        if (this.columnModel.getColumn(columnModelIndex).getIdentifier() == LogEntryField.COMMENT) {
            logEntry.setComment(String.valueOf(value));
        }
        fireTableCellUpdated(rowModelIndex, columnModelIndex);
    }

    /**
     * The class of a column's values, which decides how the table draws and sorts it. It is that of
     * the first row's value and is remembered once known, so that asking does not fetch a value (a
     * whole response body, for the body column) for every cell drawn and every comparison of a
     * sort. An empty text is not remembered: it may only stand for a value that has not arrived.
     */
    @Override
    public Class<?> getColumnClass(int columnModelIndex) {
        LogEntryField field =
                ((LogTableColumn) columnModel.getColumn(columnModelIndex)).getIdentifier();
        Class<?> known = columnClasses.get(field);
        if (known != null) {
            return known;
        }
        Object value = getValueAt(0, columnModelIndex);
        if (value == null) {
            return Object.class;
        }
        if (!"".equals(value)) {
            columnClasses.put(field, value.getClass());
        }
        return value.getClass();
    }

    public void removeLogEntry(LogEntry logEntry) {
        removeLogEntries(List.of(logEntry));
    }

    public synchronized void removeLogEntries(List<LogEntry> removed) {
        for (LogEntry entry : removed) {
            int row = entries.indexOf(entry);
            if (row >= 0) {
                removeEntryAtRow(row);
            }
        }
    }

    public synchronized void removeEntryAtRow(int row) {
        entries.remove(row);
        this.fireTableRowsDeleted(row, row);
    }

    public void addEntry(LogEntry logEntry) {
        addEntries(List.of(logEntry));
    }

    /**
     * Appends entries in the given order, then drops the oldest rows beyond the maximum. The table
     * hears of one insertion and at most one deletion, however many entries there are: it redoes
     * its row bookkeeping per event, so a burst of messages added one by one stalls it.
     */
    public synchronized void addEntries(List<LogEntry> added) {
        if (added.isEmpty()) {
            return;
        }
        int firstNewRow = entries.size();
        for (LogEntry entry : added) {
            entry.setArrivalNumber(nextArrivalNumber++);
            entries.addLast(entry);
        }
        this.fireTableRowsInserted(firstNewRow, entries.size() - 1);

        int excess = entries.size() - maximumEntries.getAsInt();
        if (excess > 0) {
            entries.removeFirst(excess);
            this.fireTableRowsDeleted(0, excess - 1);
        }
    }

    public void updateEntry(LogEntry logEntry) {
        updateEntries(List.of(logEntry));
    }

    /**
     * Tells the table that these entries changed. Entries no longer in the table are ignored, and
     * neighbouring rows are announced together.
     */
    public synchronized void updateEntries(Collection<LogEntry> updated) {
        int[] rows = new int[updated.size()];
        int count = 0;
        for (LogEntry entry : updated) {
            int row = entries.indexOf(entry);
            if (row >= 0) {
                rows[count++] = row;
            }
        }
        Arrays.sort(rows, 0, count);
        int start = 0;
        while (start < count) {
            int end = start;
            while (end + 1 < count && rows[end + 1] <= rows[end] + 1) {
                end++;
            }
            fireTableRowsUpdated(rows[start], rows[end]);
            start = end + 1;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int colModelIndex) {
        LogEntry entry = rowOrNull(rowIndex);
        if (entry == null) {
            return null;
        }

        LogTableColumn column = (LogTableColumn) columnModel.getColumn(colModelIndex);
        if (column.getIdentifier() == LogEntryField.NUMBER) {
            return rowIndex + 1;
        }

        Object value = entry.getValueByKey(column.getIdentifier());

        if (value instanceof Date date) {
            return LogProcessor.LOGGER_DATE_FORMAT.format(date);
        }
        return value;
    }

    /** The rows, oldest first, as a list that follows the table and cannot be changed through. */
    public List<LogEntry> getData() {
        return view;
    }

    public synchronized LogEntry getRow(int row) {
        return entries.get(row);
    }

    private synchronized LogEntry rowOrNull(int row) {
        return row >= 0 && row < entries.size() ? entries.get(row) : null;
    }

    private synchronized LogEntry[] snapshot() {
        return entries.toArray();
    }

    public synchronized void reset() {
        this.entries.clear();
        this.fireTableDataChanged();
    }

    @Override
    public void onColorFilterChange(final TableColorRule filter) {
        boolean retest = filter.isShouldRetest();
        updateInBackground(entry -> entry.testColorFilter(filter, retest));
    }

    @Override
    public void onColorFilterAdd(final TableColorRule filter) {
        if (!filter.isEnabled() || filter.getFilterExpression() == null) return;
        updateInBackground(entry -> entry.testColorFilter(filter, false));
    }

    @Override
    public void onColorFilterRemove(final TableColorRule filter) {
        if (!filter.isEnabled() || filter.getFilterExpression() == null) return;
        updateInBackground(entry -> entry.removeColorFilter(filter.getUuid()));
    }

    @Override
    public void onTagChange(final Tag filter) {
        boolean retest = filter.shouldRetest();
        updateInBackground(entry -> entry.testTag(filter, retest));
    }

    @Override
    public void onTagAdd(final Tag filter) {
        if (!filter.isEnabled() || filter.getFilterExpression() == null) return;
        updateInBackground(entry -> entry.testTag(filter, false));
    }

    @Override
    public void onTagRemove(final Tag filter) {
        if (!filter.isEnabled() || filter.getFilterExpression() == null) return;
        updateInBackground(entry -> entry.removeTag(filter));
    }

    /**
     * Applies a change to every entry on a background thread, and tells the table which rows it
     * altered. It works on a copy of the rows, so entries arriving meanwhile do not disturb it.
     *
     * @param change returns whether the entry's row needs repainting
     */
    private void updateInBackground(Predicate<LogEntry> change) {
        new SwingWorker<Void, LogEntry>() {
            @Override
            protected Void doInBackground() {
                for (LogEntry entry : snapshot()) {
                    if (change.test(entry)) {
                        publish(entry);
                    }
                }
                return null;
            }

            @Override
            protected void process(List<LogEntry> changed) {
                updateEntries(changed);
            }
        }.execute();
    }

    /** The rows as a read-only list, each read going through the model's lock. */
    private final class EntriesView extends AbstractList<LogEntry> implements RandomAccess {
        @Override
        public LogEntry get(int index) {
            return getRow(index);
        }

        @Override
        public int size() {
            return getRowCount();
        }

        @Override
        public Object[] toArray() {
            return snapshot();
        }
    }
}
