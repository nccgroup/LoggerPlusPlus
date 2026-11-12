package com.nccgroup.loggerplusplus.logview.processor;

import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableModel;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;

/**
 * Carries entries from the worker threads to the log table, which may only change on the event
 * dispatch thread.
 *
 * <p>Changes are handed over in batches: one task on the event thread applies everything that has
 * accumulated since the last one. Under load the batches grow instead of the event queue, so the
 * table does its bookkeeping once per batch and the user interface stays responsive; when idle, an
 * entry still reaches the table at once.
 */
final class TableFeed {
    private enum Kind {
        ADDED,
        UPDATED,
        REMOVED
    }

    private record Change(Kind kind, LogEntry entry) {}

    private final LogTableModel table;
    private final Executor eventThread;
    private final Object lock = new Object();
    private List<Change> pending = new ArrayList<>();
    private boolean deliveryScheduled;

    /**
     * @param eventThread runs a task on the event dispatch thread, later
     */
    TableFeed(LogTableModel table, Executor eventThread) {
        this.table = table;
        this.eventThread = eventThread;
    }

    void added(LogEntry entry) {
        hand(new Change(Kind.ADDED, entry));
    }

    void updated(LogEntry entry) {
        hand(new Change(Kind.UPDATED, entry));
    }

    void removed(LogEntry entry) {
        hand(new Change(Kind.REMOVED, entry));
    }

    private void hand(Change change) {
        boolean schedule;
        synchronized (lock) {
            pending.add(change);
            schedule = !deliveryScheduled;
            deliveryScheduled = true;
        }
        if (schedule) {
            eventThread.execute(this::deliver);
        }
    }

    /** On the event thread: applies, in order, every change handed over so far. */
    private void deliver() {
        List<Change> batch;
        synchronized (lock) {
            batch = pending;
            pending = new ArrayList<>();
            deliveryScheduled = false;
        }

        List<LogEntry> added = new ArrayList<>();
        Set<LogEntry> updated = new LinkedHashSet<>();
        for (Change change : batch) {
            switch (change.kind()) {
                case ADDED -> added.add(change.entry());
                case UPDATED -> updated.add(change.entry());
                case REMOVED -> {
                    // A removal follows the addition of its entry, which must therefore be applied
                    // first.
                    table.addEntries(added);
                    added.clear();
                    table.removeLogEntry(change.entry());
                }
            }
        }
        table.addEntries(added);
        // Last, so that every updated row exists; an entry removed meanwhile is ignored by the
        // table.
        table.updateEntries(updated);
    }
}
