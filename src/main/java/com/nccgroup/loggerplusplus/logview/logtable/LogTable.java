package com.nccgroup.loggerplusplus.logview.logtable;

//
// extend JTable to handle cell selection and column move/resize
//

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilterListener;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilter;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilterListener;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.LogEntryListener;
import com.nccgroup.loggerplusplus.logview.MultipleLogEntryMenu;
import com.nccgroup.loggerplusplus.logview.SingleLogEntryMenu;
import com.nccgroup.loggerplusplus.logview.LogTableFilterStatusListener;
import com.nccgroup.loggerplusplus.logview.RequestViewerController;
import com.nccgroup.loggerplusplus.userinterface.LogTableModel;
import com.nccgroup.loggerplusplus.userinterface.renderer.BooleanRenderer;
import com.nccgroup.loggerplusplus.util.Globals;

import javax.swing.*;
import javax.swing.event.RowSorterEvent;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class LogTable extends JTable implements LogFilterListener, ColorFilterListener, LogEntryListener
{

    public LogTable(LogTableModel tableModel, LogTableColumnModel logTableColumnModel)
    {
        super(tableModel, logTableColumnModel);
        this.setTableHeader(new TableHeader(getColumnModel(),this)); // This was used to create tool tips
        this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF); // to have horizontal scroll bar
        this.setRowHeight(20); // As we are not using Burp customised UI, we have to define the row height to make it more pretty
        this.setDefaultRenderer(Boolean.class, new BooleanRenderer()); //Fix grey checkbox background
        ((JComponent) this.getDefaultRenderer(Boolean.class)).setOpaque(true); // to remove the white background of the checkboxes!

        this.setAutoCreateRowSorter(true);
        ((DefaultRowSorter) this.getRowSorter()).setMaxSortKeys(1);
        ((DefaultRowSorter) this.getRowSorter()).setSortsOnUpdates(true);

        this.getRowSorter().addRowSorterListener(rowSorterEvent -> {
            if(rowSorterEvent.getType() != RowSorterEvent.Type.SORT_ORDER_CHANGED) return;
            List<? extends RowSorter.SortKey> sortKeys = LogTable.this.getRowSorter().getSortKeys();
            if(sortKeys == null || sortKeys.size() == 0){
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_ORDER, null);
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_COLUMN, null);
            }else {
                RowSorter.SortKey sortKey = sortKeys.get(0);
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_ORDER, sortKey.getSortOrder());
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_COLUMN, sortKey.getColumn());
            }
        });

        Integer sortColumn = LoggerPlusPlus.preferences.getSetting(Globals.PREF_SORT_COLUMN);
        SortOrder sortOrder = LoggerPlusPlus.preferences.getSetting(Globals.PREF_SORT_ORDER);
        if(sortColumn >= 0 && sortOrder != SortOrder.UNSORTED){
            this.getRowSorter().setSortKeys(Collections.singletonList(new RowSorter.SortKey(sortColumn, sortOrder)));
        }

        this.getSelectionModel().addListSelectionListener(e -> {
            if(e.getValueIsAdjusting()) return;
            RequestViewerController controller = LoggerPlusPlus.instance.getRequestViewerController();
            int selectedRow = getSelectedRow();
            if(selectedRow == -1){
                controller.setDisplayedEntity(null);
            }else {
                // Use a relative instead of an absolute index (This prevents an issue when a filter is set)
                LogEntry logEntry = getModel().getData().get(convertRowIndexToModel(selectedRow));
                if (logEntry.requestResponse != null) {
                    controller.setDisplayedEntity(logEntry.requestResponse);
                }
            }
        });

        this.getSelectionModel().setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        registerListeners();
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return getPreferredSize().width < getParent().getWidth();
    }

    //Sneak in row coloring just before rendering the cell.
    @Override
    public Component prepareRenderer(TableCellRenderer renderer, int row, int column)
    {
        LogEntry entry = null;
        Integer modelRow = null;
        try{
            modelRow = convertRowIndexToModel(row);
            entry = this.getModel().getRow(modelRow);
        }catch (NullPointerException ignored){
            ignored.printStackTrace();
            LoggerPlusPlus.instance.logError("NullPointerException caused by view->model index conversion.");
        }

        if(entry == null){
            return new JLabel("Error, view the logs for info.");
        }

        Component c = super.prepareRenderer(renderer, row, column);

        IntStream selectedRows = IntStream.of(this.getSelectedRows());

        if(selectedRows.anyMatch(i -> i == row)){
            c.setBackground(this.getSelectionBackground());
            c.setForeground(this.getSelectionForeground());
        }else {
            if(entry.getMatchingColorFilters().size() != 0){
                ColorFilter colorFilter = null;
                Map<UUID, ColorFilter> colorFilters = LoggerPlusPlus.preferences.getSetting(Globals.PREF_COLOR_FILTERS);
                for (UUID uid : entry.getMatchingColorFilters()) {
                    if(colorFilter == null || colorFilter.getPriority() > colorFilters.get(uid).getPriority()){
                        colorFilter = colorFilters.get(uid);
                    }
                }
                if (colorFilter == null) {
                    c.setForeground(this.getForeground());
                    c.setBackground(this.getBackground());
                } else {
                    c.setForeground(colorFilter.getForegroundColor());
                    c.setBackground(colorFilter.getBackgroundColor());
                }
            }else{
                c.setForeground(this.getForeground());
                c.setBackground(this.getBackground());
            }
        }
        return c;
    }

    private void registerListeners(){
        this.addMouseListener( new MouseAdapter()
        {
            @Override
            public void mouseClicked(MouseEvent e) {
                onMouseEvent(e);
            }

            @Override
            public void mouseReleased( MouseEvent e ){
                onMouseEvent(e);
            }

            @Override
            public void mousePressed(MouseEvent e) {
                onMouseEvent(e);
            }

            private void onMouseEvent(MouseEvent e){
                if ( SwingUtilities.isRightMouseButton( e )){
                    Point p = e.getPoint();
                    int rowAtPoint = rowAtPoint(p);
                    if(rowAtPoint == -1) return;

                    if(IntStream.of(LogTable.this.getSelectedRows()).noneMatch(i -> i == rowAtPoint)){
                        //We right clicked an unselected row. Set it as the selected row and update our selected
                        setRowSelectionInterval(rowAtPoint, rowAtPoint);
                    }

                    LogTableModel model = LogTable.this.getModel();
                    if(LogTable.this.getSelectedRowCount() == 1){
                        LogEntry logEntry = model.getRow(convertRowIndexToModel(rowAtPoint));
                        LogEntryField logField = LogTable.this.getColumnModel()
                                .getModelColumn(convertColumnIndexToModel(columnAtPoint(p))).getIdentifier();

                        if (e.isPopupTrigger() && e.getComponent() instanceof JTable ) {
                            new SingleLogEntryMenu(LogTable.this, logEntry, logField).show(e.getComponent(), e.getX(), e.getY());
                        }
                    }else{
                        List<LogEntry> selectedEntries = IntStream.of(LogTable.this.getSelectedRows())
                                .mapToObj(selectedRow -> model.getRow(convertRowIndexToModel(selectedRow)))
                                .collect(Collectors.toList());

                        if (e.isPopupTrigger() && e.getComponent() instanceof JTable ) {
                            new MultipleLogEntryMenu(LogTable.this, selectedEntries).show(e.getComponent(), e.getX(), e.getY());
                        }
                    }
                }
            }
        });

        LoggerPlusPlus.instance.getLibraryController().addColorFilterListener(this);
        LoggerPlusPlus.instance.getLogProcessor().addLogListener(this);
    }


    public LogFilter getCurrentFilter(){
        return (LogFilter) ((TableRowSorter) this.getRowSorter()).getRowFilter();
    }

    public void setFilter(LogFilter filter){
        ((DefaultRowSorter) this.getRowSorter()).setRowFilter(filter);
        ((JScrollPane) this.getParent().getParent()).getVerticalScrollBar().setValue(0);
    }

    // to saveFilters the new grepTable changes
    public void saveTableChanges(){
        // saveFilters it to the relevant variables and preferences
        this.getColumnModel().saveLayout();
    }

    @Override
    public LogTableModel getModel(){
        return (LogTableModel) super.getModel();
    }

    @Override
    public LogTableColumnModel getColumnModel(){ return (LogTableColumnModel) super.getColumnModel(); }


    //FilterListeners
    @Override
    public void onFilterChange(final ColorFilter filter) {
        createFilterTestingWorker(filter, filter.shouldRetest()).execute();
    }

    @Override
    public void onFilterAdd(final ColorFilter filter) {
        if(!filter.isEnabled() || filter.getFilter() == null) return;
        createFilterTestingWorker(filter, false);
    }

    @Override
    public void onFilterRemove(final ColorFilter filter) {
        if(!filter.isEnabled() || filter.getFilter() == null) return;
        new SwingWorker<Void, Integer>(){
            @Override
            protected Void doInBackground() throws Exception {
                for (int i = 0; i< getModel().getData().size(); i++) {
                    boolean wasPresent = getModel().getRow(i).matchingColorFilters.remove(filter.getUUID());
                    if(wasPresent){
                        publish(i);
                    }
                }
                return null;
            }

            @Override
            protected void process(List<Integer> rows) {
                for (Integer row : rows) {
                    getModel().fireTableRowsUpdated(row, row);
                }
            }
        }.execute();
    }

    private SwingWorker<Void, Integer> createFilterTestingWorker(final ColorFilter filter, boolean retestExisting){
        return new SwingWorker<Void, Integer>(){

            @Override
            protected Void doInBackground() throws Exception {
                for (int i = 0; i< getModel().getData().size(); i++) {
                    boolean colorResult = getModel().getRow(i).testColorFilter(filter, retestExisting);
                    if(colorResult || filter.isModified()){
                        publish(i);
                    }
                }

                return null;
            }

            @Override
            protected void process(List<Integer> updatedRows) {
                for (Integer row : updatedRows) {
                    getModel().fireTableRowsUpdated(row, row);
                }

            }
        };
    }

    @Override
    public void onFilterRemoveAll() {}

    @Override
    public synchronized void onRequestAdded(int modelIndex, LogEntry logEntry, boolean hasResponse) {
        try {
            getModel().fireTableRowsInserted(modelIndex, modelIndex);

            if (LoggerPlusPlus.preferences.getSetting(Globals.PREF_AUTO_SCROLL)) {
                JScrollBar scrollBar = LoggerPlusPlus.instance.getLogScrollPanel().getVerticalScrollBar();
                scrollBar.setValue(scrollBar.getMaximum() + 100);
            }
        }catch (Exception e){
            e.printStackTrace();
            System.out.println(modelIndex);
            System.out.println(logEntry);
            //TODO Fix out of bounds exception here.
        }
    }

    @Override
    public void onResponseUpdated(int modelRow, LogEntry existingEntry) {
        getModel().fireTableRowsUpdated(modelRow, modelRow);
    }

    @Override
    public void onRequestRemoved(int modelIndex, LogEntry logEntry) {
        try {
            getModel().fireTableRowsDeleted(modelIndex, modelIndex);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    @Override
    public void onLogsCleared() {
        getModel().fireTableDataChanged();
    }

    @Override
    public void onFilterSet(LogFilter filter) {
        this.setFilter(filter);
    }

    @Override
    public void onFilterError(String invalidFilter, ParseException exception) {
        this.setFilter(null);
    }

    @Override
    public void onFilterCleared() {
        this.setFilter(null);
    }
}