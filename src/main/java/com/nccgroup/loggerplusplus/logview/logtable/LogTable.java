package com.nccgroup.loggerplusplus.logview.logtable;

//
// extend JTable to handle cell selection and column move/resize
//

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logview.MultipleLogEntryMenu;
import com.nccgroup.loggerplusplus.logview.SingleLogEntryMenu;
import com.nccgroup.loggerplusplus.logview.entryviewer.RequestViewerController;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.BooleanRenderer;

import javax.swing.*;
import javax.swing.event.RowSorterEvent;
import javax.swing.event.TableModelEvent;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class LogTable extends JTable
{
    private final LogTableController controller;
    private final Preferences preferences;
    private final TableRowSorter<LogTableModel> sorter;

    LogTable(LogTableController controller)
    {
        super(controller.getLogTableModel(), controller.getLogTableColumnModel());
        this.controller = controller;
        this.preferences = controller.getPreferences();

        this.setTableHeader(controller.getTableHeader()); // This was used to create tool tips
        this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF); // to have horizontal scroll bar
        this.setRowHeight(20); // As we are not using Burp customised UI, we have to define the row height to make it more pretty
        this.setDefaultRenderer(Boolean.class, new BooleanRenderer()); //Fix grey checkbox background
        ((JComponent) this.getDefaultRenderer(Boolean.class)).setOpaque(true); // to remove the white background of the checkboxes!

        this.sorter = new TableRowSorter<>(this.getModel());
        this.sorter.setMaxSortKeys(1);
        this.sorter.setSortsOnUpdates(true);
        this.setRowSorter(this.sorter);

        this.sorter.addRowSorterListener(rowSorterEvent -> {
            if(rowSorterEvent.getType() != RowSorterEvent.Type.SORT_ORDER_CHANGED) return;
            List<? extends RowSorter.SortKey> sortKeys = LogTable.this.sorter.getSortKeys();
            if(sortKeys == null || sortKeys.size() == 0){
                this.preferences.setSetting(Globals.PREF_SORT_ORDER, null);
                this.preferences.setSetting(Globals.PREF_SORT_COLUMN, null);
            }else {
                RowSorter.SortKey sortKey = sortKeys.get(0);
                this.preferences.setSetting(Globals.PREF_SORT_ORDER, sortKey.getSortOrder());
                this.preferences.setSetting(Globals.PREF_SORT_COLUMN, sortKey.getColumn());
            }
        });

        Integer sortColumn = this.preferences.getSetting(Globals.PREF_SORT_COLUMN);
        SortOrder sortOrder = this.preferences.getSetting(Globals.PREF_SORT_ORDER);
        if(sortColumn >= 0 && sortOrder != SortOrder.UNSORTED){
            try {
                this.sorter.setSortKeys(Collections.singletonList(new RowSorter.SortKey(sortColumn, sortOrder)));
            }catch (IllegalArgumentException exception){
                //If we can't set the sort key because its invalid, just ignore it.
            }
        }

        this.getSelectionModel().addListSelectionListener(e -> {
            if(e.getValueIsAdjusting()) return;
            RequestViewerController requestViewerController = LogTable.this.controller.getLogViewController().getRequestViewerController();
            int selectedRow = getSelectedRow();
            if(selectedRow == -1){
                requestViewerController.setDisplayedEntity(null);
            }else {
                // Use a relative instead of an absolute index (This prevents an issue when a filter is set)
                LogEntry logEntry = getModel().getData().get(convertRowIndexToModel(selectedRow));
                if (logEntry != null) {
                    requestViewerController.setDisplayedEntity(logEntry);
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
        try {
            modelRow = convertRowIndexToModel(row);
            entry = this.getModel().getRow(modelRow);
        } catch (NullPointerException ignored) {
            ignored.printStackTrace();
        }

        Component c = super.prepareRenderer(renderer, row, column);

        IntStream selectedRows = IntStream.of(this.getSelectedRows());

        if(selectedRows.anyMatch(i -> i == row)){
            c.setBackground(this.getSelectionBackground());
            c.setForeground(this.getSelectionForeground());
        }else {
            if(entry == null){
                System.err.println("Could not convert row index to model. Table entry might not be highlighted properly.");
                return c;
            }
            if(entry.getMatchingColorFilters().size() != 0){
                TableColorRule tableColorRule = null;
                Map<UUID, TableColorRule> colorFilters = this.preferences.getSetting(Globals.PREF_COLOR_FILTERS);
                for (UUID uid : entry.getMatchingColorFilters()) {
                    if(tableColorRule == null || tableColorRule.getPriority() > colorFilters.get(uid).getPriority()){
                        tableColorRule = colorFilters.get(uid);
                    }
                }
                if (tableColorRule == null) {
                    c.setForeground(this.getForeground());
                    c.setBackground(this.getBackground());
                } else {
                    c.setForeground(tableColorRule.getForegroundColor());
                    c.setBackground(tableColorRule.getBackgroundColor());
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
                        LogEntryField logField = (LogEntryField) LogTable.this.getColumnModel()
                                .getColumn(columnAtPoint(p)).getIdentifier();

                        if (e.isPopupTrigger() && e.getComponent() instanceof JTable ) {
                            new SingleLogEntryMenu(controller, logEntry, logField).show(e.getComponent(), e.getX(), e.getY());
                        }
                    }else{
                        List<LogEntry> selectedEntries = IntStream.of(LogTable.this.getSelectedRows())
                                .mapToObj(selectedRow -> model.getRow(convertRowIndexToModel(selectedRow)))
                                .collect(Collectors.toList());

                        if (e.isPopupTrigger() && e.getComponent() instanceof JTable ) {
                            new MultipleLogEntryMenu(controller, selectedEntries).show(e.getComponent(), e.getX(), e.getY());
                        }
                    }
                }
            }
        });

        getModel().addTableModelListener(tableModelEvent -> {
            if(tableModelEvent.getType() == TableModelEvent.INSERT && (boolean) preferences.getSetting(Globals.PREF_AUTO_SCROLL)){
                LogTable.this.scrollRectToVisible(getCellRect(tableModelEvent.getFirstRow(), tableModelEvent.getColumn(), true));
            }
        });
    }


    public LogTableFilter getCurrentFilter(){
        return (LogTableFilter) this.sorter.getRowFilter();
    }

    public void setFilter(LogTableFilter filter){
        this.sorter.setRowFilter(filter);
        ((JScrollPane) this.getParent().getParent()).getVerticalScrollBar().setValue(0);
    }

    @Override
    public LogTableModel getModel(){
        return (LogTableModel) super.getModel();
    }

    @Override
    public LogTableColumnModel getColumnModel(){ return (LogTableColumnModel) super.getColumnModel(); }
}