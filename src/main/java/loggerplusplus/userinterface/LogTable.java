package loggerplusplus.userinterface;

//
// extend JTable to handle cell selection and column move/resize
//

import loggerplusplus.*;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.filter.ColorFilterListener;
import loggerplusplus.filter.LogFilter;
import loggerplusplus.filter.parser.ParseException;
import loggerplusplus.userinterface.renderer.BooleanRenderer;

import javax.swing.*;
import javax.swing.event.RowSorterEvent;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class LogTable extends JTable implements FilterListener, ColorFilterListener, LogEntryListener
{

    public LogTable(LogTableModel tableModel, LogTableColumnModel logTableColumnModel)
    {
        super(tableModel, logTableColumnModel);
        this.setTableHeader(new TableHeader (getColumnModel(),this)); // This was used to create tool tips
        this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF); // to have horizontal scroll bar
        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION); // selecting one row at a time
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
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_ORDER, String.valueOf(sortKey.getSortOrder()));
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_COLUMN, sortKey.getColumn());
            }
        });

        Integer sortColumn = LoggerPlusPlus.preferences.getSetting(Globals.PREF_SORT_COLUMN);
        SortOrder sortOrder;
        try{
            sortOrder = SortOrder.valueOf(LoggerPlusPlus.preferences.getSetting(Globals.PREF_SORT_ORDER));
        }catch(Exception e){
            sortOrder = SortOrder.ASCENDING;
        }
        if(sortColumn > 0){ //TODO Fix bug with renderer throwing null pointer when
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
        this.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

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
            //The NPE here should hopefully be fixed. Log anyway just in case...
            LoggerPlusPlus.instance.logError("NullPointerException caused by view->model index conversion.");
        }

        if(entry == null){
            return new JLabel("Error, view the logs for info.");
        }

        Component c = super.prepareRenderer(renderer, row, column);

        if(this.getSelectedRow() == row){
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
                    if(rowAtPoint > -1){
                        setRowSelectionInterval(rowAtPoint, rowAtPoint);
                    }

                    final int row = convertRowIndexToModel(rowAtPoint);
                    final int modelCol = convertColumnIndexToModel(columnAtPoint(p));

                    if (e.isPopupTrigger() && e.getComponent() instanceof JTable ) {
                        new LogEntryMenu(LogTable.this, row, modelCol).show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            }
        });

        LoggerPlusPlus.instance.addFilterListener(this);
        LoggerPlusPlus.instance.getLogManager().addLogListener(this);
    }


    public LogFilter getCurrentFilter(){
        return (LogFilter) ((TableRowSorter) this.getRowSorter()).getRowFilter();
    }

    public void setFilter(LogFilter filter){
        ((DefaultRowSorter) this.getRowSorter()).setRowFilter(filter);
        this.getRowSorter().allRowsChanged();
    }

    // to save the new grepTable changes
    public void saveTableChanges(){
        // save it to the relevant variables and preferences
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
        Thread onChangeThread = new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i< getModel().getData().size(); i++) {
                    boolean colorResult = getModel().getRow(i).testColorFilter(filter, filter.shouldRetest());
                    if(colorResult || filter.isModified()){
                        int finalI = i;
                        SwingUtilities.invokeLater(() -> {
                            getModel().fireTableRowsUpdated(finalI, finalI);
                        });
                    }
                }
            }
        });
        onChangeThread.start();
    }

    @Override
    public void onFilterAdd(final ColorFilter filter) {
        if(!filter.isEnabled() || filter.getFilter() == null) return;
        Thread onAddThread = new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i< getModel().getData().size(); i++) {
                    boolean colorResult = getModel().getRow(i).testColorFilter(filter, false);
                    int finalI = i;
                    SwingUtilities.invokeLater(() -> {
                        if(colorResult) getModel().fireTableRowsUpdated(finalI, finalI);
                    });
                }
            }
        });
        onAddThread.start();
    }

    @Override
    public void onFilterRemove(final ColorFilter filter) {
        if(!filter.isEnabled() || filter.getFilter() == null) return;
        Thread onRemoveThread = new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i< getModel().getData().size(); i++) {
                    boolean wasPresent = getModel().getRow(i).matchingColorFilters.remove(filter.getUid());
                    int finalI = i;
                    SwingUtilities.invokeLater(() -> {
                        if(wasPresent) getModel().fireTableRowsUpdated(finalI, finalI);
                    });
                }
            }
        });
        onRemoveThread.start();
    }

    @Override
    public void onFilterRemoveAll() {}

    @Override
    public void onRequestAdded(int modelIndex, LogEntry logEntry, boolean hasResponse) {
        try {
            SwingUtilities.invokeLater(() -> {
                getModel().fireTableRowsInserted(modelIndex, modelIndex);

                if(LoggerPlusPlus.preferences.getSetting(Globals.PREF_AUTO_SCROLL)) {
                    JScrollBar scrollBar = LoggerPlusPlus.instance.getLogScrollPanel().getVerticalScrollBar();
                    scrollBar.setValue(scrollBar.getMaximum()+50);
                }
            });
        }catch (Exception e){
            //TODO Fix out of bounds exception here.
        }
    }

    @Override
    public void onResponseUpdated(int modelRow, LogEntry existingEntry) {
        SwingUtilities.invokeLater(() -> getModel().fireTableRowsUpdated(modelRow, modelRow));
    }

    @Override
    public void onRequestRemoved(int index, LogEntry logEntry) {
        SwingUtilities.invokeLater(() -> getModel().fireTableRowsDeleted(index, index));
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