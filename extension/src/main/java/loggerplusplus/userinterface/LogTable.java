package loggerplusplus.userinterface;

//
// extend JTable to handle cell selection and column move/resize
//

import loggerplusplus.Globals;
import loggerplusplus.LogEntry;
import loggerplusplus.LogEntryListener;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.filter.Filter;
import loggerplusplus.filter.FilterListener;
import loggerplusplus.userinterface.renderer.BooleanRenderer;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.table.TableStringConverter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class LogTable extends JTable implements FilterListener, LogEntryListener
{

    public LogTable(LogTableModel tableModel)
    {
        super(tableModel, new LogTableColumnModel());
        this.getModel().setColumnModel(this.getColumnModel());
        this.setTableHeader(new TableHeader (getColumnModel(),this)); // This was used to create tool tips
        this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF); // to have horizontal scroll bar
        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION); // selecting one row at a time
        this.setRowHeight(20); // As we are not using Burp customised UI, we have to define the row height to make it more pretty
        this.setDefaultRenderer(Boolean.class, new BooleanRenderer()); //Fix grey checkbox background
        ((JComponent) this.getDefaultRenderer(Boolean.class)).setOpaque(true); // to remove the white background of the checkboxes!


        TableRowSorter rowSorter = new LogTableRowSorter();
        try {
            rowSorter.setModel(this.getModel());
        }catch (NullPointerException nPException){
            getColumnModel().resetToDefaultVariables();
            LoggerPlusPlus.callbacks.printError("Failed to create grepTable from stored preferences. Table structure has been reset.");
            rowSorter.setModel(this.getModel());
        }
        setRowSorter(rowSorter);

        Integer sortColumn = (Integer) LoggerPlusPlus.preferences.getSetting(Globals.PREF_SORT_COLUMN);
        SortOrder sortOrder;
        try{
            sortOrder = SortOrder.valueOf((String) LoggerPlusPlus.preferences.getSetting(Globals.PREF_SORT_ORDER));
        }catch(Exception e){
            sortOrder = SortOrder.ASCENDING;
        }
        if(sortColumn != -1 && sortOrder != null){
            this.getRowSorter().setSortKeys(Collections.singletonList(new RowSorter.SortKey(sortColumn, sortOrder)));
        }

        DefaultListSelectionModel model = new DefaultListSelectionModel(){
            @Override
            public void addSelectionInterval(int start, int end) {
                super.addSelectionInterval(start, end);
                LogEntry logEntry = getModel().getData().get(convertRowIndexToModel(start));
                if (logEntry.requestResponse != null && !getModel().getCurrentlyDisplayedItem().equals(logEntry.requestResponse)) {
                    if (logEntry.requestResponse.getRequest() != null)
                        LoggerPlusPlus.instance.getRequestViewer().setMessage(logEntry.requestResponse.getRequest(), true);
                    if (logEntry.requestResponse.getResponse() != null)
                        LoggerPlusPlus.instance.getResponseViewer().setMessage(logEntry.requestResponse.getResponse(), false);
                    else
                        LoggerPlusPlus.instance.getResponseViewer().setMessage(new byte[0], false);
                    getModel().setCurrentlyDisplayedItem(logEntry.requestResponse);
                }
            }
        };

        this.setSelectionModel(model);
        LoggerPlusPlus.instance.getLogManager().addLogListener(this);
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
        Component c = super.prepareRenderer(renderer, row, column);
        LogEntry entry = this.getModel().getRow(convertRowIndexToModel(row));

        if(this.getSelectedRow() == row){
            c.setBackground(this.getSelectionBackground());
            c.setForeground(this.getSelectionForeground());
        }else {
            if(entry.getMatchingColorFilters().size() != 0){
                ColorFilter colorFilter = null;
                Map<UUID, ColorFilter> colorFilters = (Map<UUID, ColorFilter>) LoggerPlusPlus.preferences.getSetting(Globals.PREF_COLOR_FILTERS);
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

    @Override
    public int convertColumnIndexToView(int i) {
        return this.getColumnModel().getColumnViewLocation(i);
    }

    private void registerListeners(){
        final LogTable _this = this;
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
                    final int row = convertRowIndexToModel(rowAtPoint(p));
                    final int col = convertColumnIndexToModel(columnAtPoint(p));
                    if (e.isPopupTrigger() && e.getComponent() instanceof JTable ) {
                        getSelectionModel().setSelectionInterval(row, row);
                        new LogEntryMenu(_this, row, col).show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            }
        });

        LoggerPlusPlus.instance.addFilterListener(this);
    }


    public Filter getCurrentFilter(){
        return (Filter) ((TableRowSorter) this.getRowSorter()).getRowFilter();
    }

    public void setFilter(Filter filter){
        try {
            ((TableRowSorter) this.getRowSorter()).setRowFilter(filter);
        }catch (NullPointerException ignored){}
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend)
    {
        // show the log entry for the selected row
        if(this.getModel().getData().size()>=row){
            LogEntry logEntry = this.getModel().getData().get(this.convertRowIndexToModel(row));
            if(logEntry.requestResponse != null) {
                    if(logEntry.requestResponse.getRequest() != null)
                        LoggerPlusPlus.instance.getRequestViewer().setMessage(logEntry.requestResponse.getRequest(), true);
                    if (logEntry.requestResponse.getResponse() != null)
                        LoggerPlusPlus.instance.getResponseViewer().setMessage(logEntry.requestResponse.getResponse(), false);
                    else
                        LoggerPlusPlus.instance.getResponseViewer().setMessage(new byte[0], false);
                this.getModel().setCurrentlyDisplayedItem(logEntry.requestResponse);
            }
            super.changeSelection(row, col, toggle, extend);
        }
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
                        getModel().fireTableRowsUpdated(i, i);
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
                    if(colorResult) getModel().fireTableRowsUpdated(i, i);
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
                    if(wasPresent) getModel().fireTableRowsUpdated(i, i);
                }
            }
        });
        onRemoveThread.start();
    }

    @Override
    public void onFilterRemoveAll() {}

    @Override
    public void onRequestAdded(LogEntry logEntry, boolean hasResponse) {
//        int rowNo = LoggerPlusPlus.instance.getLogManager().getLogEntries().size()-1;
//        getModel().fireTableRowsInserted(rowNo, rowNo);
        getModel().fireTableDataChanged();

        if((boolean) LoggerPlusPlus.preferences.getSetting(Globals.PREF_AUTO_SCROLL)) {
            JScrollBar scrollBar = LoggerPlusPlus.instance.getLogScrollPanel().getVerticalScrollBar();
            scrollBar.setValue(scrollBar.getMaximum());
        }
    }

    @Override
    public void onResponseUpdated(LogEntry existingEntry) {
        //Calculate adjusted row in case it's moved. Update 10 either side to account for deleted rows
//        if(!(existingEntry instanceof LogEntry.PendingRequestEntry)){
//            return;
//        }
//        int row = ((LogEntry.PendingRequestEntry) existingEntry).getLogRow();
//        if(row == -1) return;
//        LogManager logManager = LoggerPlusPlus.instance.getLogManager();
//        if(logManager.getLogEntries().size() == logManager.getMaximumEntries()) {
//            int newRow = ((LogEntry.PendingRequestEntry) existingEntry).getLogRow() - logManager.getMaximumEntries() - logManager.getTotalRequests();
//            getModel().fireTableRowsUpdated(newRow - 10, Math.min(logManager.getMaximumEntries(), newRow + 10));
//        }else{
//            getModel().fireTableRowsUpdated(row, row);
//        }
        getModel().fireTableDataChanged();
    }

    @Override
    public void onRequestRemoved(int index, LogEntry logEntry) {
//        getModel().fireTableRowsDeleted(index, index);
        getModel().fireTableDataChanged();
    }

    //Custom sorter to fix issues with columnModel having different model column and view column counts.
    class LogTableRowSorter extends TableRowSorter {
        public TableModel tableModel;

        @Override
        public void setModel(TableModel model) {
            this.tableModel = model;
            super.setModel(model);
            this.setModelWrapper(new TableRowSorterModelWrapper());
            this.setMaxSortKeys(1);
        }

        @Override
        public int convertRowIndexToModel(int index) {
            //On occasion, for reasons unknown the conversion will cause a null pointer.
            //The exact same line with identical parameters will often work if run again
            //Temporary fix is to let the grepTable update the row again, such as on redraw.
            try {
                return super.convertRowIndexToModel(index);
            }catch (NullPointerException | IndexOutOfBoundsException e){
                return this.getViewRowCount()-1;
            }
        }

        @Override
        public void setSortKeys(List list) {
            super.setSortKeys(list);
            if(list == null){
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_ORDER, null);
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_COLUMN, null);
            }else {
                SortKey sortKey = (SortKey) list.get(0);
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_ORDER, String.valueOf(sortKey.getSortOrder()));
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_SORT_COLUMN, sortKey.getColumn());
            }
        }

        private class TableRowSorterModelWrapper extends ModelWrapper<LogTableModel, Integer> {
            private TableRowSorterModelWrapper() {
            }

            public LogTableModel getModel() {
                return (LogTableModel) LogTableRowSorter.this.tableModel;
            }

            public int getColumnCount() {
                return LogTableRowSorter.this.tableModel == null?0:((LogTableModel)LogTableRowSorter.this.tableModel).getModelColumnCount();
            }

            public int getRowCount() {
                return LogTableRowSorter.this.tableModel == null?0:LogTableRowSorter.this.tableModel.getRowCount();
            }

            public Object getValueAt(int row, int column) {
                return LogTableRowSorter.this.tableModel.getValueAt(row, column);
            }

            public String getStringValueAt(int row, int column) {
                TableStringConverter converter = LogTableRowSorter.this.getStringConverter();
                if(converter != null) {
                    String value = converter.toString(LogTableRowSorter.this.tableModel, row, column);
                    return value != null?value:"";
                } else {
                    Object o = this.getValueAt(row, column);
                    if(o == null) {
                        return "";
                    } else {
                        String string = o.toString();
                        return string == null?"":string;
                    }
                }
            }

            public Integer getIdentifier(int index) {
                return Integer.valueOf(index);
            }
        }
        
    }
}