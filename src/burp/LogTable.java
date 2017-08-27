package burp;

//
// extend JTable to handle cell selection and column move/resize
//

import burp.filter.ColorFilter;
import burp.filter.Filter;
import burp.filter.FilterListener;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.UIResource;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

public class LogTable extends JTable implements FilterListener
{

    public LogTable(List<LogEntry> data)
    {
        super(new LogTableModel(data), new LogTableColumnModel());
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
            BurpExtender.getInstance().getCallbacks().printError("Failed to create table from stored preferences. Table structure has been reset.");
            rowSorter.setModel(this.getModel());
        }
        setRowSorter(rowSorter);

        Integer sortColumn = BurpExtender.getInstance().getLoggerPreferences().getSortColumn();
        SortOrder sortOrder = BurpExtender.getInstance().getLoggerPreferences().getSortOrder();
        if(sortColumn != -1 && sortOrder != null){
            this.getRowSorter().setSortKeys(Collections.singletonList(new RowSorter.SortKey(sortColumn, sortOrder)));
        }

        registerListeners();
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
                Map<UUID, ColorFilter> colorFilters = BurpExtender.getInstance().getLoggerPreferences().getColorFilters();
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

        BurpExtender.getInstance().addFilterListener(this);
    }


    Filter getCurrentFilter(){
        return (Filter) ((TableRowSorter) this.getRowSorter()).getRowFilter();
    }

    public void setFilter(Filter filter){
        ((TableRowSorter) this.getRowSorter()).setRowFilter(filter);
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend)
    {
        // show the log entry for the selected row
        if(this.getModel().getData().size()>=row){
            LogEntry logEntry = this.getModel().getData().get(this.convertRowIndexToModel(row));
            if(logEntry.requestResponse != null) {
                    if(logEntry.requestResponse.getRequest() != null)
                        BurpExtender.getInstance().getRequestViewer().setMessage(logEntry.requestResponse.getRequest(), true);
                    if (logEntry.requestResponse.getResponse() != null)
                        BurpExtender.getInstance().getResponseViewer().setMessage(logEntry.requestResponse.getResponse(), false);
                    else
                        BurpExtender.getInstance().getResponseViewer().setMessage(new byte[0], false);
                this.getModel().setCurrentlyDisplayedItem(logEntry.requestResponse);
            }
            super.changeSelection(row, col, toggle, extend);
        }
    }

    // to save the new table changes
    public void saveTableChanges(){
        // save it to the relevant variables and preferences
        this.getColumnModel().saveColumnJSON();
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
        Thread onRemoveThread = new Thread(new Runnable(){
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


    static class LeftTableCellRenderer extends DefaultTableCellRenderer {
        protected  LeftTableCellRenderer() {
            setHorizontalAlignment(SwingConstants.LEFT);
        }
    }

    //Recreate boolean renderer to fix checkbox bug
    static class BooleanRenderer extends JCheckBox implements TableCellRenderer, UIResource {
        private static final Border noFocusBorder = new EmptyBorder(1, 1, 1, 1);

        public BooleanRenderer() {
            this.setHorizontalAlignment(0);
            this.setBorderPainted(true);
            this.setOpaque(true);
        }

        public Component getTableCellRendererComponent(JTable var1, Object var2, boolean var3, boolean var4, int var5, int var6) {
            if(var3) {
                this.setForeground(var1.getSelectionForeground());
                super.setBackground(var1.getSelectionBackground());
            } else {
                this.setForeground(var1.getForeground());
                this.setBackground(var1.getBackground());
            }

            this.setSelected(var2 != null && ((Boolean)var2).booleanValue());
            if(var4) {
                this.setBorder(UIManager.getBorder("LogTable.focusCellHighlightBorder"));
            } else {
                this.setBorder(noFocusBorder);
            }

            return this;
        }
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
            //Temporary fix is to let the table update the row again, such as on redraw.
            try {
                return super.convertRowIndexToModel(index);
            }catch (NullPointerException e){
                return this.getViewRowCount()-1;
            }
        }

        @Override
        public void setSortKeys(List list) {
            super.setSortKeys(list);
            SortKey sortKey = (SortKey) list.get(0);
            BurpExtender.getInstance().getLoggerPreferences().setSortColumn(sortKey.getColumn());
            BurpExtender.getInstance().getLoggerPreferences().setSortOrder(sortKey.getSortOrder());
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