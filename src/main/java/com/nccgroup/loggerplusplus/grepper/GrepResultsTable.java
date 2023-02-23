package com.nccgroup.loggerplusplus.grepper;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import org.jdesktop.swingx.JXTree;
import org.jdesktop.swingx.JXTreeTable;
import org.jdesktop.swingx.tree.DefaultXTreeCellRenderer;
import org.jdesktop.swingx.treetable.AbstractTreeTableModel;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.tree.TreePath;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.regex.Pattern;

public class GrepResultsTable extends JXTreeTable implements GrepperListener {

    private final GrepperController controller;
    private final GrepTableModel tableModel;

    public GrepResultsTable(GrepperController controller){
        super();
        this.controller = controller;
        this.tableModel = new GrepTableModel();

        this.setTreeTableModel(this.tableModel);

        this.setAutoCreateRowSorter(true);
        this.setColumnSelectionAllowed(true);

        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if(SwingUtilities.isRightMouseButton(e)) {
                    JPopupMenu menu = new JPopupMenu();
                    int row = rowAtPoint(e.getPoint());
                    TreePath path = getPathForRow(row);
                    if(path == null) return;
                    Object obj = path.getLastPathComponent();
                    if (obj instanceof GrepResults) {
                        obj = ((GrepResults) obj).getLogEntry();
                    } else if (obj instanceof GrepResults.Match) {
                        obj = ((GrepResults) path.getPathComponent(path.getPathCount() - 2)).getLogEntry();
                    }
                    final int index = controller.getLogTableController()
                                                    .getLogTable().getModel().getData().indexOf(obj);
                    JMenuItem viewInLogs = new JMenuItem(new AbstractAction("View in Logs") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            LogTable table = controller.getLogTableController().getLogTable();
                            table.changeSelection(table.convertRowIndexToView(index), 1, false, false);
                            LoggerPlusPlus.instance.getMainViewController().getTabbedPanel().setSelectedIndex(0);
                        }
                    });
                    menu.add(viewInLogs);
                    if(controller.getLogTableController().getLogTable().convertRowIndexToView(index) == -1){
                        viewInLogs.setEnabled(false);
                        viewInLogs.setToolTipText("Unavailable. Hidden by filter.");
                        viewInLogs.addMouseListener(new MouseAdapter() {
                            final int defaultTimeout = ToolTipManager.sharedInstance().getInitialDelay();
                            @Override
                            public void mouseEntered(MouseEvent e) {
                                ToolTipManager.sharedInstance().setInitialDelay(0);
                            }

                            @Override
                            public void mouseExited(MouseEvent e) {
                                ToolTipManager.sharedInstance().setInitialDelay(defaultTimeout);
                            }
                        });
                    }
                    menu.show(GrepResultsTable.this, e.getX(), e.getY());
                }
                super.mouseReleased(e);
            }
        });

        this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        DefaultXTreeCellRenderer renderer = ((DefaultXTreeCellRenderer) ((JXTree.DelegatingRenderer) this.getTreeCellRenderer()).getDelegateRenderer());
        renderer.setBackground(null);
        renderer.setOpaque(true);

        this.controller.addListener(this);
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return getPreferredSize().width < getParent().getWidth();
    }

    @Override
    public void onSearchStarted(Pattern pattern, int searchEntries) {
        tableModel.reset();
        tableModel.setPatternGroups(pattern.matcher("").groupCount());
    }

    @Override
    public void onEntryProcessed(GrepResults entryResults) {
        if(entryResults != null) tableModel.addEntry(entryResults);
    }

    @Override
    public void onSearchComplete() {
        tableModel.reload();
    }

    @Override
    public void onResetRequested() {
        tableModel.reset();
    }

    @Override
    public void onShutdownInitiated() {

    }

    @Override
    public void onShutdownComplete() {
        tableModel.reload();
    }


    class GrepTableModel extends AbstractTreeTableModel {
        private String[] columns = new String[]{"Entry", "Request Matches", "Response Matches", "Total Matches", "Complete Match"};
        private final ArrayList<GrepResults> matchingEntries;
        private int patternGroups = 0;

        GrepTableModel(){
            super(new Object());
            this.matchingEntries = new ArrayList<>();
        }

        public void setPatternGroups(int count){
            this.patternGroups = count;
            ((AbstractTableModel) GrepResultsTable.this.getModel()).fireTableStructureChanged();
        }

        public void addEntry(GrepResults matches){
            if (matches.getMatches().size() == 0) return;
            synchronized (this.matchingEntries) {
                this.matchingEntries.add(matches);
            }
        }

        public void reload(){
            synchronized (matchingEntries) {
                modelSupport.fireNewRoot();
            }
        }

        @Override
        public int getColumnCount() {
            return columns.length + patternGroups;
        }

        @Override
        public String getColumnName(int column) {
            if(column < columns.length) return columns[column];
            else return "Group " + (column-columns.length+1);
        }

        @Override
        public boolean isLeaf(Object node) {
            return node instanceof GrepResults.Match;
        }

        @Override
        public Object getValueAt(Object node, int column) {
            if(node instanceof GrepResults) {
                if (column == 0) return ((GrepResults) node).getLogEntry().toString();
                if (column == 1) return ((GrepResults) node).getRequestMatches();
                if (column == 2) return ((GrepResults) node).getResponseMatches();
                if (column == 3) return ((GrepResults) node).getMatches().size();
                else return "";
            }
            if(node instanceof GrepResults.Match){
                if(column == 0) return ((GrepResults.Match) node).isRequest ? "REQUEST" : "RESPONSE";
                if(column >= 1 && column <= 3) return null;
                return ((GrepResults.Match) node).groups[column-4];
            }
            return "";
        }

        @Override
        public Object getChild(Object parent, int i) {
            if(parent instanceof GrepResults)
                return ((GrepResults) parent).getMatches().get(i);
            if(this.matchingEntries == null) return null;
            return this.matchingEntries.get(i);
        }

        @Override
        public int getChildCount(Object parent) {
            if(parent instanceof GrepResults){
                return ((GrepResults) parent).getMatches().size();
            }
            synchronized (matchingEntries) {
                return this.matchingEntries.size();
            }
        }

        @Override
        public int getIndexOfChild(Object parent, Object child) {
            if(parent instanceof GrepResults){
                return ((GrepResults) parent).getMatches().indexOf(child);
            }
            return -1;
        }

        public void reset() {
            synchronized (matchingEntries) {
                matchingEntries.clear();
            }
            SwingUtilities.invokeLater(() -> {
                modelSupport.fireNewRoot();
            });
        }
    }

}
