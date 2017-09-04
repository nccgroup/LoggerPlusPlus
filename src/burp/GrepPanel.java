package burp;

import org.jdesktop.swingx.JXTree;
import org.jdesktop.swingx.JXTreeTable;
import org.jdesktop.swingx.tree.DefaultXTreeCellRenderer;
import org.jdesktop.swingx.treetable.AbstractTreeTableModel;

import javax.swing.*;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Created by corey on 29/08/17.
 */

public class GrepPanel extends JPanel{
    ArrayList<LogEntryMatches> matchingEntries;
    Map<String, Integer> unique;
    Pattern activePattern;


    GrepTableModel tableModel;
    JXTreeTable table;
    JTable uniqueValueTable;
    UniqueValueTableModel uniqueTableModel;
    JButton btnSetPattern;
    boolean searching;
    JCheckBox onlyInScope;
    Thread searchThread;

    GrepPanel(){
        this.setLayout(new BorderLayout());
        JPanel regexPanel = new JPanel(new BorderLayout());
        regexPanel.add(new JLabel("  Regex: "), BorderLayout.WEST);
        final JTextField field = new JTextField();
        regexPanel.add(field, BorderLayout.CENTER);
        btnSetPattern = new JButton("Search");
        btnSetPattern.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if(!searching)
                    setActivePattern(field.getText());
                else if(!searchThread.isInterrupted()){
                    btnSetPattern.setText("Stopping. Click to force stop.");
                    searchThread.interrupt();
                }else{
                    searchThread.stop();
                    btnSetPattern.setText("Search");
                    searching = false;
                    tableModel.reload();
                    uniqueTableModel.reload();
                    table.revalidate();
                    table.repaint();
                    uniqueValueTable.revalidate();
                    uniqueValueTable.repaint();
                }
            }
        });
        field.getInputMap(JComponent.WHEN_FOCUSED)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "submit");
        field.getActionMap().put("submit", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if(!searching)
                    setActivePattern(field.getText());
                else if(!searchThread.isInterrupted()){
                    btnSetPattern.setText("Stopping. Click to force stop.");
                    searchThread.interrupt();
                }else{
                    searchThread.stop();
                    btnSetPattern.setText("Search");
                    searching = false;
                    tableModel.reload();
                    uniqueTableModel.reload();
                    table.revalidate();
                    table.repaint();
                    uniqueValueTable.revalidate();
                    uniqueValueTable.repaint();
                }
            }
        });
        this.onlyInScope = new JCheckBox("In Scope Only");
        JPanel buttonsPanel = new JPanel(new BorderLayout());
        buttonsPanel.add(this.onlyInScope, BorderLayout.WEST);
        buttonsPanel.add(btnSetPattern, BorderLayout.EAST);
        regexPanel.add(buttonsPanel, BorderLayout.EAST);
        this.add(regexPanel, BorderLayout.NORTH);

        matchingEntries = new ArrayList<>();
        unique = new HashMap<>();

        //Result Table
        tableModel = new GrepTableModel(new String[]{"Entry", "Matches"}, this.matchingEntries);
        table = new JXTreeTable(tableModel){
            @Override
            public boolean getScrollableTracksViewportWidth() {
                return getPreferredSize().width < getParent().getWidth();
            }
        };
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if(SwingUtilities.isRightMouseButton(e)) {
                    JPopupMenu menu = new JPopupMenu();
                    int row = table.rowAtPoint(e.getPoint());
                    TreePath path = table.getPathForRow(row);
                    Object obj = path.getLastPathComponent();
                    if (obj instanceof LogEntryMatches) {
                        obj = ((LogEntryMatches) obj).entry;
                    } else if (obj instanceof LogEntryMatches.Match) {
                        obj = ((LogEntryMatches) path.getPathComponent(path.getPathCount() - 2)).entry;
                    }
                    final int index = BurpExtender.getInstance().getLogTable().getModel().getData().indexOf(obj);
                    JMenuItem viewInLogs = new JMenuItem(new AbstractAction("View in Logs") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            if (index != -1) {
                                BurpExtender.getInstance().getLogTable().changeSelection(index, 1, false, false);
                                BurpExtender.getInstance().getTabbedPane().setSelectedIndex(0);
                            }
                        }
                    });
                    menu.add(viewInLogs);
                    viewInLogs.setEnabled(index != -1);
                    menu.show(table, e.getX(), e.getY());
                }
                super.mouseReleased(e);
            }
        });
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        DefaultXTreeCellRenderer renderer = ((DefaultXTreeCellRenderer) ((JXTree.DelegatingRenderer) table.getTreeCellRenderer()).getDelegateRenderer());
        renderer.setBackground(null);
        renderer.setOpaque(true);

        //Unique Values
        uniqueTableModel = new UniqueValueTableModel(this.unique);
        uniqueValueTable = new JTable(uniqueTableModel);
        uniqueValueTable.setAutoCreateRowSorter(true);

        JTabbedPane tabbed = new JTabbedPane();
        tabbed.addTab("Results", new JScrollPane(table));
        tabbed.addTab("Unique Values", new JScrollPane(uniqueValueTable));

        this.add(tabbed, BorderLayout.CENTER);
    }


    public synchronized void setActivePattern(String string){
        if(string.equalsIgnoreCase("")){
            tableModel.clearResults();
            uniqueTableModel.clearResults();
        }else {
            btnSetPattern.setText("Cancel");
            searching = true;
            try {
                activePattern = Pattern.compile(string, Pattern.CASE_INSENSITIVE);
            } catch (PatternSyntaxException e) {
                MoreHelp.showWarningMessage("Pattern syntax invalid.");
                endSearch();
                return;
            }
            int patternGroups = activePattern.matcher("").groupCount();
            String[] columns = new String[patternGroups + 3];
            columns[0] = "Entry";
            columns[1] = "Matches";
            columns[2] = "All Groups";
            for (int i = 1; i <= patternGroups; i++) {
                columns[i + 2] = "Group " + i + " Value";
            }
            tableModel.setColumns(columns);

            unique.clear();
            matchingEntries.clear();
            searchThread = new Thread() {
                @Override
                public void run() {
                    synchronized (BurpExtender.getInstance().getLogEntries()) {
                        for (LogEntry entry : BurpExtender.getInstance().getLogEntries()) {
                            if (onlyInScope.isSelected() && !BurpExtender.getInstance().getCallbacks().isInScope(entry.url)) continue;
                            if(isInterrupted()) break;
                            LogEntryMatches matches = new LogEntryMatches(entry, activePattern);
                            if (matches.results.size() > 0) matchingEntries.add(matches);
                        }
                    }
                    endSearch();
                }
            };
            searchThread.start();
        }
    }

    public void endSearch(){
        btnSetPattern.setText("Search");
        searching = false;
        tableModel.reload();
        uniqueTableModel.reload();
        table.revalidate();
        table.repaint();
        uniqueValueTable.revalidate();
        uniqueValueTable.repaint();
    }

    class LogEntryMatches{
        LogEntry entry;
        ArrayList<Match> results;
        class Match {
            String[] groups;
            Boolean isRequest;
        }

        public LogEntryMatches(LogEntry entry, Pattern pattern) {
            this.entry = entry;
            this.results = new ArrayList<>();
            getEntryMatches(pattern);
        }

        void getEntryMatches(Pattern pattern){
            if(entry.requestResponse != null){
                if(entry.requestResponse.getRequest() != null) {
                    Matcher reqMatcher = pattern.matcher(new String(entry.requestResponse.getRequest()));
                    while(reqMatcher.find()){
                        String[] groups = new String[reqMatcher.groupCount()+1];
                        Match match = new Match();
                        if(unique.containsKey(reqMatcher.group(0))){
                            unique.put(reqMatcher.group(0), unique.get(reqMatcher.group(0))+1);
                        }else{
                            unique.put(reqMatcher.group(0), 1);
                        }
                        for (int i = 0; i < groups.length; i++) {
                            groups[i] = reqMatcher.group(i);
                        }
                        match.groups = groups;
                        match.isRequest = true;
                        results.add(match);
                    }
                }
                if(entry.requestResponse.getResponse() != null) {
                    Matcher respMatcher = pattern.matcher(new String(entry.requestResponse.getResponse()));
                    while(respMatcher.find()){
                        String[] groups = new String[respMatcher.groupCount()+1];
                        Match match = new Match();
                        if(unique.containsKey(respMatcher.group(0))){
                            unique.put(respMatcher.group(0), unique.get(respMatcher.group(0))+1);
                        }else{
                            unique.put(respMatcher.group(0), 1);
                        }
                        for (int i = 0; i < groups.length; i++) {
                            groups[i] = respMatcher.group(i);
                        }
                        match.groups = groups;
                        match.isRequest = false;
                        results.add(match);
                    }
                }
            }
        }
    }

    class GrepTableModel extends AbstractTreeTableModel {
        String[] columns = {"Entry", "Matches"};
        ArrayList<LogEntryMatches> matchingEntries;

        GrepTableModel(String[] columns, ArrayList<LogEntryMatches> matchingEntries){
            super(new Object());
            this.columns = columns;
            this.matchingEntries = matchingEntries;
        }

        public void setColumns(String[] columns){
            this.columns = columns;
        }

        public void reload(){
            modelSupport.fireNewRoot();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public boolean isLeaf(Object node) {
            return node instanceof LogEntryMatches.Match;
        }

        @Override
        public Object getValueAt(Object node, int i) {
            if(node instanceof LogEntryMatches){
                if(i == 0) return ((LogEntryMatches) node).entry.toString();
                if(i == 1) return ((LogEntryMatches) node).results.size();
                else return "";
            }
            if(node instanceof LogEntryMatches.Match){
                if(i == 0) return ((LogEntryMatches.Match) node).isRequest ? "REQUEST" : "RESPONSE";
                if(i == 1) return "";
                if(i-1 > ((LogEntryMatches.Match) node).groups.length){
                    return "";
                }
                return ((LogEntryMatches.Match) node).groups[i-2];
            }
            return "";
        }

        @Override
        public Object getChild(Object parent, int i) {
            if(parent instanceof LogEntryMatches)
                return ((LogEntryMatches) parent).results.get(i);
            if(this.matchingEntries == null) return null;
            return this.matchingEntries.get(i);
        }

        @Override
        public int getChildCount(Object parent) {
            if(parent instanceof LogEntryMatches){
                return ((LogEntryMatches) parent).results.size();
            }
            if(this.matchingEntries == null) return 0;
            return this.matchingEntries.size();
        }

        @Override
        public int getIndexOfChild(Object parent, Object child) {
            if(parent instanceof LogEntryMatches){
                return ((LogEntryMatches) parent).results.indexOf(child);
            }
            return -1;
        }

        public void clearResults() {
            matchingEntries.clear();
            modelSupport.fireNewRoot();
        }
    }

    class UniqueValueTableModel extends DefaultTableModel {
        String[] COLUMN_NAMES = {"Value", "Count"};
        Map<String, Integer> uniqueValues;

        UniqueValueTableModel(Map<String, Integer> uniqueValues){
            this.uniqueValues = uniqueValues;

        }

        @Override
        public int getRowCount() {
            if(uniqueValues == null) return 0;
            return uniqueValues.size();
        }

        public void reload(){
            fireTableDataChanged();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int i) {
            return COLUMN_NAMES[i];
        }

        @Override
        public Class<?> getColumnClass(int i) {
            if(i == 1) return Integer.class;
            else return String.class;
        }

        @Override
        public boolean isCellEditable(int i, int i1) {
            return false;
        }

        @Override
        public Object getValueAt(int row, int column) {
            //TODO move sort logic
            if(row >= this.uniqueValues.size()) return "";
            ArrayList<String> keys = new ArrayList<>(this.uniqueValues.keySet());
            Collections.sort(keys);
            if(column == 0) return keys.get(row);
            else return this.uniqueValues.get(keys.get(row));
        }

        @Override
        public void setValueAt(Object o, int i, int i1) {
            return;
        }

        @Override
        public void addTableModelListener(TableModelListener tableModelListener) {
            return;
        }

        @Override
        public void removeTableModelListener(TableModelListener tableModelListener) {
            return;
        }

        public void clearResults() {
            uniqueValues.clear();
        }
    }

}

