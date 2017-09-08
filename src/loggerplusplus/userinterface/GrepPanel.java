package loggerplusplus.userinterface;

import burp.BurpExtender;
import ca.odell.glazedlists.BasicEventList;
import ca.odell.glazedlists.EventList;
import ca.odell.glazedlists.UniqueList;
import ca.odell.glazedlists.swing.EventTableModel;
import ca.odell.glazedlists.swing.GlazedListsSwing;
import loggerplusplus.LogEntry;
import loggerplusplus.MoreHelp;
import org.jdesktop.swingx.JXTree;
import org.jdesktop.swingx.JXTreeTable;
import org.jdesktop.swingx.tree.DefaultXTreeCellRenderer;
import org.jdesktop.swingx.treetable.AbstractTreeTableModel;

import javax.swing.*;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Created by corey on 29/08/17.
 */

public class GrepPanel extends JPanel{
    Pattern activePattern;
    final HistoryField field;
    GrepTableModel grepModel;
    JXTreeTable grepTable;
    UniqueValueTable uniqueValueTable;
    JButton btnSetPattern;
    boolean isSearching;
    JCheckBox searchInScopeOnly;
    Thread searchThread;
    ExecutorService searchExecutor;

    public GrepPanel(){
        this.setLayout(new GridBagLayout());
        JPanel regexPanel = new JPanel(new BorderLayout());
        regexPanel.add(new JLabel("  Regex: "), BorderLayout.WEST);
        field = new HistoryField(15, "grepHistory");
        regexPanel.add(field, BorderLayout.CENTER);
        btnSetPattern = new JButton("Search");
        btnSetPattern.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                toggleSearch();
            }
        });
        field.getEditor().getEditorComponent().addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if(e.getKeyChar() == KeyEvent.VK_ENTER){
                    toggleSearch();
                }
                super.keyReleased(e);
            }
        });
        this.searchInScopeOnly = new JCheckBox("In Scope Only");
        JPanel buttonsPanel = new JPanel(new BorderLayout());
        buttonsPanel.add(this.searchInScopeOnly, BorderLayout.WEST);
        buttonsPanel.add(btnSetPattern, BorderLayout.EAST);
        regexPanel.add(buttonsPanel, BorderLayout.EAST);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.weightx = gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = gbc.gridy = 0;
        this.add(regexPanel, gbc);

        //Result Table
        grepModel = new GrepTableModel(new String[]{"Entry", "Matches"});
        grepTable = new JXTreeTable(grepModel){
            @Override
            public boolean getScrollableTracksViewportWidth() {
                return getPreferredSize().width < getParent().getWidth();
            }
        };
        grepTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if(SwingUtilities.isRightMouseButton(e)) {
                    JPopupMenu menu = new JPopupMenu();
                    int row = grepTable.rowAtPoint(e.getPoint());
                    TreePath path = grepTable.getPathForRow(row);
                    Object obj = path.getLastPathComponent();
                    if (obj instanceof LogEntryMatches) {
                        obj = ((LogEntryMatches) obj).entry;
                    } else if (obj instanceof LogEntryMatches.Match) {
                        obj = ((LogEntryMatches) path.getPathComponent(path.getPathCount() - 2)).entry;
                    }
                    final int index = BurpExtender.getLoggerInstance().getLogTable().getModel().getData().indexOf(obj);
                    JMenuItem viewInLogs = new JMenuItem(new AbstractAction("View in Logs") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            if (index != -1) {
                                BurpExtender.getLoggerInstance().getLogTable().changeSelection(index, 1, false, false);
                                BurpExtender.getLoggerInstance().getTabbedPane().setSelectedIndex(0);
                            }
                        }
                    });
                    menu.add(viewInLogs);
                    viewInLogs.setEnabled(index != -1);
                    menu.show(grepTable, e.getX(), e.getY());
                }
                super.mouseReleased(e);
            }
        });
        grepTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        DefaultXTreeCellRenderer renderer = ((DefaultXTreeCellRenderer) ((JXTree.DelegatingRenderer) grepTable.getTreeCellRenderer()).getDelegateRenderer());
        renderer.setBackground(null);
        renderer.setOpaque(true);

        //Unique Values
        EventList eventList = GlazedListsSwing.swingThreadProxyList(new UniqueList(new BasicEventList()));
        EventTableModel tableModel = new EventTableModel(eventList, new UniqueValueTable.UniqueValueTableFormat());
        uniqueValueTable = new UniqueValueTable(eventList, tableModel);

        JTabbedPane tabbed = new JTabbedPane();
        tabbed.addTab("Results", new JScrollPane(grepTable));
        tabbed.addTab("Unique Values", new JScrollPane(uniqueValueTable));

        gbc.gridy = 1;
        gbc.weightx = gbc.weighty = 999;
        this.add(tabbed, gbc);

        this.searchExecutor = Executors.newCachedThreadPool();
    }

    private void toggleSearch(){
        if(!isSearching) {
            setActivePattern((String) field.getSelectedItem());
            ((HistoryField.HistoryComboModel) field.getModel()).addToHistory((String) field.getSelectedItem());
        }else if(!searchThread.isInterrupted()){
            btnSetPattern.setText("Stopping. Click to force stop.");
            searchThread.interrupt();
        }else{
            searchThread.stop();
            endSearch();
        }
    }


    public synchronized void setActivePattern(String string){
        if(string.equalsIgnoreCase("")){
            grepModel.clearResults();
            uniqueValueTable.clearList();
        }else {
            btnSetPattern.setText("Cancel");
            isSearching = true;
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
            grepModel.setColumns(columns);

            uniqueValueTable.clearList();
            grepModel.clearResults();
            searchThread = new Thread() {
                @Override
                public void run() {
                    synchronized (BurpExtender.getLoggerInstance().getLogManager().getLogEntries()) {
                        for (final LogEntry entry : BurpExtender.getLoggerInstance().getLogManager().getLogEntries()) {
                            searchExecutor.submit(new Runnable() {
                                @Override
                                public void run() {
                                    if (!searchInScopeOnly.isSelected() || BurpExtender.getCallbacks().isInScope(entry.url)) {
                                        LogEntryMatches matches = new LogEntryMatches(entry, activePattern);
                                        if (matches.results.size() > 0) grepModel.addEntry(matches);
                                    }
                                }
                            });
                        }
                    }

                    try {
                        searchExecutor.awaitTermination(Integer.MAX_VALUE, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        searchExecutor.shutdownNow();
                    }
                    endSearch();
                }
            };
            searchThread.start();
        }
    }

    public void endSearch(){
        btnSetPattern.setText("Search");
        isSearching = false;
        grepModel.reload();
        grepTable.revalidate();
        grepTable.repaint();
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
                        uniqueValueTable.addItem(reqMatcher.group(0));
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
                        uniqueValueTable.addItem(respMatcher.group(0));
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

        GrepTableModel(String[] columns){
            super(new Object());
            this.columns = columns;
            this.matchingEntries = new ArrayList<>();
        }

        public void addEntry(LogEntryMatches matches){
            synchronized (matchingEntries) {
                this.matchingEntries.add(matches);
            }

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
}

