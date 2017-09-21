package loggerplusplus.userinterface;

import ca.odell.glazedlists.BasicEventList;
import ca.odell.glazedlists.EventList;
import loggerplusplus.LogEntry;
import loggerplusplus.LoggerPlusPlus;
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
import java.util.concurrent.ThreadPoolExecutor;
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
        JPanel regexPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = gbc.gridy = 0;
        gbc.ipadx = 10;
        gbc.weightx = 1;
        regexPanel.add(new JLabel(" Regex:"), gbc);
        field = new HistoryField(15, "grepHistory");
        gbc.gridx++;
        gbc.weightx = 999;
        regexPanel.add(field, gbc);
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
        gbc.gridx++;
        gbc.weightx = 1;
        regexPanel.add(this.searchInScopeOnly, gbc);
        gbc.gridx++;
        gbc.weightx = 1;
        regexPanel.add(btnSetPattern, gbc);

        gbc = new GridBagConstraints();
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
                    final int index = LoggerPlusPlus.getInstance().getLogTable().getModel().getData().indexOf(obj);
                    JMenuItem viewInLogs = new JMenuItem(new AbstractAction("View in Logs") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            if (index != -1) {
                                LogTable table = LoggerPlusPlus.getInstance().getLogTable();
                                table.changeSelection(table.convertRowIndexToView(index), 1, false, false);
                                LoggerPlusPlus.getInstance().getTabbedPane().setSelectedIndex(0);
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
//        SortedList eventList = new SortedList(new UniqueList(new BasicEventList()));
//        AdvancedTableModel tableModel = GlazedListsSwing.eventTableModel(GlazedListsSwing.swingThreadProxyList(eventList), new UniqueValueTable.UniqueValueTableFormat());
        uniqueValueTable = new UniqueValueTable();

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
            //Start search
            if(field.getSelectedItem() != null) {
                setActivePattern((String) field.getSelectedItem());
                ((HistoryField.HistoryComboModel) field.getModel()).addToHistory((String) field.getSelectedItem());
            }
        }else if(!((ThreadPoolExecutor) searchExecutor).isTerminating()){
            //Attempt shutdown
            searchExecutor.shutdownNow();
            btnSetPattern.setText("Stopping. Click to force stop.");
        }else{
            searchThread.interrupt();
        }
    }


    public synchronized void setActivePattern(String string){
        if(string == null || string.equalsIgnoreCase("")){
            grepModel.clearResults();
            uniqueValueTable.reset();
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

            searchThread = new Thread() {
                @Override
                public void run() {
                    uniqueValueTable.reset();
                    grepModel.clearResults();
                    GrepPanel.this.searchExecutor = Executors.newCachedThreadPool();
                    ArrayList<LogEntry> logEntryList;
                    synchronized (LoggerPlusPlus.getInstance().getLogManager().getLogEntries()) {
                        logEntryList = new ArrayList<>(LoggerPlusPlus.getInstance().getLogManager().getLogEntries());
                    }
                    for (final LogEntry entry : logEntryList) {
                        searchExecutor.submit(new Runnable() {
                            @Override
                            public void run() {
                                if (!searchInScopeOnly.isSelected() || LoggerPlusPlus.getCallbacks().isInScope(entry.url)) {
                                    LogEntryMatches matches = new LogEntryMatches(entry, activePattern);
                                    if (matches.results.size() > 0) grepModel.addEntry(matches);
                                }
                            }
                        });
                    }
                    searchExecutor.shutdown();

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
            try {
                getEntryMatches(pattern);
            }catch (Exception e){
                e.printStackTrace();
            }
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
        EventList matchingEntries;

        GrepTableModel(String[] columns){
            super(new Object());
            this.columns = columns;
            this.matchingEntries = new BasicEventList<LogEntryMatches>();
        }

        public void addEntry(LogEntryMatches matches){
            this.matchingEntries.getReadWriteLock().writeLock().lock();
            try{
                this.matchingEntries.add(matches);
            }finally {
                this.matchingEntries.getReadWriteLock().writeLock().unlock();
            }

        }

        public void setColumns(String[] columns){
            this.columns = columns;
        }

        public void reload(){
            synchronized (matchingEntries) {
                modelSupport.fireNewRoot();
            }
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
            matchingEntries.getReadWriteLock().writeLock().lock();
            try {
                if (matchingEntries.size() != 0) {
                    matchingEntries.clear();
                }
            }catch(IndexOutOfBoundsException iobException){
            }finally {
                matchingEntries.getReadWriteLock().writeLock().unlock();
            }
            modelSupport.fireNewRoot();
        }
    }
}

