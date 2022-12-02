package com.nccgroup.loggerplusplus.grepper;

import com.coreyd97.BurpExtenderUtilities.HistoryField;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logview.entryviewer.RequestViewerController;
import com.nccgroup.loggerplusplus.util.Globals;

import javax.swing.*;
import javax.swing.tree.TreePath;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class GrepperPanel extends JPanel implements GrepperListener {

    private final GrepperController controller;
    private final Preferences preferences;
    private final HistoryField searchField;
    private final JButton searchButton;
    private final JButton resetButton;
    private final JProgressBar progressBar;
    private final JCheckBox searchRequests;
    private final JCheckBox searchResponses;
    private final JCheckBox inScopeOnly;
    private final JTabbedPane resultsPane;
    private final GrepResultsTable grepResultsTable;
    private final RequestViewerController requestViewerController;
    private final UniquePatternMatchTable uniqueTable;

    GrepperPanel(GrepperController controller, Preferences preferences) {
        this.controller = controller;
        this.preferences = preferences;

        searchField = new HistoryField(this.preferences, Globals.PREF_GREP_HISTORY, 15);
        searchField.getEditor().getEditorComponent().addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyChar() == KeyEvent.VK_ENTER) {
                    startSearch();
                }
            }
        });

        this.progressBar = new JProgressBar();
        this.inScopeOnly = new JCheckBox("In Scope Only");
        this.searchRequests = new JCheckBox("Search Requests", true);
        this.searchResponses = new JCheckBox("Search Responses", true);

        this.searchButton = new JButton(new AbstractAction("Search") {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (controller.isSearching()) {
                    controller.cancelSearch();
                } else {
                    startSearch();
                }
            }
        });

        this.resetButton = new JButton(new AbstractAction("Reset") {
            @Override
            public void actionPerformed(ActionEvent e) {
                controller.reset();
            }
        });

        this.grepResultsTable = new GrepResultsTable(controller);
        this.requestViewerController = new RequestViewerController(preferences);

        grepResultsTable.addTreeSelectionListener(treeSelectionEvent -> {
            TreePath selectedPath = treeSelectionEvent.getPath();
            GrepResults grepResultEntry = (GrepResults) selectedPath.getPath()[1];
            GrepResults.Match selectedMatch = null;
            if (selectedPath.getPath().length > 2) {
                selectedMatch = (GrepResults.Match) selectedPath.getPath()[2];
            }

            LogEntry requestResponse = grepResultEntry.getLogEntry();
            List<GrepResults.Match> matches;

            if (selectedMatch != null) {
                matches = Collections.singletonList(selectedMatch);
            } else {
                matches = grepResultEntry.getMatches();
            }

            requestViewerController.setDisplayedEntity(requestResponse);

            //TODO Setup message editor to support highlighting. Code is ready, waiting on API support.
//            IHttpRequestResponseWithMarkers markedRequestResponse = controller.addMarkers(requestResponse, matches);
            //https://forum.portswigger.net/thread/eeditor-custom-highlighting-991b1a7e?CategoryId=burp-extensions
        });

        JSplitPane resultsSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(grepResultsTable), requestViewerController.getRequestViewerPanel());
        this.uniqueTable = new UniquePatternMatchTable(controller);

        this.resultsPane = new JTabbedPane();
        this.resultsPane.addTab("Results", resultsSplitPane);
        this.resultsPane.addTab("Unique Results", new JScrollPane(uniqueTable));

        JLabel regexLabel = new JLabel("Regex: ");

        PanelBuilder panelBuilder = new PanelBuilder();
        panelBuilder.setComponentGrid(new JComponent[][]{
                new JComponent[]{regexLabel, searchField, searchRequests, searchResponses, inScopeOnly, searchButton, resetButton},
                new JComponent[]{resultsPane, resultsPane, resultsPane, resultsPane, resultsPane, resultsPane, resultsPane},
                new JComponent[]{progressBar, progressBar, progressBar, progressBar, progressBar, progressBar, progressBar}
        });
        panelBuilder.setGridWeightsY(new int[][]{
                new int[]{0, 0, 0, 0, 0, 0},
                new int[]{1, 1, 1, 1, 1, 1},
                new int[]{0, 0, 0, 0, 0, 0}
        });
        panelBuilder.setGridWeightsX(new int[][]{
                new int[]{0, 1, 0, 0, 0, 0},
                new int[]{0, 0, 0, 0, 0, 0},
                new int[]{0, 0, 0, 0, 0, 0}
        });


        this.setLayout(new BorderLayout());
        this.add(panelBuilder.build(), BorderLayout.CENTER);

        this.controller.addListener(this);
    }

    private void startSearch() {
        String patternString = ((JTextField) this.searchField.getEditor().getEditorComponent()).getText();
        Pattern pattern;
        try {
            pattern = Pattern.compile(patternString, Pattern.CASE_INSENSITIVE);
        } catch (PatternSyntaxException e) {
            JOptionPane.showMessageDialog(JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getMainViewController().getUiComponent()), "Pattern Syntax Invalid", "Invalid Pattern", JOptionPane.ERROR_MESSAGE);
            return;
        }

        this.controller.beginSearch(pattern, this.inScopeOnly.isSelected(),
                this.searchRequests.isSelected(), this.searchResponses.isSelected());
    }

    @Override
    public void onSearchStarted(Pattern pattern, int totalRequests) {
        SwingUtilities.invokeLater(() -> {
            this.searchRequests.setEnabled(false);
            this.searchResponses.setEnabled(false);
            this.searchField.setEnabled(false);
            this.resetButton.setEnabled(false);
            this.searchButton.setText("Cancel");
            this.progressBar.setMaximum(totalRequests);
            this.progressBar.setValue(0);
        });
    }

    @Override
    public synchronized void onEntryProcessed(GrepResults entryResults) {
        SwingUtilities.invokeLater(() -> {
            this.progressBar.setValue(this.progressBar.getValue()+1);
        });
    }

    @Override
    public void onSearchComplete() {
        unlockUI();
    }

    @Override
    public void onResetRequested() {

    }

    @Override
    public void onShutdownInitiated() {
        SwingUtilities.invokeLater(() -> {
            this.searchButton.setText("Stopping...");
        });
    }

    @Override
    public void onShutdownComplete() {
        unlockUI();
    }

    private void unlockUI() {
        SwingUtilities.invokeLater(() -> {
            this.searchButton.setText("Search");
            this.progressBar.setValue(0);
            this.searchField.setEnabled(true);
            this.resetButton.setEnabled(true);
            this.searchRequests.setEnabled(true);
            this.searchResponses.setEnabled(true);
        });
    }
}
