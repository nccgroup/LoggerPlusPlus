package com.nccgroup.loggerplusplus.grepper;

import burp.BurpExtender;
import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.HistoryField;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.util.Globals;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class GrepperPanel extends JPanel implements GrepperListener {

    private final GrepperController controller;
    private final Preferences preferences;
    private final HistoryField searchField;
    private final JButton searchButton;
    private final JButton resetButton;
    private final JProgressBar progressBar;
    private final JCheckBox inScopeOnly;
    private final JTabbedPane resultsPane;
    private final GrepResultsTable grepResultsTable;
    private final UniquePatternMatchTable uniqueTable;

    GrepperPanel(GrepperController controller, Preferences preferences){
        this.controller = controller;
        this.preferences = preferences;

        searchField = new HistoryField(this.preferences, Globals.PREF_GREP_HISTORY, 15);
        searchField.getEditor().getEditorComponent().addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if(e.getKeyChar() == KeyEvent.VK_ENTER){
                    startSearch();
                }
            }
        });

        this.progressBar = new JProgressBar();
        this.inScopeOnly = new JCheckBox("In Scope Only");

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
        this.uniqueTable = new UniquePatternMatchTable(controller);

        this.resultsPane = new JTabbedPane();
        this.resultsPane.addTab("Results", new JScrollPane(grepResultsTable));
        this.resultsPane.addTab("Unique Results", new JScrollPane(uniqueTable));

        JPanel wrapperPanel = PanelBuilder.build(new JComponent[][]{
                new JComponent[]{new JLabel("Regex: "), searchField, inScopeOnly, searchButton, resetButton},
                new JComponent[]{resultsPane, resultsPane, resultsPane, resultsPane, resultsPane},
                new JComponent[]{progressBar, progressBar, progressBar, progressBar, progressBar}
        }, new int[][]{
                new int[]{0, 1,   0, 0, 0},
                new int[]{1, 100, 1, 1, 0},
                new int[]{0, 0,   0, 0, 0}
        }, Alignment.FILL, 1.0, 1.0);

        this.setLayout(new BorderLayout());
        this.add(wrapperPanel, BorderLayout.CENTER);

        this.controller.addListener(this);
    }

    private void startSearch(){
        String patternString = ((JTextField) this.searchField.getEditor().getEditorComponent()).getText();
        Pattern pattern;
        try {
            pattern = Pattern.compile(patternString, Pattern.CASE_INSENSITIVE);
        }catch (PatternSyntaxException e){
            JOptionPane.showMessageDialog(JOptionPane.getFrameForComponent(controller.getLoggerPlusPlus().getMainViewController().getUiComponent()), "Pattern Syntax Invalid", "Invalid Pattern", JOptionPane.ERROR_MESSAGE);
            return;
        }

        this.controller.beginSearch(pattern, this.inScopeOnly.isSelected());
    }

    @Override
    public void onSearchStarted(Pattern pattern, int totalRequests) {
        SwingUtilities.invokeLater(() -> {
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
        SwingUtilities.invokeLater(() -> {
            this.searchButton.setText("Search");
            this.progressBar.setValue(0);
            this.searchField.setEnabled(true);
            this.resetButton.setEnabled(true);
        });
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
        SwingUtilities.invokeLater(() -> {
            this.searchButton.setText("Search");
            this.progressBar.setValue(0);
            this.searchField.setEnabled(true);
            this.resetButton.setEnabled(true);
        });
    }
}
