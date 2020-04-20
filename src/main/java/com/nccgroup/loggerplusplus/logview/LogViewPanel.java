package com.nccgroup.loggerplusplus.logview;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.BurpExtenderUtilities.VariableViewPanel;
import com.nccgroup.loggerplusplus.logview.entryviewer.RequestViewerPanel;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.util.Globals;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Created by corey on 24/08/17.
 */
public class LogViewPanel extends JPanel {

    private final LogViewController controller;
    private final Preferences preferences;
    private final MainControlsPanel mainControlsPanel;
    private final LogTable logTable;
    private final JScrollPane logTableScrollPane;
    private final RequestViewerPanel requestViewerPanel;
    private final VariableViewPanel tableViewerSplitPanel;

    public LogViewPanel(LogViewController controller){
        this.controller = controller;
        this.preferences = controller.getPreferences();

        mainControlsPanel = new MainControlsPanel(controller.getLogFilterController());

        logTable = controller.getLogTableController().getLogTable();

        logTableScrollPane = new JScrollPane(logTable,ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);//View
        logTableScrollPane.addMouseWheelListener(mouseWheelEvent -> {
            JScrollBar scrollBar = logTableScrollPane.getVerticalScrollBar();
            preferences.setSetting(Globals.PREF_AUTO_SCROLL,
                    scrollBar.getValue() + scrollBar.getHeight() >= scrollBar.getMaximum());
        });
        logTableScrollPane.getVerticalScrollBar().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                JScrollBar scrollBar = logTableScrollPane.getVerticalScrollBar();
                preferences.setSetting(Globals.PREF_AUTO_SCROLL,
                        scrollBar.getValue() + scrollBar.getHeight() >= scrollBar.getMaximum());
            }
        });

        requestViewerPanel = controller.getRequestViewerController().getRequestViewerPanel();

        tableViewerSplitPanel = new VariableViewPanel(controller.getPreferences(), Globals.PREF_LAYOUT,
                logTableScrollPane, "Log Table",
                requestViewerPanel, "Request/Response", VariableViewPanel.View.VERTICAL);

        buildUI();
    }

    private void buildUI(){
        this.removeAll();
        this.setLayout(new BorderLayout());

        JPanel panel = PanelBuilder.build(new Component[][]{
                new Component[]{mainControlsPanel},
                new Component[]{tableViewerSplitPanel},
        }, new int[][]{
                new int[]{0},
                new int[]{1}
        }, Alignment.FILL, 1.0, 1.0);

        this.add(panel, BorderLayout.CENTER);
    }

    public VariableViewPanel getTableViewerSplitPanel() {
        return tableViewerSplitPanel;
    }

    public RequestViewerPanel getRequestViewerPanel() {
        return requestViewerPanel;
    }

    public LogTable getLogTable() {
        return logTable;
    }

    public JScrollPane getScrollPane() {
        return logTableScrollPane;
    }
}
