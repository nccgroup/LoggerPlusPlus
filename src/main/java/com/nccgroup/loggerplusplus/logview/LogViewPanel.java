package com.nccgroup.loggerplusplus.logview;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.loggerplusplus.logentry.LogManager;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableColumnModel;
import com.nccgroup.loggerplusplus.userinterface.LogTableModel;
import com.nccgroup.loggerplusplus.util.Globals;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * Created by corey on 24/08/17.
 */
public class LogViewPanel extends JPanel {

    final LogTable logTable;
    final JScrollPane logTableScrollPane;
    final JProgressBar progressBar;
    JComponent importPanel;
    JComponent filteringPanel;

    public LogViewPanel(LogManager logManager){
        this.setLayout(new BorderLayout());

        LogTableColumnModel columnModel = new LogTableColumnModel();
        LogTableModel tableModel = new LogTableModel(logManager, columnModel);
        logTable = new LogTable(tableModel, columnModel);
        logTableScrollPane = new JScrollPane(logTable,ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);//View
        logTableScrollPane.addMouseWheelListener(new MouseWheelListener() {
            @Override
            public void mouseWheelMoved(MouseWheelEvent mouseWheelEvent) {
                JScrollBar scrollBar = logTableScrollPane.getVerticalScrollBar();
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_AUTO_SCROLL,
                        scrollBar.getValue() + scrollBar.getHeight() >= scrollBar.getMaximum());
            }
        });
        logTableScrollPane.getVerticalScrollBar().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                JScrollBar scrollBar = logTableScrollPane.getVerticalScrollBar();
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_AUTO_SCROLL,
                        scrollBar.getValue() + scrollBar.getHeight() >= scrollBar.getMaximum());
            }
        });

        this.add(this.logTableScrollPane, BorderLayout.CENTER);

        PanelBuilder panelBuilder = new PanelBuilder(LoggerPlusPlus.preferences);
        progressBar = new JProgressBar();
        importPanel = panelBuilder.build(new JComponent[][]{
                new JComponent[]{new JLabel("Importing: ")},
                new JComponent[]{progressBar}
        }, Alignment.CENTER, 1.0, 1.0);
        filteringPanel = panelBuilder.build(new JComponent[][]{
                new JComponent[]{new JLabel("Filtering results...")}
        }, Alignment.CENTER, 1.0, 1.0);

        logTable.addFilterStatusListener(new LogTableFilterStatusListener() {
            @Override
            public void onFilteringStart() {
                LogViewPanel.this.removeAll();
                LogViewPanel.this.add(filteringPanel, BorderLayout.CENTER);
                LogViewPanel.this.revalidate();
                LogViewPanel.this.repaint();
            }

            @Override
            public void onFilteringFinish() {
                LogViewPanel.this.removeAll();
                LogViewPanel.this.add(logTableScrollPane, BorderLayout.CENTER);
                LogViewPanel.this.revalidate();
                LogViewPanel.this.repaint();
            }
        });
    }

    public void showImportProgress(int entries){
        progressBar.setMaximum(entries);
        this.removeAll();
        this.add(importPanel, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
    }

    public void setProgressValue(int progressValue){
        if(progressBar == null) return;
        this.progressBar.setValue(progressValue);
    }

    public void showLogTable(){
        this.removeAll();
        this.add(logTableScrollPane, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
    }

    public LogTable getLogTable() {
        return logTable;
    }

    public JScrollPane getScrollPane() {
        return logTableScrollPane;
    }
}
