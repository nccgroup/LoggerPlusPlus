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

    public LogViewPanel(LogManager logManager){
        this.setLayout(new GridLayout());

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
        logTableScrollPane.getVerticalScrollBar().addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {}
            @Override
            public void mousePressed(MouseEvent mouseEvent) {}
            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                JScrollBar scrollBar = logTableScrollPane.getVerticalScrollBar();
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_AUTO_SCROLL,
                        scrollBar.getValue() + scrollBar.getHeight() >= scrollBar.getMaximum());
            }
            @Override
            public void mouseEntered(MouseEvent mouseEvent) {}
            @Override
            public void mouseExited(MouseEvent mouseEvent) {}
        });

        this.add(this.logTableScrollPane);

        PanelBuilder panelBuilder = new PanelBuilder(LoggerPlusPlus.preferences);
        progressBar = new JProgressBar();
        try {
            importPanel = panelBuilder.build(new JComponent[][]{
                    new JComponent[]{new JLabel("Importing: ")},
                    new JComponent[]{progressBar}
            }, Alignment.CENTER, 1.0, 1.0);
        }catch (Exception e){
            importPanel = new JLabel("Importing entries, please wait...");
        }
    }

    public void showImportProgress(int entries){
        progressBar.setMaximum(entries);
        this.remove(logTableScrollPane);
        this.add(importPanel);
        this.revalidate();
        this.repaint();
    }

    public void setProgressValue(int progressValue){
        if(progressBar == null) return;
        this.progressBar.setValue(progressValue);
    }

    public void showLogTable(){
        this.remove(importPanel);
        this.add(logTableScrollPane);
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
