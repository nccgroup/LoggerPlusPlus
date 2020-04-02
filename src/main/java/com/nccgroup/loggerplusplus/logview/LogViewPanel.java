package com.nccgroup.loggerplusplus.logview;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.loggerplusplus.logentry.LogProcessor;
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

    public LogViewPanel(LogProcessor logProcessor){
        this.setLayout(new BorderLayout());

        LogTableColumnModel columnModel = new LogTableColumnModel();
        LogTableModel tableModel = new LogTableModel(logProcessor, columnModel);
        logTable = new LogTable(tableModel, columnModel);
        logTableScrollPane = new JScrollPane(logTable,ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                                                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);//View
        logTableScrollPane.addMouseWheelListener(mouseWheelEvent -> {
            JScrollBar scrollBar = logTableScrollPane.getVerticalScrollBar();
            LoggerPlusPlus.preferences.setSetting(Globals.PREF_AUTO_SCROLL,
                    scrollBar.getValue() + scrollBar.getHeight() >= scrollBar.getMaximum());
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
    }

    public LogTable getLogTable() {
        return logTable;
    }

    public JScrollPane getScrollPane() {
        return logTableScrollPane;
    }
}
