package loggerplusplus.userinterface;

import loggerplusplus.FilterController;
import loggerplusplus.Globals;
import loggerplusplus.LogManager;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.userinterface.dialog.ColorFilterDialog;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * Created by corey on 24/08/17.
 */
public class LogViewPanel extends JPanel {

    final LogTable logTable;
    final JScrollPane logTableScrollPane;
    JProgressBar progressBar;

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
    }

    public void showImportProgress(int entries){
        progressBar = new JProgressBar(0, entries);
        this.remove(logTableScrollPane);
        this.add(progressBar);
    }

    public void setProgressValue(int progressValue){
        if(progressBar == null) return;
        this.progressBar.setValue(progressValue);
    }

    public void showLogTable(){
        this.remove(progressBar);
        this.add(logTableScrollPane);
    }

    public LogTable getLogTable() {
        return logTable;
    }

    public JScrollPane getScrollPane() {
        return logTableScrollPane;
    }
}
