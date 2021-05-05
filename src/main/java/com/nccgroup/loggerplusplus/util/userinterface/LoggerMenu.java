package com.nccgroup.loggerplusplus.util.userinterface;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.BurpExtenderUtilities.VariableViewPanel;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.ColorFilterDialog;
import org.apache.logging.log4j.Level;

import javax.swing.*;
import java.awt.event.ActionEvent;

/**
 * Created by corey on 07/09/17.
 */
public class LoggerMenu extends javax.swing.JMenu {

    private final LoggerPlusPlus loggerPlusPlus;
    private final Preferences preferences;

    public LoggerMenu(LoggerPlusPlus loggerPlusPlus){
        super(Globals.APP_NAME);
        this.loggerPlusPlus = loggerPlusPlus;
        this.preferences = loggerPlusPlus.getPreferencesController().getPreferences();

        this.add(loggerPlusPlus.getMainViewController().getPopOutWrapper().getPopoutMenuItem());
        this.add(loggerPlusPlus.getLogViewController().getLogViewPanel().getRequestViewerPanel().getPopoutMenuItem());

        JMenuItem colorFilters = new JMenuItem(new AbstractAction("Color Filters") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new ColorFilterDialog(LoggerPlusPlus.instance.getLibraryController()).setVisible(true);
            }
        });
        this.add(colorFilters);

        JMenu viewMenu = new JMenu("View");
        VariableViewPanel.View currentView = preferences.getSetting(Globals.PREF_LAYOUT);
        ButtonGroup bGroup = new ButtonGroup();
        JRadioButtonMenuItem viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPlusPlus.getLogViewController().setPanelLayout(VariableViewPanel.View.VERTICAL);
            }
        });
        viewMenuItem.setSelected(currentView == VariableViewPanel.View.VERTICAL);
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPlusPlus.getLogViewController().setPanelLayout(VariableViewPanel.View.HORIZONTAL);
            }
        });
        viewMenuItem.setSelected(currentView == VariableViewPanel.View.HORIZONTAL);
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPlusPlus.getLogViewController().setPanelLayout(VariableViewPanel.View.TABS);
            }
        });
        viewMenuItem.setSelected(currentView == VariableViewPanel.View.TABS);
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        this.add(viewMenu);

        viewMenu = new JMenu("Request/Response View");
        VariableViewPanel.View currentReqRespView = preferences.getSetting(Globals.PREF_MESSAGE_VIEW_LAYOUT);
        bGroup = new ButtonGroup();
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPlusPlus.getLogViewController().setEntryViewerLayout(VariableViewPanel.View.VERTICAL);
            }
        });
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem.setSelected(currentReqRespView == VariableViewPanel.View.VERTICAL);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPlusPlus.getLogViewController().setEntryViewerLayout(VariableViewPanel.View.HORIZONTAL);
            }
        });
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem.setSelected(currentReqRespView == VariableViewPanel.View.HORIZONTAL);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPlusPlus.getLogViewController().setEntryViewerLayout(VariableViewPanel.View.TABS);
            }
        });
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem.setSelected(currentReqRespView == VariableViewPanel.View.TABS);
        this.add(viewMenu);

        ButtonGroup logLevelGroup = new ButtonGroup();
        Level logLevel = preferences.getSetting(Globals.PREF_LOG_LEVEL);
        AbstractButton debug = new JRadioButtonMenuItem(String.valueOf(Level.DEBUG), logLevel.compareTo(Level.DEBUG) == 0);
        debug.addActionListener(actionEvent -> {
            preferences.setSetting(Globals.PREF_LOG_LEVEL, Level.DEBUG);
        });
        AbstractButton info = new JRadioButtonMenuItem(String.valueOf(Level.INFO), logLevel.compareTo(Level.INFO) == 0);
        info.addActionListener(actionEvent -> {
            preferences.setSetting(Globals.PREF_LOG_LEVEL, Level.INFO);
        });

        logLevelGroup.add(debug);
        logLevelGroup.add(info);
        JMenu logLevelMenu = new JMenu("Log Level");
        logLevelMenu.add(debug);
        logLevelMenu.add(info);

        this.add(logLevelMenu);
    }
}
