package com.nccgroup.loggerplusplus;

import com.coreyd97.BurpExtenderUtilities.PopOutPanel;
import com.nccgroup.loggerplusplus.about.AboutPanel;
import com.nccgroup.loggerplusplus.help.HelpPanel;
import com.nccgroup.loggerplusplus.util.Globals;

import javax.swing.*;
import java.awt.*;

public class MainViewController {
    
    private final JTabbedPane tabbedPane;
    private final PopOutPanel popOutWrapper;

    public MainViewController() {
        this.tabbedPane = new JTabbedPane();
        LoggerPlusPlus loggerPlusPlus = LoggerPlusPlus.instance;
        tabbedPane.addTab("View Logs", null, loggerPlusPlus.getLogViewController().getLogViewPanel(), null);
        tabbedPane.addTab("Filter Library", null, loggerPlusPlus.getLibraryController().getFilterLibraryPanel(), null);
        tabbedPane.addTab("Grep Values", null, loggerPlusPlus.getGrepperController().getGrepperPanel(), null);
        tabbedPane.addTab("Options", null, loggerPlusPlus.getPreferencesController().getPreferencesPanel(), null);
        tabbedPane.addTab("About", null, new AboutPanel(loggerPlusPlus.getPreferencesController().getPreferences()), null);
        tabbedPane.addTab("Help", null, new HelpPanel(), null);
        this.popOutWrapper = new PopOutPanel(LoggerPlusPlus.montoya, tabbedPane, Globals.APP_NAME);
    }

    public Component getUiComponent() {
        return popOutWrapper;
    }

    public JTabbedPane getTabbedPanel(){
        return tabbedPane;
    }

    public PopOutPanel getPopOutWrapper() {
        return popOutWrapper;
    }
}
