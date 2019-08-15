package loggerplusplus.userinterface;

import com.coreyd97.BurpExtenderUtilities.VariableViewPanel;
import loggerplusplus.Globals;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.userinterface.dialog.ColorFilterDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;

/**
 * Created by corey on 07/09/17.
 */
public class LoggerMenu extends javax.swing.JMenu {

    private JMenuItem popoutMainMenuItem;
    private JMenuItem popoutReqRespMenuItem;

    public LoggerMenu(){
        super(LoggerPlusPlus.instance.getTabCaption());
        JMenuItem colorFilters = new JMenuItem(new AbstractAction("Color Filters") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new ColorFilterDialog(LoggerPlusPlus.instance.getColorFilterListeners()).setVisible(true);
            }
        });
        this.add(colorFilters);

        JMenu viewMenu = new JMenu("View");
        VariableViewPanel.View currentView = LoggerPlusPlus.preferences.getSetting(Globals.PREF_LAYOUT);
        ButtonGroup bGroup = new ButtonGroup();
        JRadioButtonMenuItem viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.instance.getLogSplitPanel().setView(VariableViewPanel.View.VERTICAL);
            }
        });
        viewMenuItem.setSelected(currentView == VariableViewPanel.View.VERTICAL);
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.instance.getLogSplitPanel().setView(VariableViewPanel.View.HORIZONTAL);
            }
        });
        viewMenuItem.setSelected(currentView == VariableViewPanel.View.HORIZONTAL);
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.instance.getLogSplitPanel().setView(VariableViewPanel.View.TABS);
            }
        });
        viewMenuItem.setSelected(currentView == VariableViewPanel.View.TABS);
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        this.add(viewMenu);

        viewMenu = new JMenu("Request/Response View");
        VariableViewPanel.View currentReqRespView = LoggerPlusPlus.preferences.getSetting(Globals.PREF_MESSAGE_VIEW_LAYOUT);
        bGroup = new ButtonGroup();
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.instance.getReqRespPanel().setView(VariableViewPanel.View.VERTICAL);
            }
        });
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem.setSelected(currentReqRespView == VariableViewPanel.View.VERTICAL);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.instance.getReqRespPanel().setView(VariableViewPanel.View.HORIZONTAL);
            }
        });
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem.setSelected(currentReqRespView == VariableViewPanel.View.HORIZONTAL);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.instance.getReqRespPanel().setView(VariableViewPanel.View.TABS);
            }
        });
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem.setSelected(currentReqRespView == VariableViewPanel.View.TABS);
        this.add(viewMenu);

        JCheckBoxMenuItem debugOption = new JCheckBoxMenuItem("Debug");
        if(LoggerPlusPlus.preferences.getSetting(Globals.PREF_IS_DEBUG) != null) {
            debugOption.setSelected(LoggerPlusPlus.preferences.getSetting(Globals.PREF_IS_DEBUG));
        }
        debugOption.addActionListener((e) -> {
            Boolean currentSetting = LoggerPlusPlus.preferences.getSetting(Globals.PREF_IS_DEBUG);
            if(currentSetting == null) {
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_IS_DEBUG, true);
            }else{
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_IS_DEBUG, !currentSetting);
            }
        });
        this.add(debugOption);
    }
}
