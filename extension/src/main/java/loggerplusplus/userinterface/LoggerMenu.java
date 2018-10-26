package loggerplusplus.userinterface;

import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.LoggerPreferences;
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
        super(LoggerPlusPlus.getInstance().getTabCaption());
        LoggerPreferences loggerPreferences = LoggerPlusPlus.getInstance().getLoggerPreferences();
        JMenuItem colorFilters = new JMenuItem(new AbstractAction("Color Filters") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new ColorFilterDialog(LoggerPlusPlus.getInstance().getFilterListeners()).setVisible(true);
            }
        });
        this.add(colorFilters);

        popoutMainMenuItem = new JMenuItem(new AbstractAction("Pop Out Main Panel") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.getInstance().getMainPopOutPanel().toggle();
            }
        });
        this.add(popoutMainMenuItem);

        popoutReqRespMenuItem = new JMenuItem(new AbstractAction("Pop Out Request/Response Panel") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.getInstance().getReqRespPopOutPanel().toggle();
            }
        });
        this.add(popoutReqRespMenuItem);

        JMenu viewMenu = new JMenu("View");
        ButtonGroup bGroup = new ButtonGroup();
        JRadioButtonMenuItem viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.getInstance().getLogSplitPanel().setView(VariableViewPanel.View.VERTICAL);
            }
        });
        viewMenuItem.setSelected(loggerPreferences.getView() == VariableViewPanel.View.VERTICAL);
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.getInstance().getLogSplitPanel().setView(VariableViewPanel.View.HORIZONTAL);
            }
        });
        viewMenuItem.setSelected(loggerPreferences.getView() == VariableViewPanel.View.HORIZONTAL);
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.getInstance().getLogSplitPanel().setView(VariableViewPanel.View.TABS);
            }
        });
        viewMenuItem.setSelected(loggerPreferences.getView() == VariableViewPanel.View.TABS);
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        this.add(viewMenu);

        viewMenu = new JMenu("Request/Response View");
        bGroup = new ButtonGroup();
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.getInstance().getReqRespPanel().setView(VariableViewPanel.View.VERTICAL);
            }
        });
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem.setSelected(loggerPreferences.getReqRespView() == VariableViewPanel.View.VERTICAL);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.getInstance().getReqRespPanel().setView(VariableViewPanel.View.HORIZONTAL);
            }
        });
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem.setSelected(loggerPreferences.getReqRespView() == VariableViewPanel.View.HORIZONTAL);
        viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.getInstance().getReqRespPanel().setView(VariableViewPanel.View.TABS);
            }
        });
        viewMenu.add(viewMenuItem);
        bGroup.add(viewMenuItem);
        viewMenuItem.setSelected(loggerPreferences.getReqRespView() == VariableViewPanel.View.TABS);

        this.add(viewMenu);
    }

    public JMenuItem getPopoutMainMenuItem() {
        return popoutMainMenuItem;
    }

    public JMenuItem getPopoutReqRespMenuItem() {
        return popoutReqRespMenuItem;
    }
}
