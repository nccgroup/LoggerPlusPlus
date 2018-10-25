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

    private JMenuItem popoutItem;

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

        popoutItem = new JMenuItem(new AbstractAction("Pop Out") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.getInstance().getPopoutPanel().toggle();
            }
        });
        this.add(popoutItem);

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

    public JMenuItem getPopoutItem() {
        return popoutItem;
    }
}
