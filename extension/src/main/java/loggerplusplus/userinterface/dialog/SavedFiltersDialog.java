package loggerplusplus.userinterface.dialog;

import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.filter.SavedFilter;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.util.ArrayList;

/**
 * Created by corey on 22/08/17.
 */
public class SavedFiltersDialog extends JFrame{
    private static SavedFiltersDialog instance;
    ArrayList<SavedFilter> savedFilters;
    SavedFiltersTable filterTable;

    public SavedFiltersDialog(){
        if(instance != null) instance.dispose();
        instance = this;
        this.savedFilters = LoggerPlusPlus.getInstance().getLoggerPreferences().getSavedFilters();
        this.filterTable = new SavedFiltersTable(savedFilters);
        buildDialog();
        pack();

        this.addWindowListener(new WindowListener() {
            @Override
            public void windowOpened(WindowEvent windowEvent) {}
            @Override
            public void windowClosing(WindowEvent windowEvent) {}
            @Override
            public void windowClosed(WindowEvent windowEvent) {
                LoggerPlusPlus.getInstance().getLoggerPreferences().setSavedFilters(savedFilters);
            }
            @Override
            public void windowIconified(WindowEvent windowEvent) {}
            @Override
            public void windowDeiconified(WindowEvent windowEvent) {}
            @Override
            public void windowActivated(WindowEvent windowEvent) {}
            @Override
            public void windowDeactivated(WindowEvent windowEvent) {}
        });
    }

    private void buildDialog() {
        this.setLayout(new BorderLayout());
        this.setTitle("Saved Filters");
        JPanel content = new JPanel(new GridBagLayout());
        this.add(content, BorderLayout.CENTER);
        final JScrollPane filterListWrapper = new JScrollPane(filterTable);
        GridBagConstraints gbcFilterWrapper = new GridBagConstraints();
        gbcFilterWrapper.gridx = 0;
        gbcFilterWrapper.gridy = 0;
        gbcFilterWrapper.weighty = 999;
        gbcFilterWrapper.weightx = 999;
        gbcFilterWrapper.fill = GridBagConstraints.BOTH;
        this.setMinimumSize(filterTable.getMinimumSize());
        content.add(filterListWrapper, gbcFilterWrapper);

        GridBagConstraints gbcFooter = new GridBagConstraints();
        gbcFooter.gridx = 0;
        gbcFooter.gridy = 1;
        gbcFooter.fill = GridBagConstraints.BOTH;
        gbcFooter.weighty = gbcFooter.weightx = 1;
        gbcFooter.gridwidth = 2;
        JPanel buttonPanel = new JPanel(new BorderLayout());
        JPanel deleteButtonPanel = new JPanel(new BorderLayout());
        JButton btnDeleteAll = new JButton("Delete All");
        btnDeleteAll.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                ((SavedFiltersTableModel) filterTable.getModel()).removeAll();
            }
        });
        JButton btnDeleteSelected = new JButton("Delete Selected");
        btnDeleteSelected.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                filterTable.removeSelected();
            }
        });

        JPanel rightPanel = new JPanel(new BorderLayout());
        JButton btnAddFilter = new JButton("Add Filter");
        btnAddFilter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                ((SavedFiltersTableModel) filterTable.getModel()).addFilter(new SavedFilter());
            }
        });
        JButton btnClose = new JButton("Close");
        final JFrame _this = this;
        btnClose.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                _this.dispose();
            }
        });
        deleteButtonPanel.add(btnDeleteAll, BorderLayout.WEST);
        deleteButtonPanel.add(btnDeleteSelected, BorderLayout.EAST);
        rightPanel.add(btnAddFilter, BorderLayout.WEST);
        rightPanel.add(btnClose, BorderLayout.EAST);
        buttonPanel.add(deleteButtonPanel, BorderLayout.WEST);
        buttonPanel.add(rightPanel, BorderLayout.EAST);
        content.add(buttonPanel, gbcFooter);
    }


}
