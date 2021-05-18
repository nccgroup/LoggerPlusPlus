package com.nccgroup.loggerplusplus.util.userinterface.dialog;

import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;

/**
 * Created by corey on 19/07/17.
 */
public class TagDialog extends JFrame {
    private static TagDialog instance;
    private final FilterLibraryController filterLibraryController;
    private final TagTable filterTable;

    public TagDialog(FilterLibraryController filterLibraryController) {
        if (instance != null) instance.dispose();
        instance = this;
        this.filterLibraryController = filterLibraryController;
        this.filterTable = new TagTable(filterLibraryController);
        buildDialog();
        pack();
    }

    private void buildDialog() {
        this.setLayout(new BorderLayout());
        this.setTitle("Log Tags");
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

        gbcFilterWrapper.gridx = 1;
        gbcFilterWrapper.weightx = 1;
        gbcFilterWrapper.fill = GridBagConstraints.HORIZONTAL;
        final JPanel priorityControls = new JPanel(new GridLayout(0, 1));
        priorityControls.add(new JButton(new AbstractAction("\u25B2") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                filterTable.moveSelectedUp();
            }
        }));
        priorityControls.add(new JButton(new AbstractAction("\u25BC") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                filterTable.moveSelectedDown();
            }
        }));
        content.add(priorityControls, gbcFilterWrapper);

        GridBagConstraints gbcFooter = new GridBagConstraints();
        gbcFooter.gridx = 0;
        gbcFooter.gridy = 1;
        gbcFooter.fill = GridBagConstraints.BOTH;
        gbcFooter.weighty = gbcFooter.weightx = 1;
        gbcFooter.gridwidth = 2;
        JPanel buttonPanel = new JPanel(new BorderLayout());
        JButton btnDeleteAll = new JButton("Delete All");
        btnDeleteAll.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                ((TagTableModel) filterTable.getModel()).removeAll();
            }
        });
        JPanel rightPanel = new JPanel(new BorderLayout());
        JButton btnAddFilter = new JButton("Add Tag");
        btnAddFilter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                ((TagTableModel) filterTable.getModel()).addTag(new Tag());
            }
        });
        JButton btnClose = new JButton("Close");
        btnClose.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                TagDialog.this.dispatchEvent(new WindowEvent(TagDialog.this, WindowEvent.WINDOW_CLOSING));
            }
        });
        rightPanel.add(btnAddFilter, BorderLayout.WEST);
        rightPanel.add(btnClose, BorderLayout.EAST);
        buttonPanel.add(btnDeleteAll, BorderLayout.WEST);
        buttonPanel.add(rightPanel, BorderLayout.EAST);
        content.add(buttonPanel, gbcFooter);

    }
}
