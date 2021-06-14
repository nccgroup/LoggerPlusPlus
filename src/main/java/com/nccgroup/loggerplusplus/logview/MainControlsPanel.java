package com.nccgroup.loggerplusplus.logview;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilterController;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.ColorFilterDialog;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.TagDialog;

import javax.swing.*;
import java.awt.*;

public class MainControlsPanel extends JPanel {
    
    private final LogFilterController logFilterController;

    public MainControlsPanel(LogFilterController logFilterController){
        super(new GridBagLayout());

        this.logFilterController = logFilterController;
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 0;
        gbc.weightx = 0;
        gbc.weighty = 1;

        this.add(new JLabel(" Filter: "), gbc);

        gbc.gridx = 1;
        gbc.weightx = 99.0;
        this.add(logFilterController.getFilterField(), gbc);

        final JButton tagsButton = new JButton("Tags");
        tagsButton.addActionListener(actionEvent -> new TagDialog(LoggerPlusPlus.instance.getLibraryController()).setVisible(true));

        gbc.gridx = 2;
        gbc.weightx = 0;
        this.add(tagsButton, gbc);

        final JButton colorFilterButton = new JButton("Colorize");
        colorFilterButton.addActionListener(actionEvent -> new ColorFilterDialog(LoggerPlusPlus.instance.getLibraryController()).setVisible(true));

        gbc.gridx = 3;
        gbc.weightx = 0;
        this.add(colorFilterButton, gbc);

        final JButton clearLogsButton = new JButton("Clear Logs");
        clearLogsButton.addActionListener(actionEvent ->
                logFilterController.getLogViewController().getLogTableController().reset());

        gbc.gridx = 4;
        gbc.weightx = 0;
        this.add(clearLogsButton, gbc);
    }


}
