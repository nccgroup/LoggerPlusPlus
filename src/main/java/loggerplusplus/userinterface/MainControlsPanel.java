package loggerplusplus.userinterface;

import loggerplusplus.LogFilterController;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.userinterface.dialog.ColorFilterDialog;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

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

        this.add(new JLabel(" LogFilter: "), gbc);

        gbc.gridx = 1;
        gbc.weightx = 99.0;
        this.add(logFilterController.getFilterField(), gbc);

        final JButton colorFilterButton = new JButton("Colorize");
        colorFilterButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new ColorFilterDialog(LoggerPlusPlus.instance.getColorFilterListeners()).setVisible(true);
            }
        });

        gbc.gridx = 3;
        gbc.weightx = 0;
        this.add(colorFilterButton, gbc);

        final JButton clearLogsButton = new JButton("Clear Logs");
        clearLogsButton.addActionListener(actionEvent ->
                LoggerPlusPlus.instance.getLogManager().reset());

        gbc.gridx = 4;
        gbc.weightx = 0;
        this.add(clearLogsButton, gbc);
    }


}
