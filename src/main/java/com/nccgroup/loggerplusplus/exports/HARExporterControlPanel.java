package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class HARExporterControlPanel extends JPanel {
    HARExporterControlPanel(HARExporter harExporter) {
        this.setLayout(new BorderLayout());

        JButton manualSaveButton = new JButton("Export as HAR");
        manualSaveButton.addActionListener(actionEvent -> {
            final List<LogEntry> entries = LoggerPlusPlus.instance.getLogEntries();
            harExporter.exportEntries(entries);
        });

        this.add(PanelBuilder.build(new JComponent[][] { new JComponent[] { manualSaveButton }, },
                new int[][] { new int[] { 1 }, }, Alignment.FILL, 1.0, 1.0), BorderLayout.CENTER);

        this.setBorder(BorderFactory.createTitledBorder("HAR Exporter"));
    }
}