package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;

public class CSVExporterControlPanel extends JPanel {

    private final CSVExporter csvExporter;

    CSVExporterControlPanel(CSVExporter csvExporter){
        this.csvExporter = csvExporter;
        this.setLayout(new BorderLayout());

        JButton manualSaveButton = new JButton("Export as CSV");
        manualSaveButton.addActionListener(actionEvent -> {
            final List<LogEntry> entries = LoggerPlusPlus.instance.getLogEntries();
            csvExporter.exportEntries(entries);
        });

        JToggleButton exportButton = new JToggleButton("Auto-export as CSV");
        exportButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                boolean newSelectedState = exportButton.isSelected();
                boolean operationSuccess = exportButton.isSelected() ? enableExporter() : disableExporter();
                exportButton.setSelected(!newSelectedState ^ operationSuccess);
            }
        });

        this.add(PanelBuilder.build(new JComponent[][]{
                new JComponent[]{manualSaveButton},
                new JComponent[]{exportButton}
        }, new int[][]{
                new int[]{1},
                new int[]{1}
        }, Alignment.FILL, 1.0, 1.0), BorderLayout.CENTER);

        this.setBorder(BorderFactory.createTitledBorder("CSV Exporter"));
    }

    private boolean enableExporter(){
        try {
            this.csvExporter.getExportController().enableExporter(this.csvExporter);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean disableExporter(){
        try{
            this.csvExporter.getExportController().disableExporter(this.csvExporter);
            return true;
        }catch (Exception e){
            return false;
        }
    }

}
