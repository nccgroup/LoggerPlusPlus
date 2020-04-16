package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.util.SwingWorkerWithProgressDialog;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.util.List;

import static com.nccgroup.loggerplusplus.exports.CSVExporter.buildHeader;

public class CSVExporterControlPanel extends JPanel {

    private final CSVExporter csvExporter;

    CSVExporterControlPanel(CSVExporter csvExporter){
        this.csvExporter = csvExporter;
        this.setLayout(new BorderLayout());

        JButton manualSaveButton = new JButton("Export as CSV");
        manualSaveButton.addActionListener(actionEvent -> {
            handleManualSave();
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

        this.add(new PanelBuilder().build(new JComponent[][]{
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

    private void handleManualSave(){
        try {
            List<LogEntryField> fields = csvExporter.showFieldChooserDialog();
            File file = CSVExporter.getSaveFile("LoggerPlusPlus.csv");
            final boolean append;
            if (file.exists()) {
                append = CSVExporter.shouldAppendToExistingFile(file, fields);
            }else{
                append = true;
            }

            final List<LogEntry> entries = this.csvExporter.getExportController().getLoggerPlusPlus().getLogEntries();

            SwingWorkerWithProgressDialog<Void> importWorker = new SwingWorkerWithProgressDialog<Void>(JOptionPane.getFrameForComponent(this), "CSV Export", "Exporting as CSV...", entries.size()){
                @Override
                protected Void doInBackground() throws Exception {
                    super.doInBackground();
                    try(FileWriter fileWriter = new FileWriter(file, append)) {
                        if(!append) { //If we're not appending to existing file, add the header
                            fileWriter.append(buildHeader(fields));
                            fileWriter.flush();
                        }

                        for (int i = 0; i < entries.size(); i++) {
                            if(this.isCancelled()) break;
                            fileWriter.append("\n");
                            LogEntry entry = entries.get(i);
                            fileWriter.append(CSVExporter.entryToCSVString(entry, fields));
                            fileWriter.flush();
                            publish(i);
                        }
                    }

                    return null;
                }

                @Override
                protected void done() {
                    super.done();
                    JOptionPane.showMessageDialog(CSVExporterControlPanel.this, "Export as CSV completed.", "CSV Export", JOptionPane.INFORMATION_MESSAGE);
                }
            };

            importWorker.execute();

        }catch (Exception e){
            //Cancelled.
            e.printStackTrace();
        }
    }

}
