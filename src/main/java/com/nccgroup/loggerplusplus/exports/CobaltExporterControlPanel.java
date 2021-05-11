package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.concurrent.ExecutionException;

public class CobaltExporterControlPanel extends JPanel {

    private final CobaltExporter cobaltExporter;
    private static final String STARTING_TEXT = "Starting Cobalt Exporter...";
    private static final String STOPPING_TEXT = "Stopping Cobalt Exporter...";
    private static final String START_TEXT = "Start Cobalt Exporter";
    private static final String STOP_TEXT = "Stop Cobalt Exporter";

    Logger logger = LogManager.getLogger(this);

    public CobaltExporterControlPanel(CobaltExporter cobaltExporter) {
        this.cobaltExporter = cobaltExporter;
        this.setLayout(new BorderLayout());

        JButton showConfigDialogButton = new JButton(new AbstractAction("Configure Cobalt Exporter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new CobaltExporterConfigDialog(JOptionPane.getFrameForComponent(
                        CobaltExporterControlPanel.this), cobaltExporter)
                        .setVisible(true);
            }
        });

        JToggleButton exportButton = new JToggleButton("Start Cobalt Exporter");
        exportButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                boolean buttonNowActive = exportButton.isSelected();
                exportButton.setEnabled(false);
                exportButton.setText(buttonNowActive ? STARTING_TEXT : STOPPING_TEXT);
                new SwingWorker<Boolean, Void>(){
                    Exception exception;

                    @Override
                    protected Boolean doInBackground() throws Exception {
                        boolean success = false;
                        try {
                            if (exportButton.isSelected()) {
                                enableExporter();
                            } else {
                                disableExporter();
                            }
                            success = true;
                        }catch (Exception e){
                            this.exception = e;
                        }
                        return success;
                    }

                    @Override
                    protected void done() {
                        try {
                            if(exception != null) {
                                JOptionPane.showMessageDialog(exportButton, "Could not start cobalt exporter: " +
                                        exception.getMessage() + "\nSee the logs for more information.", "Cobalt Exporter", JOptionPane.ERROR_MESSAGE);
                                logger.error("Could not start cobalt exporter.", exception);
                            }
                            Boolean success = get();
                            boolean isRunning = buttonNowActive ^ !success;
                            exportButton.setSelected(isRunning);
                            showConfigDialogButton.setEnabled(!isRunning);

                            exportButton.setText(isRunning ? STOP_TEXT : START_TEXT);

                        } catch (InterruptedException | ExecutionException e) {
                            e.printStackTrace();
                        }
                        exportButton.setEnabled(true);
                    }
                }.execute();
            }
        });

        if (isExporterEnabled()){
            exportButton.setSelected(true);
            exportButton.setText(STOP_TEXT);
            showConfigDialogButton.setEnabled(false);
        }


        this.add(PanelBuilder.build(new JComponent[][]{
                new JComponent[]{showConfigDialogButton},
                new JComponent[]{exportButton}
        }, new int[][]{
                new int[]{1},
                new int[]{1}
        }, Alignment.FILL, 1.0, 1.0), BorderLayout.CENTER);


        this.setBorder(BorderFactory.createTitledBorder("Cobalt Exporter"));
    }

    private void enableExporter() throws Exception {
        this.cobaltExporter.getExportController().enableExporter(this.cobaltExporter);
    }

    private void disableExporter() throws Exception {
        this.cobaltExporter.getExportController().disableExporter(this.cobaltExporter);
    }

    private boolean isExporterEnabled() {
        return this.cobaltExporter.getExportController().getEnabledExporters().contains(this.cobaltExporter);
    }

}
