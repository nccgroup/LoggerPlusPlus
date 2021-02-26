package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.ExecutionException;

public class ElasticExporterControlPanel extends JPanel {

    private final ElasticExporter elasticExporter;
    private static final String STARTING_TEXT = "Starting Elastic Exporter...";
    private static final String STOPPING_TEXT = "Stopping Elastic Exporter...";
    private static final String START_TEXT = "Start Elastic Exporter";
    private static final String STOP_TEXT = "Stop Elastic Exporter";

    public ElasticExporterControlPanel(ElasticExporter elasticExporter){
        this.elasticExporter = elasticExporter;
        this.setLayout(new BorderLayout());

        JButton showConfigDialogButton = new JButton(new AbstractAction("Configure Elastic Exporter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                new ElasticExporterConfigDialog(JOptionPane.getFrameForComponent(
                        ElasticExporterControlPanel.this), elasticExporter)
                        .setVisible(true);
            }
        });

        JToggleButton exportButton = new JToggleButton("Start Elastic Exporter");
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
                                JOptionPane.showMessageDialog(exportButton, "Could not start elastic exporter: " +
                                        exception.getMessage() + "\nSee the logs for more information.", "Elastic Exporter", JOptionPane.ERROR_MESSAGE);
                                StringWriter sw = new StringWriter();
                                exception.printStackTrace(new PrintWriter(sw));
                                elasticExporter.getExportController().getLoggerPlusPlus().getLoggingController().logError(sw.toString());
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


        this.setBorder(BorderFactory.createTitledBorder("Elastic Exporter"));
    }

    private void enableExporter() throws Exception {
        this.elasticExporter.getExportController().enableExporter(this.elasticExporter);
    }

    private void disableExporter() throws Exception {
        this.elasticExporter.getExportController().disableExporter(this.elasticExporter);
    }

    private boolean isExporterEnabled() {
        return this.elasticExporter.getExportController().getEnabledExporters().contains(this.elasticExporter);
    }

}
