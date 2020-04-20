package com.nccgroup.loggerplusplus.util;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.Collections;
import java.util.List;

public abstract class SwingWorkerWithProgressDialog<T> extends SwingWorker<T, Integer> {

    private final JProgressBar jProgressBar;
    private final JDialog dialog;

    public SwingWorkerWithProgressDialog(Frame dialogOwner, String title, String message, int progressBarMax){
        jProgressBar = new JProgressBar(0, progressBarMax);
        dialog = new JDialog(dialogOwner, title, false);
        JLabel messageLabel = new JLabel(message);
        JButton cancelButton = new JButton(new AbstractAction("Cancel") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                SwingWorkerWithProgressDialog.this.cancel(true);
            }
        });

        JPanel bodyPanel = PanelBuilder.build(new Component[][]{
                new Component[]{messageLabel, messageLabel},
                new Component[]{jProgressBar, cancelButton}
        }, new int[][]{
                new int[]{0, 0},
                new int[]{1, 0}
        }, Alignment.CENTER, 0.8, 0.8);

        dialog.add(bodyPanel);
        dialog.setResizable(false);
        dialog.pack();

        dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
    }

    @Override
    protected T doInBackground() throws Exception {
        dialog.setVisible(true);
        return null;
    }

    @Override
    protected void process(List<Integer> chunks) {
        jProgressBar.setValue(Collections.max(chunks));
    }

    @Override
    protected void done() {
        dialog.dispose();
        super.done();
    }
}
