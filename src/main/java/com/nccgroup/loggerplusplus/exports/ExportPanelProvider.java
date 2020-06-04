package com.nccgroup.loggerplusplus.exports;

import javax.swing.*;

public interface ExportPanelProvider {
    /**
     * Build the control panel to be displayed in the preferences tab
     *
     * @return JComponent Component to be displayed
     */
    JComponent getExportPanel();
}
