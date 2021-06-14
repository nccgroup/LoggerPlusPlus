package com.nccgroup.loggerplusplus.exports;

import com.nccgroup.loggerplusplus.logentry.LogEntry;

import javax.swing.*;
import java.util.List;

public interface ContextMenuExportProvider {
    JMenuItem getExportEntriesMenuItem(List<LogEntry> entries);
}
