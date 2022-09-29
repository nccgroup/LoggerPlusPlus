package com.nccgroup.loggerplusplus.logview;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.exports.ContextMenuExportProvider;
import com.nccgroup.loggerplusplus.exports.ExportController;
import com.nccgroup.loggerplusplus.exports.LogExporter;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableController;

import javax.swing.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Created by corey on 24/08/17.
 */
public class MultipleLogEntryMenu extends JPopupMenu {

    public MultipleLogEntryMenu(final LogTableController logTableController, final List<LogEntry> selectedEntries){
        final LogTable logTable = logTableController.getLogTable();
        final boolean isPro = LoggerPlusPlus.callbacks.getBurpVersion()[0].equals("Burp Suite Professional");

        this.add(new JMenuItem(selectedEntries.size() + " items"));
        this.add(new Separator());

        JMenuItem copySelectedDomains = new JMenu("Copy selected hostnames");
        copySelectedDomains.add(new JMenuItem(new AbstractAction("All") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                copySelected(selectedEntries, Scope.DOMAIN, false);
            }
        }));
        copySelectedDomains.add(new JMenuItem(new AbstractAction("Unique") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                copySelected(selectedEntries, Scope.DOMAIN, true);
            }
        }));
        this.add(copySelectedDomains);

        JMenuItem copySelectedPaths = new JMenu("Copy selected paths");
        copySelectedPaths.add(new JMenuItem(new AbstractAction("All") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                copySelected(selectedEntries, Scope.PATH, false);
            }
        }));
        copySelectedPaths.add(new JMenuItem(new AbstractAction("Unique") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                copySelected(selectedEntries, Scope.PATH, true);
            }
        }));
        this.add(copySelectedPaths);

        JMenuItem copySelectedUrls = new JMenu("Copy selected URLs");
        copySelectedUrls.add(new JMenuItem(new AbstractAction("All") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                copySelected(selectedEntries, Scope.URL, false);
            }
        }));
        copySelectedUrls.add(new JMenuItem(new AbstractAction("Unique") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                copySelected(selectedEntries, Scope.URL, true);
            }
        }));
        this.add(copySelectedUrls);

        JMenu exportMenu = new JMenu("Export entries as...");
        ExportController exportController = logTableController.getLogViewController().getLoggerPlusPlus().getExportController();
        for (LogExporter exporter : exportController.getExporters().values()) {
            if (exporter instanceof ContextMenuExportProvider) {
                JMenuItem item = ((ContextMenuExportProvider) exporter).getExportEntriesMenuItem(selectedEntries);
                if (item != null) exportMenu.add(item);
            }
        }

        if(exportMenu.getItemCount() > 0){
            this.add(new JPopupMenu.Separator());
            this.add(exportMenu);
        }

        this.add(new Separator());

        JMenuItem spider = new JMenuItem(new AbstractAction("Spider selected " + selectedEntries.size() + " urls") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    LoggerPlusPlus.callbacks.sendToSpider(entry.getUrl());
                }
            }
        });
        this.add(spider);

        JMenuItem activeScan = new JMenuItem(new AbstractAction("Active scan selected " + selectedEntries.size() + " urls") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    LoggerPlusPlus.callbacks.doActiveScan(entry.getHostname(), entry.getTargetPort(), entry.isSSL(), entry.getRequest());
                }
            }
        });
        this.add(activeScan);
        activeScan.setEnabled(isPro);

        JMenuItem passiveScan = new JMenuItem(new AbstractAction("Passive scan selected " + selectedEntries.size() + " urls") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    if (entry.isComplete()) { //Cannot scan entries without response
                        LoggerPlusPlus.callbacks.doPassiveScan(entry.getHostname(), entry.getTargetPort(), entry.isSSL(), entry.getRequest(), entry.getResponse());
                    }
                }
            }
        });
        passiveScan.setEnabled(isPro);
        this.add(passiveScan);

        this.add(new Separator());

        JMenuItem sendToRepeater = new JMenuItem(new AbstractAction("Send " + selectedEntries.size() + " selected items to Repeater") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    LoggerPlusPlus.callbacks.sendToRepeater(entry.getHostname(), entry.getTargetPort(), entry.isSSL(), entry.getRequest(), "L++");
                }
            }
        });
        this.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem(new AbstractAction("Send " + selectedEntries.size() + " selected items to Intruder") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    LoggerPlusPlus.callbacks.sendToIntruder(entry.getHostname(), entry.getTargetPort(), entry.isSSL(), entry.getRequest());
                }
            }
        });
        this.add(sendToIntruder);

        JMenu sendToComparer = new JMenu("Send " + selectedEntries.size() + " selected items to Comparer");
        JMenuItem comparerRequest = new JMenuItem(new AbstractAction("Requests") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    LoggerPlusPlus.callbacks.sendToComparer(entry.getRequest());
                }
            }
        });
        sendToComparer.add(comparerRequest);
        JMenuItem comparerResponse = new JMenuItem(new AbstractAction("Responses") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    if (entry.isComplete()) { //Do not add entries without a response
                        LoggerPlusPlus.callbacks.sendToComparer(entry.getResponse());
                    }
                }
            }
        });
        sendToComparer.add(comparerResponse);
        this.add(sendToComparer);

        this.add(new Separator());

        JMenuItem removeItem = new JMenuItem(new AbstractAction("Remove " + selectedEntries.size() + " selected items") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                //If we don't clear the selection, the table will select the next entry after row is deleted
                //This causes the request response viewer to change after each and slow the process.
                logTable.getSelectionModel().clearSelection();
                logTable.getModel().removeLogEntries(selectedEntries);
            }
        });
        this.add(removeItem);
    }

    enum Scope {URL, DOMAIN, PATH}
    private void copySelected(List<LogEntry> items, Scope scope, boolean onlyUnique){
        Clipboard clipboard = getToolkit().getSystemClipboard();
        Collection<String> values;
        if(onlyUnique) values = new LinkedHashSet<String>();
        else values = new LinkedList<>();
        for (LogEntry item : items) {
            switch (scope) {
                case URL:
                    values.add(String.valueOf(item.getUrl()));
                    break;
                case PATH:
                    values.add(item.getUrl().getPath());
                    break;
                case DOMAIN:
                    values.add(item.getHostname());
                    break;
            }
        }

        String result = values.stream().collect(Collectors.joining("\n"));
        clipboard.setContents(new StringSelection(result), null);
    }
}
