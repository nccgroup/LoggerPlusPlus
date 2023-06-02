package com.nccgroup.loggerplusplus.logview;

import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.exports.ContextMenuExportProvider;
import com.nccgroup.loggerplusplus.exports.ExportController;
import com.nccgroup.loggerplusplus.exports.LogExporter;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableController;
import lombok.extern.log4j.Log4j2;

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
@Log4j2
public class MultipleLogEntryMenu extends JPopupMenu {

    public MultipleLogEntryMenu(final LogTableController logTableController, final List<LogEntry> selectedEntries){
        final LogTable logTable = logTableController.getLogTable();
        final boolean isPro = LoggerPlusPlus.montoya.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL;

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
        ExportController exportController = LoggerPlusPlus.instance.getExportController();
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

        JMenuItem scanner = new JMenuItem(new AbstractAction("Crawl selected " + selectedEntries.size() + " urls") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                List<String> urls = selectedEntries.stream().map(logEntry -> logEntry.getUrl().toExternalForm()).toList();
                CrawlConfiguration config = CrawlConfiguration.crawlConfiguration(urls.toArray(String[]::new));
                Crawl crawl = LoggerPlusPlus.montoya.scanner().startCrawl(config);
            }
        });
        this.add(scanner);

        JMenuItem activeScan = new JMenuItem(new AbstractAction("Active scan selected " + selectedEntries.size() + " urls") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                AuditConfiguration auditConfiguration = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
                Audit scan = LoggerPlusPlus.montoya.scanner().startAudit(auditConfiguration);
                for (LogEntry selectedEntry : selectedEntries) {
                    scan.addRequestResponse(HttpRequestResponse.httpRequestResponse(selectedEntry.getRequest(), selectedEntry.getResponse()));
                }
            }
        });
        this.add(activeScan);
        activeScan.setEnabled(isPro);

        JMenuItem passiveScan = new JMenuItem(new AbstractAction("Passive scan selected " + selectedEntries.size() + " urls") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                AuditConfiguration auditConfiguration = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS);
                Audit scan = LoggerPlusPlus.montoya.scanner().startAudit(auditConfiguration);
                for (LogEntry selectedEntry : selectedEntries) {
                    scan.addRequestResponse(HttpRequestResponse.httpRequestResponse(selectedEntry.getRequest(), selectedEntry.getResponse()));
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
                    LoggerPlusPlus.montoya.repeater().sendToRepeater(entry.getRequest());
                }
            }
        });
        this.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem(new AbstractAction("Send " + selectedEntries.size() + " selected items to Intruder") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    LoggerPlusPlus.montoya.intruder().sendToIntruder(entry.getRequest());
                }
            }
        });
        this.add(sendToIntruder);

        JMenu sendToComparer = new JMenu("Send " + selectedEntries.size() + " selected items to Comparer");
        JMenuItem comparerRequest = new JMenuItem(new AbstractAction("Requests") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    LoggerPlusPlus.montoya.comparer().sendToComparer(entry.getRequest().toByteArray());
                }
            }
        });
        sendToComparer.add(comparerRequest);
        JMenuItem comparerResponse = new JMenuItem(new AbstractAction("Responses") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                for (LogEntry entry : selectedEntries) {
                    if (entry.isComplete()) { //Do not add entries without a response
                        LoggerPlusPlus.montoya.comparer().sendToComparer(entry.getResponse().toByteArray());
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
                    values.add(String.valueOf(item.getUrlString()));
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
