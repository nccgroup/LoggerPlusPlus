package com.nccgroup.loggerplusplus.logview;

import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.exports.ContextMenuExportProvider;
import com.nccgroup.loggerplusplus.exports.ExportController;
import com.nccgroup.loggerplusplus.exports.LogExporter;
import com.nccgroup.loggerplusplus.filter.ComparisonOperator;
import com.nccgroup.loggerplusplus.filter.FilterExpression;
import com.nccgroup.loggerplusplus.filter.LogicalOperator;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableController;
import com.nccgroup.loggerplusplus.logview.processor.LogProcessor;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.ColorFilterDialog;
import lombok.extern.log4j.Log4j2;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Date;

/**
 * Created by corey on 24/08/17.
 */
@Log4j2
public class SingleLogEntryMenu extends JPopupMenu {

    public SingleLogEntryMenu(final LogTableController logTableController, final LogEntry entry, final LogEntryField selectedField) {
        final LogTable logTable = logTableController.getLogTable();
        final String columnName = selectedField.getFullLabel();
        final Object columnValue = entry.getValueByKey(selectedField);
        final String columnValueString;

        if (columnValue != null) {
            if (columnValue instanceof Date) {
                columnValueString = "\"" + LogProcessor.LOGGER_DATE_FORMAT.format(columnValue) + "\"";
            } else {
                columnValueString = columnValue instanceof Number ?
                        columnValue.toString() : "\"" + columnValue + "\"";
            }
        } else {
            columnValueString = "\"\"";
        }

        final boolean isPro = LoggerPlusPlus.montoya.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL;
        String title = entry.getValueByKey(LogEntryField.URL).toString();
        if (title.length() > 50) title = title.substring(0, 47) + "...";
        this.add(new JMenuItem(title));
        this.add(new JPopupMenu.Separator());

        if (selectedField != LogEntryField.NUMBER) {
            JMenuItem useAsFilter = new JMenuItem(new AbstractAction("Use " + columnName + " Value As LogFilter") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    logTableController.getLogViewController().getLogFilterController().setFilter(columnName + "==" + columnValueString);
                }
            });
            this.add(useAsFilter);

            if (logTable.getCurrentFilter() != null) {
                JMenu addToCurrentFilter = new JMenu("Add " + columnName + " Value To LogFilter");
                JMenuItem andFilter = new JMenuItem(new AbstractAction(LogicalOperator.AND.getLabel()) {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        try {
                            logTable.getCurrentFilter().getFilterExpression().addConditionToFilter(LogicalOperator.AND, selectedField, ComparisonOperator.EQUAL, columnValueString);
                            logTableController.getLogViewController().getLogFilterController().setFilter(logTable.getCurrentFilter());
                        } catch (ParseException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });

                JMenuItem andNotFilter = new JMenuItem(new AbstractAction("AND NOT") {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        try {
                            logTable.getCurrentFilter().getFilterExpression().addConditionToFilter(LogicalOperator.AND, selectedField, ComparisonOperator.NOT_EQUAL, columnValueString);
                            logTableController.getLogViewController().getLogFilterController().setFilter(logTable.getCurrentFilter());
                        } catch (ParseException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });

                JMenuItem orFilter = new JMenuItem(new AbstractAction(LogicalOperator.OR.getLabel()) {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        try {
                            logTable.getCurrentFilter().getFilterExpression().addConditionToFilter(LogicalOperator.OR, selectedField, ComparisonOperator.EQUAL, columnValueString);
                            logTableController.getLogViewController().getLogFilterController().setFilter(logTable.getCurrentFilter());
                        } catch (ParseException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
                addToCurrentFilter.add(andFilter);
                addToCurrentFilter.add(andNotFilter);
                addToCurrentFilter.add(orFilter);
                this.add(addToCurrentFilter);
            }

            JMenuItem colorFilterItem = new JMenuItem(new AbstractAction("Set " + columnName + " Value as Color Filter") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    TableColorRule tableColorRule = new TableColorRule("New Filter", columnName + " == " + columnValueString);
                    LoggerPlusPlus.instance.getLibraryController().addColorFilter(tableColorRule);
                    ColorFilterDialog colorFilterDialog = new ColorFilterDialog(LoggerPlusPlus.instance.getLibraryController());
                    colorFilterDialog.setVisible(true);
                }
            });
            this.add(colorFilterItem);
        }

        this.add(new JPopupMenu.Separator());
        final boolean inScope = LoggerPlusPlus.isUrlInScope(entry.getUrlString());
        JMenuItem scopeItem;
        if (!inScope) {
            scopeItem = new JMenu("Add to scope");
            scopeItem.add(new JMenuItem(new AbstractAction("Domain") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    try {
                        URL domainURL = new URL(entry.getProtocol(), entry.getHostname(), entry.getTargetPort(), "");
                        LoggerPlusPlus.montoya.scope().includeInScope(domainURL.toExternalForm());
                    } catch (MalformedURLException e) {
                        JOptionPane.showMessageDialog(scopeItem, "Could not build URL for scope entry. Sorry!", "Add to scope", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }));
            scopeItem.add(new JMenuItem(new AbstractAction("Domain + Path") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.montoya.scope().isInScope(entry.getUrlString());
                }
            }));
        } else {
            scopeItem = new JMenuItem(new AbstractAction("Remove from scope") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.montoya.scope().excludeFromScope(entry.getUrlString());
                }
            });
        }
        this.add(scopeItem);

        JMenu exportMenu = new JMenu("Export as...");
        ExportController exportController = LoggerPlusPlus.instance.getExportController();
        for (LogExporter exporter : exportController.getExporters().values()) {
            if (exporter instanceof ContextMenuExportProvider) {
                JMenuItem item = ((ContextMenuExportProvider) exporter).getExportEntriesMenuItem(Collections.singletonList(entry));
                if (item != null) exportMenu.add(item);
            }
        }

        if (exportMenu.getItemCount() > 0) {
            this.add(new JPopupMenu.Separator());
            this.add(exportMenu);
        }

        this.add(new JPopupMenu.Separator());

        JMenuItem spider = new JMenuItem(new AbstractAction("Crawl from here") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                CrawlConfiguration config = CrawlConfiguration.crawlConfiguration(entry.getUrl().toExternalForm());
                Crawl crawl = LoggerPlusPlus.montoya.scanner().startCrawl(config);
            }
        });
        this.add(spider);

        JMenuItem activeScan = new JMenuItem(new AbstractAction("Do an active scan") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                AuditConfiguration auditConfiguration = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
                Audit scan = LoggerPlusPlus.montoya.scanner().startAudit(auditConfiguration);
                scan.addRequestResponse(HttpRequestResponse.httpRequestResponse(entry.getRequest(), entry.getResponse()));
            }
        });
        this.add(activeScan);
        activeScan.setEnabled(isPro);

        JMenuItem passiveScan = new JMenuItem(new AbstractAction("Do a passive scan") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                AuditConfiguration auditConfiguration = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS);
                Audit scan = LoggerPlusPlus.montoya.scanner().startAudit(auditConfiguration);
                scan.addRequestResponse(HttpRequestResponse.httpRequestResponse(entry.getRequest(), entry.getResponse()));
            }
        });
        passiveScan.setEnabled(entry.isComplete() && isPro);
        this.add(passiveScan);

        this.add(new JPopupMenu.Separator());

        JMenuItem sendToRepeater = new JMenuItem(new AbstractAction("Send to Repeater") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.montoya.repeater().sendToRepeater(entry.getRequest());
            }
        });
        this.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem(new AbstractAction("Send to Intruder") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.montoya.intruder().sendToIntruder(entry.getRequest());
            }
        });
        this.add(sendToIntruder);

        JMenu sendToComparer = new JMenu("Send to Comparer");
        JMenuItem comparerRequest = new JMenuItem(new AbstractAction("Request") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.montoya.comparer().sendToComparer(entry.getRequest().toByteArray());
            }
        });
        sendToComparer.add(comparerRequest);
        JMenuItem comparerResponse = new JMenuItem(new AbstractAction("Response") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.montoya.comparer().sendToComparer(entry.getResponse().toByteArray());
            }
        });
        sendToComparer.add(comparerResponse);
        this.add(sendToComparer);

        this.add(new JPopupMenu.Separator());

        JMenuItem removeItem = new JMenuItem(new AbstractAction("Remove Item") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                logTable.getModel().removeLogEntry(entry);
            }
        });
        this.add(removeItem);
    }
}
