package com.nccgroup.loggerplusplus.logview;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.exports.ContextMenuExportProvider;
import com.nccgroup.loggerplusplus.exports.ExportController;
import com.nccgroup.loggerplusplus.exports.LogExporter;
import com.nccgroup.loggerplusplus.filter.ComparisonOperator;
import com.nccgroup.loggerplusplus.filter.LogicalOperator;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableController;
import com.nccgroup.loggerplusplus.logview.processor.LogProcessor;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.ColorFilterDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Date;

/**
 * Created by corey on 24/08/17.
 */
public class SingleLogEntryMenu extends JPopupMenu {

    public SingleLogEntryMenu(final LogTableController logTableController, final LogEntry entry, final LogEntryField selectedField){
        final LogTable logTable = logTableController.getLogTable();
        final String columnName = selectedField.getFullLabel();
        final Object columnValue = entry.getValueByKey(selectedField);
        final String columnValueString;

        if(columnValue != null){
            if(columnValue instanceof Date){
                columnValueString = "\"" + LogProcessor.LOGGER_DATE_FORMAT.format(columnValue) + "\"";
            }else {
                columnValueString = columnValue instanceof Number ?
                        columnValue.toString() : "\"" + columnValue + "\"";
            }
        }else{
            columnValueString = "\"\"";
        }

        final boolean isPro = LoggerPlusPlus.callbacks.getBurpVersion()[0].equals("Burp Suite Professional");
        String title = entry.getValueByKey(LogEntryField.URL).toString();
        if(title.length() > 50) title = title.substring(0, 47) + "...";
        this.add(new JMenuItem(title));
        this.add(new JPopupMenu.Separator());

        if(selectedField != LogEntryField.NUMBER) {
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
                        String newFilter = logTable.getCurrentFilter().addConditionToFilter(LogicalOperator.AND, selectedField, ComparisonOperator.EQUAL, columnValueString);
                        logTableController.getLogViewController().getLogFilterController().setFilter(newFilter);
                    }
                });

                JMenuItem andNotFilter = new JMenuItem(new AbstractAction("AND NOT") {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        String newFilter = logTable.getCurrentFilter().addConditionToFilter(LogicalOperator.AND, selectedField, ComparisonOperator.NOT_EQUAL, columnValueString);
                        logTableController.getLogViewController().getLogFilterController().setFilter(newFilter);
                    }
                });

                JMenuItem orFilter = new JMenuItem(new AbstractAction(LogicalOperator.OR.getLabel()) {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        String newFilter = logTable.getCurrentFilter().addConditionToFilter(LogicalOperator.OR, selectedField, ComparisonOperator.EQUAL, columnValueString);
                        logTableController.getLogViewController().getLogFilterController().setFilter(newFilter);
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
                    try {
                        ColorFilter colorFilter = new ColorFilter();
                        colorFilter.setFilter(new LogFilter(LoggerPlusPlus.instance.getLibraryController(),
                                columnName + " == " + columnValueString));
                        logTableController.getLogViewController().getLoggerPlusPlus().getLibraryController().addColorFilter(colorFilter);
                        ColorFilterDialog colorFilterDialog = new ColorFilterDialog(LoggerPlusPlus.instance.getLibraryController());
                        colorFilterDialog.setVisible(true);
                    } catch (ParseException e1) {
                        return;
                    }
                }
            });
            this.add(colorFilterItem);
        }

        this.add(new JPopupMenu.Separator());
        final boolean inScope = LoggerPlusPlus.callbacks.isInScope(entry.getUrl());
        JMenuItem scopeItem;
        if(!inScope){
            scopeItem = new JMenu("Add to scope");
            scopeItem.add(new JMenuItem(new AbstractAction("Domain") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    try {
                        URL domainURL = new URL(entry.getProtocol(), entry.getHostname(), entry.getTargetPort(), "");
                        LoggerPlusPlus.callbacks.includeInScope(domainURL);
                    } catch (MalformedURLException e) {
                        JOptionPane.showMessageDialog(scopeItem, "Could not build URL for scope entry. Sorry!", "Add to scope", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }));
            scopeItem.add(new JMenuItem(new AbstractAction("Domain + Path") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.callbacks.includeInScope(entry.getUrl());
                }
            }));
        }else{
            scopeItem = new JMenuItem(new AbstractAction("Remove from scope") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.callbacks.excludeFromScope(entry.getUrl());
                }
            });
        }
        this.add(scopeItem);

        JMenu exportMenu = new JMenu("Export as...");
        ExportController exportController = logTableController.getLogViewController().getLoggerPlusPlus().getExportController();
        for (LogExporter exporter : exportController.getExporters().values()) {
            if (exporter instanceof ContextMenuExportProvider) {
                JMenuItem item = ((ContextMenuExportProvider) exporter).getExportEntriesMenuItem(Collections.singletonList(entry));
                if (item != null) exportMenu.add(item);
            }
        }

        if(exportMenu.getItemCount() > 0){
            this.add(new JPopupMenu.Separator());
            this.add(exportMenu);
        }

        this.add(new JPopupMenu.Separator());

        JMenuItem spider = new JMenuItem(new AbstractAction("Spider from here") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToSpider(entry.getUrl());
            }
        });
        this.add(spider);

        JMenuItem activeScan = new JMenuItem(new AbstractAction("Do an active scan") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.doActiveScan(entry.getHostname(), entry.getTargetPort(), entry.isSSL(), entry.getRequest());
            }
        });
        this.add(activeScan);
        activeScan.setEnabled(isPro);

        JMenuItem passiveScan = new JMenuItem(new AbstractAction("Do a passive scan") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.doPassiveScan(entry.getHostname(), entry.getTargetPort(), entry.isSSL(), entry.getRequest(), entry.getResponse());
            }
        });
        passiveScan.setEnabled(entry.isComplete() && isPro);
        this.add(passiveScan);

        this.add(new JPopupMenu.Separator());

        JMenuItem sendToRepeater = new JMenuItem(new AbstractAction("Send to Repeater") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToRepeater(entry.getHostname(), entry.getTargetPort(), entry.isSSL(), entry.getRequest(), "L++");
            }
        });
        this.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem(new AbstractAction("Send to Intruder") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToIntruder(entry.getHostname(), entry.getTargetPort(), entry.isSSL(), entry.getRequest());
            }
        });
        this.add(sendToIntruder);

        JMenu sendToComparer = new JMenu("Send to Comparer");
        JMenuItem comparerRequest = new JMenuItem(new AbstractAction("Request") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToComparer(entry.getRequest());
            }
        });
        sendToComparer.add(comparerRequest);
        JMenuItem comparerResponse = new JMenuItem(new AbstractAction("Response") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToComparer(entry.getResponse());
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
