package com.nccgroup.loggerplusplus.logview;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.userinterface.dialog.ColorFilterDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.util.HashMap;
import java.util.UUID;

import static com.nccgroup.loggerplusplus.util.Globals.PREF_COLOR_FILTERS;

/**
 * Created by corey on 24/08/17.
 */
public class LogEntryMenu extends JPopupMenu {

    public LogEntryMenu(final LogTable logTable, final int modelRow, final int modelColumn){
        final LogEntry entry = logTable.getModel().getRow(modelRow);
        final LogEntryField selectedField = (logTable.getColumnModel().getModelColumn(modelColumn)).getIdentifier();
        final String columnName = selectedField.getFullLabel();
        final Object columnValue = logTable.getModel().getValueAt(modelRow, modelColumn);
        final String columnValueString;

        if(columnValue != null){
            columnValueString = columnValue instanceof Number ?
                    columnValue.toString() : "\"" + columnValue + "\"";
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
                    LoggerPlusPlus.instance.getLogFilterController().setFilter(columnName + "==" + columnValueString);
                }
            });
            this.add(useAsFilter);

            if (logTable.getCurrentFilter() != null) {
                JMenu addToCurrentFilter = new JMenu("Add " + columnName + " Value To LogFilter");
                JMenuItem andFilter = new JMenuItem(new AbstractAction("AND") {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        LoggerPlusPlus.instance.getLogFilterController().setFilter("(" + logTable.getCurrentFilter().toString() + ") && " + columnName + " == " + columnValueString);
                    }
                });
                JMenuItem orFilter = new JMenuItem(new AbstractAction("OR") {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        LoggerPlusPlus.instance.getLogFilterController().setFilter("(" + logTable.getCurrentFilter().toString() + ") || " + columnName + " == " + columnValueString);
                    }
                });
                addToCurrentFilter.add(andFilter);
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
                        HashMap<UUID, ColorFilter> colorFilters = LoggerPlusPlus.preferences.getSetting(PREF_COLOR_FILTERS);
                        colorFilters.put(colorFilter.getUUID(), colorFilter);
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
        final boolean inScope = LoggerPlusPlus.callbacks.isInScope(entry.url);
        JMenuItem scope = new JMenuItem(new AbstractAction((inScope ? "Remove from scope" : "Add to scope")) {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if(inScope)
                    LoggerPlusPlus.callbacks.excludeFromScope(entry.url);
                else
                    LoggerPlusPlus.callbacks.includeInScope(entry.url);
            }
        });
        this.add(scope);

        this.add(new JPopupMenu.Separator());

        JMenuItem spider = new JMenuItem(new AbstractAction("Spider from here") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToSpider(entry.url);
            }
        });
        this.add(spider);

        JMenuItem activeScan = new JMenuItem(new AbstractAction("Do an active scan") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.doActiveScan(entry.host, entry.targetPort, entry.isSSL, entry.requestResponse.getRequest());
            }
        });
        this.add(activeScan);
        activeScan.setEnabled(isPro);

        JMenuItem passiveScan = new JMenuItem(new AbstractAction("Do a passive scan") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.doPassiveScan(entry.host, entry.targetPort, entry.isSSL, entry.requestResponse.getRequest(), entry.requestResponse.getResponse());
            }
        });
        passiveScan.setEnabled(entry.complete && isPro);
        this.add(passiveScan);

        this.add(new JPopupMenu.Separator());

        JMenuItem sendToRepeater = new JMenuItem(new AbstractAction("Send to Repeater") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToRepeater(entry.host, entry.targetPort, entry.isSSL, entry.requestResponse.getRequest(), "L++");
            }
        });
        this.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem(new AbstractAction("Send to Intruder") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToIntruder(entry.host, entry.targetPort, entry.isSSL, entry.requestResponse.getRequest());
            }
        });
        this.add(sendToIntruder);

        JMenu sendToComparer = new JMenu("Send to Comparer");
        JMenuItem comparerRequest = new JMenuItem(new AbstractAction("Request") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToComparer(entry.requestResponse.getRequest());
            }
        });
        sendToComparer.add(comparerRequest);
        JMenuItem comparerResponse = new JMenuItem(new AbstractAction("Response") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.callbacks.sendToComparer(entry.requestResponse.getRequest());
            }
        });
        sendToComparer.add(comparerResponse);
        this.add(sendToComparer);

        this.add(new JPopupMenu.Separator());

        JMenuItem removeItem = new JMenuItem(new AbstractAction("Remove Item") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                logTable.getModel().removeRow(modelRow);
            }
        });
        this.add(removeItem);
    }
}
