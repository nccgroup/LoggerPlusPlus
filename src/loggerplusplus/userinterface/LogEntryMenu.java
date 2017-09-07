package loggerplusplus.userinterface;

import burp.BurpExtender;
import loggerplusplus.LogEntry;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.filter.CompoundFilter;
import loggerplusplus.filter.Filter;

import javax.swing.*;
import java.awt.event.ActionEvent;

/**
 * Created by corey on 24/08/17.
 */
public class LogEntryMenu extends JPopupMenu {

    LogEntryMenu(final LogTable logTable, final int row, final int col){
        final LogEntry entry = logTable.getModel().getRow(row);
        final String columnName = logTable.getColumnModel().getColumn(logTable.convertColumnIndexToView(col)).getName();
        final String columnValue = logTable.getModel().getValueAt(row, col).toString();
        final boolean isPro = BurpExtender.getCallbacks().getBurpVersion()[0].equals("Burp Suite Professional");
        String title = entry.getValueByKey(LogEntry.columnNamesType.URL).toString();
        if(title.length() > 50) title = title.substring(0, 47) + "...";
        this.add(new JMenuItem(new AbstractAction(title) {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {

            }
        }));
        this.add(new JPopupMenu.Separator());

        JMenuItem useAsFilter = new JMenuItem(new AbstractAction("Use " + columnName + " Value As Filter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                String value = "\"" + columnValue + "\"";
                try {
                    Filter filter = new Filter(columnName, "==", value);
                    BurpExtender.getLoggerInstance().setFilter(filter);
                } catch (Filter.FilterException e1) {return;}
            }
        });
        this.add(useAsFilter);

        if(logTable.getCurrentFilter() != null) {
            JMenu addToCurrentFilter = new JMenu("Add " + columnName + " Value To Filter");
            JMenuItem andFilter = new JMenuItem(new AbstractAction("AND") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    String value = "\"" + columnValue + "\"";
                    try {
                        Filter rFilter = new Filter(columnName, "==", value);
                        Filter filter = new CompoundFilter(logTable.getCurrentFilter(), "&&", rFilter);
                        BurpExtender.getLoggerInstance().setFilter(filter);
                    } catch (Filter.FilterException e1) {
                        return;
                    }
                }
            });
            JMenuItem orFilter = new JMenuItem(new AbstractAction("OR") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    String value = "\"" + columnValue + "\"";
                    try {
                        Filter rFilter = new Filter(columnName, "==", value);
                        Filter filter = new CompoundFilter(logTable.getCurrentFilter(), "||", rFilter);
                        BurpExtender.getLoggerInstance().setFilter(filter);
                    } catch (Filter.FilterException e1) {
                        return;
                    }
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
                    colorFilter.setFilter(new Filter(columnName, "==", columnValue));
                    BurpExtender.getLoggerInstance().getLoggerPreferences().getColorFilters().put(colorFilter.getUid(), colorFilter);
                } catch (Filter.FilterException e1) {
                    return;
                }
            }
        });
        this.add(colorFilterItem);

        this.add(new JPopupMenu.Separator());
        final boolean inScope = BurpExtender.getCallbacks().isInScope(entry.url);
        JMenuItem scope = new JMenuItem(new AbstractAction((inScope ? "Remove from scope" : "Add to scope")) {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if(inScope)
                    BurpExtender.getCallbacks().excludeFromScope(entry.url);
                else
                    BurpExtender.getCallbacks().includeInScope(entry.url);
            }
        });
        this.add(scope);

        this.add(new JPopupMenu.Separator());

        JMenuItem spider = new JMenuItem(new AbstractAction("Spider from here") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                BurpExtender.getCallbacks().sendToSpider(entry.url);
            }
        });
        this.add(spider);

        JMenuItem activeScan = new JMenuItem(new AbstractAction("Do an active scan") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                BurpExtender.getCallbacks().doActiveScan(entry.host, entry.targetPort, entry.isSSL, entry.requestResponse.getRequest());
            }
        });
        this.add(activeScan);
        activeScan.setEnabled(isPro);

        JMenuItem passiveScan = new JMenuItem(new AbstractAction("Do a passive scan") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                BurpExtender.getCallbacks().doPassiveScan(entry.host, entry.targetPort, entry.isSSL, entry.requestResponse.getRequest(), entry.requestResponse.getResponse());
            }
        });
        passiveScan.setEnabled(entry.complete && isPro);
        this.add(passiveScan);

        this.add(new JPopupMenu.Separator());

        JMenuItem sendToRepeater = new JMenuItem(new AbstractAction("Send to Repeater") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                BurpExtender.getCallbacks().sendToRepeater(entry.host, entry.targetPort, entry.isSSL, entry.requestResponse.getRequest(), "L++");
            }
        });
        this.add(sendToRepeater);

        JMenuItem sendToIntruder = new JMenuItem(new AbstractAction("Send to Intruder") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                BurpExtender.getCallbacks().sendToIntruder(entry.host, entry.targetPort, entry.isSSL, entry.requestResponse.getRequest());
            }
        });
        this.add(sendToIntruder);

        JMenu sendToComparer = new JMenu("Send to Comparer");
        JMenuItem comparerRequest = new JMenuItem(new AbstractAction("Request") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                BurpExtender.getCallbacks().sendToComparer(entry.requestResponse.getRequest());
            }
        });
        sendToComparer.add(comparerRequest);
        JMenuItem comparerResponse = new JMenuItem(new AbstractAction("Response") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                BurpExtender.getCallbacks().sendToComparer(entry.requestResponse.getRequest());
            }
        });
        sendToComparer.add(comparerResponse);
        this.add(sendToComparer);

        this.add(new JPopupMenu.Separator());

        JMenuItem removeItem = new JMenuItem(new AbstractAction("Remove Item") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                logTable.getModel().removeRow(row);
            }
        });
        this.add(removeItem);

    }
}
