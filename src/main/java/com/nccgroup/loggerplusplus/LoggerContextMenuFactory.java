package com.nccgroup.loggerplusplus;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.util.userinterface.dialog.ColorFilterDialog;
import org.apache.commons.text.StringEscapeUtils;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import static com.nccgroup.loggerplusplus.util.Globals.PREF_COLOR_FILTERS;

public class LoggerContextMenuFactory implements IContextMenuFactory {

    private final LoggerPlusPlus loggerPlusPlus;
    
    public LoggerContextMenuFactory(LoggerPlusPlus loggerPlusPlus){
        this.loggerPlusPlus = loggerPlusPlus;
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if(invocation == null) return null;
        JMenuItem filterMenu = new JMenu("Logger++");

        if (invocation.getSelectedMessages().length == 0 ||
                invocation.getSelectionBounds()[0] == invocation.getSelectionBounds()[1]) {
            return null;
        }

        final LogEntryField context;
        final byte[] selectedBytes;
        switch (invocation.getInvocationContext()){
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST: {
                try {
                    byte[] msg = invocation.getSelectedMessages()[0].getRequest();
                    if (LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(msg).getBodyOffset() > invocation.getSelectionBounds()[0]) {
                        context = LogEntryField.REQUEST_HEADERS;
                    } else {
                        context = LogEntryField.REQUEST_BODY;
                    }
                    selectedBytes = Arrays.copyOfRange(invocation.getSelectedMessages()[0].getRequest(),
                            invocation.getSelectionBounds()[0],invocation.getSelectionBounds()[1]);
                }catch (NullPointerException nPException){ return null; }
                break;
            }

            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE: {
                try {
                    byte[] msg = invocation.getSelectedMessages()[0].getResponse();
                    if (LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(msg).getBodyOffset() > invocation.getSelectionBounds()[0]) {
                        context = LogEntryField.RESPONSE_HEADERS;
                    } else {
                        context = LogEntryField.RESPONSE_BODY;
                    }
                    selectedBytes = Arrays.copyOfRange(invocation.getSelectedMessages()[0].getResponse(),
                            invocation.getSelectionBounds()[0], invocation.getSelectionBounds()[1]);
                } catch (NullPointerException nPException) {
                    return null;
                }
                break;
            }
            default:
                return null;
        }

        if (selectedBytes != null) System.out.println(new String(selectedBytes));

        final LogTable logTable = loggerPlusPlus.getLogViewController().getLogTableController().getLogTable();
        String selectedText = StringEscapeUtils.escapeJava(new String(selectedBytes));

        JMenuItem useAsFilter = new JMenuItem(new AbstractAction("Use Selection As LogFilter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPlusPlus.getLogViewController().getLogFilterController().setFilter(context.getFullLabel() +
                        " CONTAINS \"" + selectedText + "\"");
            }
        });

        filterMenu.add(useAsFilter);

        if(logTable.getCurrentFilter() != null) {
            JMenu addToCurrentFilter = new JMenu("Add Selection To LogFilter");
            JMenuItem andFilter = new JMenuItem(new AbstractAction("AND") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    loggerPlusPlus.getLogViewController().getLogFilterController().setFilter(logTable.getCurrentFilter().toString() + " && "
                            + "" + context.getFullLabel() + " CONTAINS \"" + selectedText + "\"");
                }
            });

            JMenuItem andNotFilter = new JMenuItem(new AbstractAction("AND NOT") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    loggerPlusPlus.getLogViewController().getLogFilterController().setFilter(logTable.getCurrentFilter().toString() + " && !("
                            + "" + context.getFullLabel() + " CONTAINS \"" + selectedText + "\")");
                }
            });

            JMenuItem orFilter = new JMenuItem(new AbstractAction("OR") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    loggerPlusPlus.getLogViewController().getLogFilterController().setFilter(logTable.getCurrentFilter().toString() + " || "
                            + context.getFullLabel() + " CONTAINS \"" + selectedText + "\"");
                }
            });
            addToCurrentFilter.add(andFilter);
            addToCurrentFilter.add(andNotFilter);
            addToCurrentFilter.add(orFilter);
            filterMenu.add(addToCurrentFilter);
        }

        JMenuItem colorFilterItem = new JMenuItem(new AbstractAction("Set Selection as Color LogFilter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    ColorFilter colorFilter = new ColorFilter();
                    colorFilter.setFilter(new LogFilter(loggerPlusPlus.getLibraryController(),
                            context.getFullLabel() + " CONTAINS \"" + selectedText + "\""));
                    HashMap<UUID,ColorFilter> colorFilters = loggerPlusPlus.getPreferencesController().getPreferences().getSetting(PREF_COLOR_FILTERS);
                    colorFilters.put(colorFilter.getUUID(), colorFilter);
                    new ColorFilterDialog(loggerPlusPlus.getLibraryController()).setVisible(true);
                } catch (ParseException e) {
                    return;
                }
            }
        });
        filterMenu.add(colorFilterItem);
        return Arrays.asList(filterMenu);
    }
}
