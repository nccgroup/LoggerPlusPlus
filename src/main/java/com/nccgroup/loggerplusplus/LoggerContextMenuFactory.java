package com.nccgroup.loggerplusplus;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
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

public class LoggerContextMenuFactory implements ContextMenuItemsProvider {
    
    public LoggerContextMenuFactory(){
    }

    @Override
    public List<JMenuItem> provideMenuItems(ContextMenuEvent event) {
        JMenuItem filterMenu = new JMenu("Logger++");

        //We're handling a message editor context menu
        //And we have a selection
        MessageEditorHttpRequestResponse requestResponse = event.messageEditorRequestResponse().orElseThrow();
        Range selectedRange = requestResponse.selectionOffsets().orElseThrow();
        HttpMessage target;

        final LogEntryField context;
        final byte[] selectedBytes;
        switch (event.invocationType()){
            case MESSAGE_EDITOR_REQUEST:
            case MESSAGE_VIEWER_REQUEST: {
                target = requestResponse.getRequestResponse().httpRequest();
                try {
                    if (selectedRange.startIndexInclusive() <= target.bodyOffset()) {
                        context = LogEntryField.REQUEST_HEADERS;
                    } else {
                        context = LogEntryField.REQUEST_BODY;
                    }
                    selectedBytes = Arrays.copyOfRange(target.asBytes().getBytes(), selectedRange.startIndexInclusive(),
                            selectedRange.endIndexExclusive());
                }catch (NullPointerException nPException){ return null; }
                break;
            }

            case MESSAGE_EDITOR_RESPONSE:
            case MESSAGE_VIEWER_RESPONSE: {
                target = requestResponse.getRequestResponse().httpResponse();
                try {
                    if (selectedRange.startIndexInclusive() <= target.bodyOffset()) {
                        context = LogEntryField.RESPONSE_HEADERS;
                    } else {
                        context = LogEntryField.RESPONSE_BODY;
                    }
                    selectedBytes = Arrays.copyOfRange(target.asBytes().getBytes(), selectedRange.startIndexInclusive(),
                            selectedRange.endIndexExclusive());
                } catch (NullPointerException nPException) {
                    return null;
                }
                break;
            }
            default:
                return null;
        }

        final LogTable logTable = LoggerPlusPlus.instance.getLogViewController().getLogTableController().getLogTable();
        String selectedText = StringEscapeUtils.escapeJava(new String(selectedBytes));

        JMenuItem useAsFilter = new JMenuItem(new AbstractAction("Use Selection As LogFilter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.instance.getLogViewController().getLogFilterController().setFilter(context.getFullLabel() +
                        " CONTAINS \"" + selectedText + "\"");
            }
        });

        filterMenu.add(useAsFilter);

        if(logTable.getCurrentFilter() != null) {
            JMenu addToCurrentFilter = new JMenu("Add Selection To LogFilter");
            JMenuItem andFilter = new JMenuItem(new AbstractAction("AND") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.instance.getLogViewController().getLogFilterController().setFilter(logTable.getCurrentFilter().toString() + " && "
                            + "" + context.getFullLabel() + " CONTAINS \"" + selectedText + "\"");
                }
            });

            JMenuItem andNotFilter = new JMenuItem(new AbstractAction("AND NOT") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.instance.getLogViewController().getLogFilterController().setFilter(logTable.getCurrentFilter().toString() + " && !("
                            + "" + context.getFullLabel() + " CONTAINS \"" + selectedText + "\")");
                }
            });

            JMenuItem orFilter = new JMenuItem(new AbstractAction("OR") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.instance.getLogViewController().getLogFilterController().setFilter(logTable.getCurrentFilter().toString() + " || "
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
                    colorFilter.setFilter(new LogFilter(LoggerPlusPlus.instance.getLibraryController(),
                            context.getFullLabel() + " CONTAINS \"" + selectedText + "\""));
                    HashMap<UUID,ColorFilter> colorFilters = LoggerPlusPlus.instance.getPreferencesController().getPreferences().getSetting(PREF_COLOR_FILTERS);
                    colorFilters.put(colorFilter.getUUID(), colorFilter);
                    new ColorFilterDialog(LoggerPlusPlus.instance.getLibraryController()).setVisible(true);
                } catch (ParseException e) {
                    return;
                }
            }
        });
        filterMenu.add(colorFilterItem);
        return Arrays.asList(filterMenu);
    }
}
