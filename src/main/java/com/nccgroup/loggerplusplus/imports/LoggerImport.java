//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Originally Developed by Soroush Dalili (@irsdl)
// Maintained by Corey Arthur (@CoreyD97)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package com.nccgroup.loggerplusplus.imports;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.EntryImportWorker;

import burp.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.io.*;
import javax.swing.*;

public class LoggerImport {

    public static String getLoadFile() {
        JFileChooser chooser = null;
        chooser = new JFileChooser();
        chooser.setDialogTitle("Import File");
        int val = chooser.showOpenDialog(null);

        if (val == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile().getAbsolutePath();
        }

        return "";
    }

    public static ArrayList<String> readFile(String filename) {
        BufferedReader reader;
        ArrayList<String> lines = new ArrayList<String>();

        try {
            reader = new BufferedReader(new FileReader(filename));
        } catch (FileNotFoundException e) {
            LoggerPlusPlus.callbacks.printError("LoggerImport-readFile: Error Opening File " + filename);
            return new ArrayList<String>();
        }
        try {
            String line;
            while ( (line = reader.readLine()) != null ) {
                lines.add(line);
            }
        } catch (IOException e) {
            LoggerPlusPlus.callbacks.printError("LoggerImport-readFile: Error Reading Line");
            return new ArrayList<String>();
        }

        return lines;
    }

    public static ArrayList<IHttpRequestResponse> importWStalker() {
        ArrayList<String> lines = new ArrayList<String>();
        ArrayList<IHttpRequestResponse> requests = new ArrayList<IHttpRequestResponse>();
        
        String filename = getLoadFile();
        lines = readFile(filename);

        Iterator<String> i = lines.iterator();
        while (i.hasNext()) {
            try {
                String line = i.next();
                String[] v = line.split(","); // Format: "base64(request),base64(response),url"

                IExtensionHelpers helpers = LoggerPlusPlus.callbacks.getHelpers();
                byte[] request = helpers.base64Decode(v[0]);
                byte[] response = helpers.base64Decode(v[1]);
                String url = v[3];

                LoggerRequestResponse x = new LoggerRequestResponse(url, request, response);
                requests.add(x);

            } catch (Exception e) {
                LoggerPlusPlus.callbacks.printError("LoggerImport-importWStalker: Error Parsing Content");
                return new ArrayList<IHttpRequestResponse>();
            }
        }

        return requests;
    }

    public static ArrayList<IHttpRequestResponse> importZAP() {
        ArrayList<IHttpRequestResponse> requests = new ArrayList<IHttpRequestResponse>();
        return requests;
    }

    public static boolean loadImported(ArrayList<IHttpRequestResponse> requests) {
        EntryImportWorker importWorker = LoggerPlusPlus.instance.getLogProcessor().createEntryImportBuilder()
            .setOriginatingTool(IBurpExtenderCallbacks.TOOL_EXTENDER)
            .setEntries(requests)
            .setInterimConsumer(integers -> {
                //Optional
                //Outputs chunks of integers representing imported indices
                //May be used to update progress bar for example
            })
            .setCallback(() -> {
                //Optional
                //Called when all entries have been imported.
            }).build();
        importWorker.execute();

        return true;
    }
}