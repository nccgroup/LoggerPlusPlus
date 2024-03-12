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

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.utilities.Base64DecodingOptions;
import burp.api.montoya.utilities.Base64Utils;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.ImportingLogEntryHttpRequestResponse;
import com.nccgroup.loggerplusplus.logview.processor.EntryImportWorker;
import lombok.extern.log4j.Log4j2;
import com.google.gson.Gson;
import com.google.gson.JsonElement;

import javax.swing.*;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;

@Log4j2
public class LoggerImport {

    private static final String COMMENT_IMPORTED_MARKER = "[Imported from JSON]";

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
            log.error("LoggerImport-readFile: Error Opening File " + filename);
            return new ArrayList<String>();
        }
        try {
            String line;
            while ( (line = reader.readLine()) != null ) {
                lines.add(line);
            }
        } catch (IOException e) {
            log.error("LoggerImport-readFile: Error Reading Line");
            return new ArrayList<String>();
        }

        return lines;
    }

    public static ArrayList<ImportingLogEntryHttpRequestResponse> importWStalker() {
        ArrayList<String> lines;
        ArrayList<ImportingLogEntryHttpRequestResponse> requests = new ArrayList<>();

        String filename = getLoadFile();
        if ( filename.length() == 0 ) { // exit if no file selected
            return new ArrayList<>();
        }

        lines = readFile(filename);
        Iterator<String> i = lines.iterator();

        while (i.hasNext()) {
            try {
                String line = i.next();
                String[] v = line.split(","); // Format: "base64(request),base64(response),url"

                String url = v[3];
                Base64Utils b64Decoder = LoggerPlusPlus.montoya.utilities().base64Utils();
                HttpService httpService = HttpService.httpService(url);
                HttpRequest httpRequest = HttpRequest.httpRequest(httpService, b64Decoder.decode(v[0], Base64DecodingOptions.URL));
                HttpResponse httpResponse = HttpResponse.httpResponse(b64Decoder.decode(v[1], Base64DecodingOptions.URL));

                requests.add(new ImportingLogEntryHttpRequestResponse(
                        HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
                ));

            } catch (Exception e) {
                log.error("LoggerImport-importWStalker: Error Parsing Content");
                return new ArrayList<>();
            }
        }

        return requests;
    }

    public static ArrayList<ImportingLogEntryHttpRequestResponse> importZAP() {
        ArrayList<String> lines = new ArrayList<String>();
        ArrayList<ImportingLogEntryHttpRequestResponse> requests = new ArrayList<ImportingLogEntryHttpRequestResponse>();

        String filename = getLoadFile();
        if ( filename.length() == 0 ) { // exit if no file selected
            return new ArrayList<ImportingLogEntryHttpRequestResponse>();
        }

        lines = readFile(filename);
        Iterator<String> i = lines.iterator();

        // Format:
        // ===[0-9]+ ==========
        // REQUEST
        // <empty>
        // RESPONSE
        String reSeparator = "^=+ ?[0-9]+ ?=+$";
        String reResponse = "^HTTP/[0-9]\\.[0-9] [0-9]+ .*$";

        // Ignore first line, since it should be a separator
        if ( i.hasNext() ) {
            i.next();
        }

        boolean isRequest = true;
        String requestBuffer = "";
        String responseBuffer = "";
        String url = "";

        // Loop lines
        while (i.hasNext()) {
            String line = i.next();

            // Request and Response Ready
            if ( line.matches(reSeparator) || !i.hasNext() ) {
                // TODO: Remove one or two \n at the end of requestBuffer

                HttpService httpService = HttpService.httpService(url);
                HttpRequest httpRequest = HttpRequest.httpRequest(httpService, requestBuffer);
                HttpResponse httpResponse = HttpResponse.httpResponse(responseBuffer);

                requests.add(new ImportingLogEntryHttpRequestResponse(
                        HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse)
                ));

                // Reset content
                isRequest = true;
                requestBuffer = "";
                responseBuffer = "";
                url = "";

                continue;
            }

            // It's the beginning of a request
            if ( requestBuffer.length() == 0 ) {
                try {
                    // Expected format: "GET https://whatever/whatever.html HTTP/1.1"
                    String[] x = line.split(" ");
                    url = x[1];

                    URL u = new URL(url);
                    String path = u.getPath();
                    line = x[0] + " " + path + " " + x[2]; // fix the path in the request

                } catch (Exception e) {
                    log.error("importZAP: Wrong Path Format");
                    return new ArrayList<>();
                }
            }

            // It's the beginning of a response
            if ( line.matches(reResponse) ) {
                isRequest = false;
            }

            // Add line to the corresponding buffer
            if ( isRequest ) {
                requestBuffer += line;
                requestBuffer += "\n";
            } else {
                responseBuffer += line;
                responseBuffer += "\n";
            }
        }

        return requests;
    }

    public static ArrayList<ImportingLogEntryHttpRequestResponse> importFromExportedJson() {
        ArrayList<ImportingLogEntryHttpRequestResponse> requests = new ArrayList<>();

        String filename = getLoadFile();
        if ( filename.length() == 0 ) { // exit if no file selected
            return new ArrayList<>();
        }

        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(filename));
        } catch (FileNotFoundException e) {
            log.error("LoggerImport-readFile: Error Opening File " + filename);
            return new ArrayList<>();
        }

        // declare all required variables for re-use in runtime
        Gson gson = LoggerPlusPlus.gsonProvider.getGson();
        JsonArray arr = gson.fromJson(reader, JsonElement.class).getAsJsonArray();
        Base64Utils b64Decoder = LoggerPlusPlus.montoya.utilities().base64Utils();
        JsonObject obj, req, res, jsonEntry;
        HttpService httpService;
        HttpRequest httpRequest;
        HttpResponse httpResponse;
        HttpRequestResponse requestResponse = null;
        String url;
        String[] v = new String[2];
        ImportingLogEntryHttpRequestResponse logEntry;

        Iterator<JsonElement> iter = arr.iterator();
        StringBuilder comment = new StringBuilder();
        while (iter.hasNext()) {
            obj = iter.next().getAsJsonObject();
            req = obj.getAsJsonObject("Request");
            res = obj.getAsJsonObject("Response");

            url = req.get("URL").getAsString();
            v[0] = req.get("AsBase64").getAsString();
            v[1] = res.get("AsBase64").getAsString();

            try {
                httpService = HttpService.httpService(url);
                httpRequest = HttpRequest.httpRequest(httpService, b64Decoder.decode(v[0]));
                httpResponse = HttpResponse.httpResponse(b64Decoder.decode(v[1]));
                requestResponse = HttpRequestResponse.httpRequestResponse(httpRequest, httpResponse);
            } catch (Exception e) {
                log.error("LoggerImport-importFromExportedJson: Error Parsing Content", e);
            }

            logEntry = new ImportingLogEntryHttpRequestResponse(requestResponse);
            logEntry.setRequestTime(req.get("Time").getAsString());
            logEntry.setResponseTime(res.get("Time").getAsString());

            // might not exist
            if (req.has("Tool")) {
                logEntry.setTool(req.get("Tool").getAsString());
            }

            if (res.has("RTT")) {
                logEntry.setRTT(res.get("RTT").getAsInt());
            }

            jsonEntry = obj.getAsJsonObject("Entry");
            if (jsonEntry.has("ListenInterface")) {
                logEntry.setListenInterface(jsonEntry.get("ListenInterface").getAsString());
            }

            comment.setLength(0); // empty the string
            if (req.has("Comment")) {
                comment.append(req.get("Comment").getAsString());

                // prevent duplicated 'imported' marker
                if (comment.indexOf(COMMENT_IMPORTED_MARKER) == -1)
                {
                    comment.insert(0, " ");
                    comment.insert(0, COMMENT_IMPORTED_MARKER);
                }
            }
            else {
                comment.insert(0, COMMENT_IMPORTED_MARKER);
            }

            logEntry.setComment(comment.toString());

            requests.add(logEntry);
        }

        return requests;
    }

    //TODO Integrate progress bar with SwingWorkerWithProgressDialog
    public static boolean loadImported(ArrayList<ImportingLogEntryHttpRequestResponse> requests, Boolean sendToAutoExporters) {
        EntryImportWorker importWorker = LoggerPlusPlus.instance.getLogProcessor().createEntryImportBuilder()
                .setOriginatingTool(ToolType.EXTENSIONS)
                .setHttpEntries(requests)
                .setSendToAutoExporters(sendToAutoExporters)
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
