package com.nccgroup.loggerplusplus.logview.processor;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.nccgroup.loggerplusplus.logentry.ImportingLogEntryHttpRequestResponse;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import lombok.extern.log4j.Log4j2;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.function.Consumer;

@Log4j2
public class EntryImportWorker extends SwingWorker<Void, Integer> {

    private final LogProcessor logProcessor;
    private ToolType originatingTool;
    private final List<ProxyHttpRequestResponse> proxyEntries;
    private final List<ImportingLogEntryHttpRequestResponse> httpEntries;
    private final Consumer<List<Integer>> interimConsumer;
    private final Runnable callback;
    private final boolean sendToAutoExporters;

    private EntryImportWorker(Builder builder){
        this.logProcessor = builder.logProcessor;
        this.originatingTool = builder.originatingTool;
        this.proxyEntries = builder.proxyEntries;
        this.httpEntries = builder.httpEntries;
        this.interimConsumer = builder.interimConsumer;
        this.callback = builder.callback;
        this.sendToAutoExporters = builder.sendToAutoExporters;
    }

    @Override
    protected Void doInBackground() throws Exception {
        logProcessor.getEntryProcessExecutor().pause(); //Pause the processor, we don't want it mixing with our import.
        boolean isProxyEntries = proxyEntries.size() > 0;
        int count = isProxyEntries ? proxyEntries.size() : httpEntries.size();

        CountDownLatch countDownLatch = new CountDownLatch(count);
        ThreadPoolExecutor entryImportExecutor = logProcessor.getEntryImportExecutor();
        ImportingLogEntryHttpRequestResponse entry = null;
        for (int index = 0; index < count; index++) {
            if(entryImportExecutor.isShutdown() || this.isCancelled()) return null;
            HttpRequest request;
            HttpResponse response;

            if(isProxyEntries){
                request = proxyEntries.get(index).finalRequest();
                response = proxyEntries.get(index).originalResponse();
            }else{
                entry = httpEntries.get(index);
                request = entry.request();
                response = entry.response();

                //TODO review: do we want to keep the original tool of the entry?
                if (entry.getTool() != null) {
                    this.originatingTool = entry.getTool();
                }
            }
            final LogEntry logEntry = new LogEntry(originatingTool, request, response);

            if (!isProxyEntries) {
                // add extra log entry data back to the entry
                // might / not exist when not import from JSON
                if (entry.getRequestTime() != null) {
                    logEntry.setRequestDateTime(entry.getRequestTime());
                }
                if (entry.getResponseTime() != null) {
                    logEntry.setResponseDateTime(entry.getResponseTime());
                }
            }

            int finalIndex = index;
            ImportingLogEntryHttpRequestResponse finalEntry = entry;
            entryImportExecutor.submit(() -> {
                if(this.isCancelled()) return;
                LogEntry result = logProcessor.processEntry(logEntry);
                if(result != null) {
                    if (!isProxyEntries) {
                        // must be called after processing:
                        if (finalEntry.getComment() != null) {
                            result.setComment(finalEntry.getComment());
                        }
                        if (finalEntry.getListenInterface() != null) {
                            result.setListenerInterface(finalEntry.getListenInterface());
                        }
                        if (finalEntry.getRTT() != null) {
                            result.setRequestResponseDelay(finalEntry.getRTT());
                        }
                    }

                    logProcessor.addNewEntry(logEntry, sendToAutoExporters);
                }
                publish(finalIndex);
                countDownLatch.countDown();
            });
        }
        countDownLatch.await();
        return null;
    }

    @Override
    protected void process(List<Integer> chunks) {
        if(this.interimConsumer != null)
            interimConsumer.accept(chunks);
    }

    @Override
    protected void done() {
        logProcessor.getEntryProcessExecutor().resume();
        if(this.callback != null) callback.run();
        super.done();
    }

    public static class Builder {

        private final LogProcessor logProcessor;
        private ToolType originatingTool = ToolType.EXTENSIONS;
        private List<ProxyHttpRequestResponse> proxyEntries = new ArrayList<>();
        private List<ImportingLogEntryHttpRequestResponse> httpEntries = new ArrayList<>();
        private Consumer<List<Integer>> interimConsumer;
        private Runnable callback;
        private boolean sendToAutoExporters = false;

        Builder(LogProcessor logProcessor){
            this.logProcessor = logProcessor;
        }

        public Builder setOriginatingTool(ToolType originatingTool){
            this.originatingTool = originatingTool;
            return this;
        }

        public Builder setProxyEntries(List<ProxyHttpRequestResponse> entries) {
            this.proxyEntries.addAll(entries);
            this.httpEntries.clear();
            return this;
        }

        public Builder setHttpEntries(List<ImportingLogEntryHttpRequestResponse> entries) {
            this.httpEntries.addAll(entries);
            this.proxyEntries.clear();
            return this;
        }

        public Builder setInterimConsumer(Consumer<List<Integer>> interimConsumer) {
            this.interimConsumer = interimConsumer;
            return this;
        }

        public Builder setCallback(Runnable callback) {
            this.callback = callback;
            return this;
        }

        //Control if the imported entries should also be sent to exporters (e.g. ElasticSearch)
        //Prevents existing entries being re-exported
        public Builder setSendToAutoExporters(boolean autoExport) {
            this.sendToAutoExporters = autoExport;
            return this;
        }

        public EntryImportWorker build() {
            return new EntryImportWorker(this);
        }
    }
}