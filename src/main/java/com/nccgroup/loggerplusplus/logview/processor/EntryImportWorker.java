package com.nccgroup.loggerplusplus.logview.processor;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.nccgroup.loggerplusplus.logentry.LogEntry;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.function.Consumer;

public class EntryImportWorker extends SwingWorker<Void, Integer> {

    private final LogProcessor logProcessor;
    private final ToolType originatingTool;
    private final List<ProxyHttpRequestResponse> proxyEntries;
    private final List<HttpRequestResponse> httpEntries;
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
        for (int index = 0; index < count; index++) {
            if(entryImportExecutor.isShutdown() || this.isCancelled()) return null;
            HttpRequest request;
            HttpResponse response;
            if(isProxyEntries){
                request = proxyEntries.get(index).finalRequest();
                response = proxyEntries.get(index).originalResponse();
            }else{
                request = httpEntries.get(index).request();
                response = httpEntries.get(index).response();
            }
            final LogEntry logEntry = new LogEntry(originatingTool, request, response);
            int finalIndex = index;
            entryImportExecutor.submit(() -> {
                if(this.isCancelled()) return;
                LogEntry result = logProcessor.processEntry(logEntry);
                if(result != null) {
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
        private List<HttpRequestResponse> httpEntries = new ArrayList<>();
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

        public Builder setHttpEntries(List<HttpRequestResponse> entries) {
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