package com.nccgroup.loggerplusplus.logview.processor;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import com.nccgroup.loggerplusplus.logentry.LogEntry;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.function.Consumer;

public class EntryImportWorker extends SwingWorker<Void, Integer> {

    private final LogProcessor logProcessor;
    private final int originatingTool;
    private final List<IHttpRequestResponse> entries;
    private final Consumer<List<Integer>> interimConsumer;
    private final Runnable callback;
    private final boolean sendToAutoExporters;

    private EntryImportWorker(Builder builder){
        this.logProcessor = builder.logProcessor;
        this.originatingTool = builder.originatingTool;
        this.entries = builder.entries;
        this.interimConsumer = builder.interimConsumer;
        this.callback = builder.callback;
        this.sendToAutoExporters = builder.sendToAutoExporters;
    }

    @Override
    protected Void doInBackground() throws Exception {
        logProcessor.getEntryProcessExecutor().pause(); //Pause the processor, we don't want it mixing with our import.

        CountDownLatch countDownLatch = new CountDownLatch(entries.size());
        ThreadPoolExecutor entryImportExecutor = logProcessor.getEntryImportExecutor();
        for (int index = 0; index < entries.size(); index++) {
            if(entryImportExecutor.isShutdown() || this.isCancelled()) return null;
            final LogEntry logEntry = new LogEntry(originatingTool, entries.get(index));
            int finalIndex = index;
            entryImportExecutor.submit(() -> {
                if(this.isCancelled()) return;
                LogEntry result = logProcessor.processEntry(logEntry);
                if(result != null) {
                    logProcessor.addProcessedEntry(logEntry, sendToAutoExporters);
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
        private int originatingTool = IBurpExtenderCallbacks.TOOL_EXTENDER;
        private List<IHttpRequestResponse> entries;
        private Consumer<List<Integer>> interimConsumer;
        private Runnable callback;
        private boolean sendToAutoExporters = false;

        Builder(LogProcessor logProcessor){
            this.logProcessor = logProcessor;
        }

        public Builder setOriginatingTool(int originatingTool){
            this.originatingTool = originatingTool;
            return this;
        }

        public Builder setEntries(List<IHttpRequestResponse> entries) {
            this.entries = entries;
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