package com.nccgroup.loggerplusplus.grepper;

import com.nccgroup.loggerplusplus.logentry.LogEntry;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GrepResults {
    private final LogEntry entry;
    private int requestMatches = 0;
    private int responseMatches = 0;
    private ArrayList<Match> results;


    public GrepResults(Pattern pattern, LogEntry entry) {
        this.entry = entry;
        this.results = new ArrayList<>();

        processEntry(pattern);
    }

    public ArrayList<Match> getResults() {
        return results;
    }

    public Object getLogEntry() {
        return this.entry;
    }

    public int getRequestMatches() {
        return requestMatches;
    }

    public int getResponseMatches() {
        return responseMatches;
    }

    private void processEntry(Pattern pattern){
        if(entry.requestResponse != null){
            if(entry.requestResponse.getRequest() != null) {
                processMatches(pattern, entry.requestResponse.getRequest(), true);
            }
            if(entry.requestResponse.getResponse() != null) {
                processMatches(pattern, entry.requestResponse.getResponse(), false);
            }
        }
    }

    private void processMatches(Pattern pattern, byte[] content, boolean isRequest){
        final Matcher respMatcher = pattern.matcher(new String(content));
        while(respMatcher.find() && !Thread.currentThread().isInterrupted()){
            String[] groups = new String[respMatcher.groupCount()+1];
            for (int i = 0; i < groups.length; i++) {
                groups[i] = respMatcher.group(i);
            }

            if(isRequest) {
                requestMatches++;
            }else {
                responseMatches++;
            }
            results.add(new Match(groups, isRequest));
        }
    }

    public static class Match {
        public final String[] groups;
        public final boolean isRequest;

        Match(String[] groups, boolean isRequest){
            this.groups = groups;
            this.isRequest = isRequest;
        }
    }
}
