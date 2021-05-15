package com.nccgroup.loggerplusplus.grepper;

import com.nccgroup.loggerplusplus.logentry.LogEntry;

import java.util.ArrayList;

public class GrepResults {
    private final LogEntry entry;
    private final ArrayList<Match> results;
    private int requestMatches = 0;
    private int responseMatches = 0;


    public GrepResults(LogEntry entry) {
        this.entry = entry;
        this.results = new ArrayList<>();
    }

    public ArrayList<Match> getMatches() {
        return results;
    }

    public LogEntry getLogEntry() {
        return this.entry;
    }

    public void addRequestMatch(Match match) {
        this.results.add(match);
        this.requestMatches++;
    }

    public void addResponseMatch(Match match) {
        this.results.add(match);
        this.responseMatches++;
    }

    public int getRequestMatches() {
        return requestMatches;
    }

    public int getResponseMatches() {
        return responseMatches;
    }

    public static class Match {
        public final String[] groups;
        public final int startIndex;
        public final int endIndex;
        public final boolean isRequest;

        Match(String[] groups, boolean isRequest, int startIndex, int endIndex) {
            this.groups = groups;
            this.isRequest = isRequest;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }
    }
}
