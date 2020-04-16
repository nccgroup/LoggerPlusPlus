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

import java.net.URL;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;

import burp.IHttpRequestResponse;
import burp.IHttpService;

class ImportRequestResponse implements IHttpRequestResponse {

    private IHttpService service;
    private byte[] request;
    private byte[] response;
    private String comment;
    private String highlight;

    ImportRequestResponse(String url, byte[] req, byte[] res) {
        LoggerHttpService srv = new LoggerHttpService(url);
        setHttpService(srv);
        setRequest(req);
        setResponse(res);
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        request = message;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        response = message;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String c) {
        comment = c;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String color) {
        highlight = color;
    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        service = httpService;
    }

    private static class LoggerHttpService implements IHttpService {

        private String host;
        private int port;
        private String protocol;

        LoggerHttpService(String urlS) {
            URL url;
            try {
                url = new URL(urlS);
            } catch (Exception e) {
                LoggerPlusPlus.callbacks.printError("LoggerHttpService: Error Parsing URL: " + urlS);
                LoggerPlusPlus.callbacks.printError(e.toString());
                return;
            }

            host = url.getHost();
            protocol = url.getProtocol();
            port = url.getPort();

            if ( port < 1 ) {
                switch (protocol) {
                    case "http":
                        port = 80;
                        break;
                    case "https":
                        port = 443;
                        break;
                }
            }
        }

        @Override
        public String getHost() {
            return host;
        }

        @Override
        public int getPort() {
            return port;
        }

        @Override
        public String getProtocol() {
            return protocol;
        }

    }
}