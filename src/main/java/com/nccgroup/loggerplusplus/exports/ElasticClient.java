package com.nccgroup.loggerplusplus.exports;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * The three calls the Elasticsearch export makes, over the JDK's own HTTP client: does an index
 * exist, create it, and add documents to it in bulk.
 *
 * <p>Elasticsearch's Java client did this before. It, and the HTTP client and JSON libraries it
 * brought, were two thirds of the extension's jar.
 */
final class ElasticClient {
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
    private final URI server;
    private final String authorization;

    /**
     * @param server the scheme, host and port, such as {@code http://127.0.0.1:9200}
     * @param authorization the value of the Authorization header, or null to send none
     */
    ElasticClient(URI server, String authorization) {
        this.server = server;
        this.authorization = authorization;
    }

    /** Creates the index unless it exists. */
    void ensureIndex(String index) throws IOException, InterruptedException {
        HttpResponse<String> exists =
                send(request("/" + index).method("HEAD", HttpRequest.BodyPublishers.noBody()));
        if (exists.statusCode() == 404) {
            requireSuccess(send(request("/" + index).PUT(HttpRequest.BodyPublishers.noBody())));
        } else {
            requireSuccess(exists);
        }
    }

    /**
     * Adds documents, each a JSON object as text, to the index in one request.
     *
     * @return the reason Elasticsearch gave for each document it refused; empty when all went in
     */
    List<String> bulkIndex(String index, List<String> documents)
            throws IOException, InterruptedException {
        // The bulk format: an action line then a document line, each ended by a newline.
        String action =
                "{\"index\":{\"_index\":" + new com.google.gson.JsonPrimitive(index) + "}}\n";
        StringBuilder body = new StringBuilder();
        for (String document : documents) {
            body.append(action).append(document).append('\n');
        }
        HttpResponse<String> response =
                send(
                        request("/_bulk")
                                .header("Content-Type", "application/x-ndjson")
                                .POST(
                                        HttpRequest.BodyPublishers.ofString(
                                                body.toString(), StandardCharsets.UTF_8)));
        requireSuccess(response);
        return refusals(response.body());
    }

    private static List<String> refusals(String bulkResponse) {
        List<String> reasons = new ArrayList<>();
        JsonObject result = JsonParser.parseString(bulkResponse).getAsJsonObject();
        if (!result.has("errors") || !result.get("errors").getAsBoolean()) {
            return reasons;
        }
        for (JsonElement item : result.getAsJsonArray("items")) {
            JsonObject outcome = item.getAsJsonObject().getAsJsonObject("index");
            if (outcome != null && outcome.has("error")) {
                JsonElement error = outcome.get("error");
                reasons.add(
                        error.isJsonObject() && error.getAsJsonObject().has("reason")
                                ? error.getAsJsonObject().get("reason").getAsString()
                                : error.toString());
            }
        }
        return reasons;
    }

    private HttpRequest.Builder request(String path) {
        HttpRequest.Builder builder =
                HttpRequest.newBuilder(server.resolve(path)).timeout(REQUEST_TIMEOUT);
        if (authorization != null) {
            builder.header("Authorization", authorization);
        }
        return builder;
    }

    private HttpResponse<String> send(HttpRequest.Builder request)
            throws IOException, InterruptedException {
        return http.send(
                request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static void requireSuccess(HttpResponse<String> response) throws IOException {
        if (response.statusCode() >= 300) {
            throw new IOException(
                    "Elasticsearch answered "
                            + response.statusCode()
                            + " to "
                            + response.request().method()
                            + " "
                            + response.request().uri()
                            + ": "
                            + response.body());
        }
    }
}
