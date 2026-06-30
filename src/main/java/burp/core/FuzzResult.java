package burp.core;

import burp.api.montoya.http.message.HttpRequestResponse;

public class FuzzResult {
    public final HttpRequestResponse rr;
    public final long rttMs;

    public FuzzResult(HttpRequestResponse r, long ms) {
        this.rr = r;
        this.rttMs = ms;
    }
}
