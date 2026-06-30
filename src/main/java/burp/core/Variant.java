package burp.core;

import burp.api.montoya.http.message.requests.HttpRequest;

public class Variant {
    public final String name;
    public final HttpRequest request;

    public Variant(String n, HttpRequest r) {
        this.name = n;
        this.request = r;
    }
}
