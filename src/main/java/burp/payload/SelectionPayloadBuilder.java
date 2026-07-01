package burp.payload;

import burp.core.ExtensionContext;
import burp.core.Variant;
import burp.util.EncoderUtils;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;

public class SelectionPayloadBuilder {

    private final ExtensionContext ctx;

    public SelectionPayloadBuilder(ExtensionContext ctx) {
        this.ctx = ctx;
    }

    public List<Variant> build(HttpRequest baseReq, int start, int end) {
        List<Variant> out = new ArrayList<>();
        ByteArray rawReq  = baseReq.toByteArray();
        ByteArray before  = rawReq.subArray(0, start);
        ByteArray after   = rawReq.subArray(end, rawReq.length());
        String selected   = rawReq.subArray(start, end).toString();
        if (ctx.chkSelUrl.isSelected())
            out.add(createSelVar(baseReq.httpService(), before, after, "SEL: URL Enc", EncoderUtils.urlEncode(selected)));
        if (ctx.chkSelDoubleUrl.isSelected())
            out.add(createSelVar(baseReq.httpService(), before, after, "SEL: Double Enc", EncoderUtils.urlEncode(EncoderUtils.urlEncode(selected))));
        if (ctx.chkSelIis.isSelected())
            out.add(createSelVar(baseReq.httpService(), before, after, "SEL: IIS Unicode", EncoderUtils.iisUnicodeEncode(selected)));
        if (ctx.chkSelUtf.isSelected())
            out.add(createSelVar(baseReq.httpService(), before, after, "SEL: UTF-8 Fullwidth", selected.replace("/", "/%ef%bc%8f")));
        for (String p : ctx.txtSelCustom.getText().split("\\r?\\n"))
            if (!p.trim().isEmpty())
                out.add(createSelVar(baseReq.httpService(), before, after, "SEL: " + p.trim(), p.trim()));
        return out;
    }

    private static Variant createSelVar(HttpService s, ByteArray b, ByteArray a, String n, String p) {
        return new Variant(n, HttpRequest.httpRequest(s, b.withAppended(ByteArray.byteArray(p)).withAppended(a)));
    }
}
