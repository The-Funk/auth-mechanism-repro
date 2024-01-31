package com.jlg;

import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.BaseAuthenticationRequest;

public class AppKeyAuthenticationRequest extends BaseAuthenticationRequest implements AuthenticationRequest {
    private final AppKeyCredential appkey;

    public AppKeyAuthenticationRequest(final AppKeyCredential appkey) {
        this.appkey = appkey;
    }

    public AppKeyCredential getToken() {
        return appkey;
    }
}