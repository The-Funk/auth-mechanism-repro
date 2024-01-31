package com.jlg;

import io.quarkus.security.credential.Credential;

public class AppKeyCredential implements Credential {

    private final String key;

    public AppKeyCredential(final String key) {
        this.key = key;
    }

}
