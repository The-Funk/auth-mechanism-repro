package com.jlg;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.logging.Log;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;

import org.eclipse.microprofile.config.ConfigProvider;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;

@ApplicationScoped
@Alternative
@Priority(1)
public class AppKeyAuthMechanism implements HttpAuthenticationMechanism {

    private static final String APP_KEY_HEADER = "x-application-key";

    protected static final ChallengeData UNAUTHORIZED_CHALLENGE = new ChallengeData(
            HttpResponseStatus.UNAUTHORIZED.code(),
            HttpHeaderNames.WWW_AUTHENTICATE, APP_KEY_HEADER);

    private static final HttpCredentialTransport APP_KEY_TRANSPORT =
            new HttpCredentialTransport(HttpCredentialTransport.Type.OTHER_HEADER, APP_KEY_HEADER);

    private static final String config_app_key =
            ConfigProvider.getConfig().getValue("security.app.key", String.class);

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {

        Log.info("authenticate from AppKeyAuthMechanism now running.");
        String appKey = context.request().getHeader(APP_KEY_HEADER);

        // Account for null value/missing header
        if (appKey == null) {
            Log.info("Missing Key!");
            return Uni.createFrom().failure(
                    new AuthenticationFailedException("Service-to-Service Authentication failed. Missing key."));
        }

        // Account for bad key
        if (!appKey.equals(config_app_key)) {
            Log.info("Bad Key!");
            return Uni.createFrom().failure(
                    new AuthenticationFailedException("Service-to-Service Authentication failed. Bad key."));
        }

        // If we didn't throw, then the key is good. Create an anonymous identity with all the roles.
        var identity = QuarkusSecurityIdentity.builder()
                .setAnonymous(true)
                .addRoles(Set.of("ROLE1","ROLE2","ROLE3"))
                .build();

        return Uni.createFrom().item(identity);
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        Log.info("getChallenge from AppKeyAuthMechanism now running.");
        String authHeader = context.request().headers().get(APP_KEY_HEADER);
        if (authHeader == null) {
            return Uni.createFrom().optional(Optional.empty());
        }
        return Uni.createFrom().item(UNAUTHORIZED_CHALLENGE);
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        Log.info("getCredentialTypes from AppKeyAuthMechanism now running.");
        return Collections.singleton(AppKeyAuthenticationRequest.class);
    }

    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        Log.info("getCredentialTransport from AppKeyAuthMechanism now running.");
        return Uni.createFrom().item(APP_KEY_TRANSPORT);
    }
}