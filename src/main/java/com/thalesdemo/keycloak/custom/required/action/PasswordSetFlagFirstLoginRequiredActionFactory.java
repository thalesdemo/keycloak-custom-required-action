package com.thalesdemo.keycloak.custom.required.action;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class PasswordSetFlagFirstLoginRequiredActionFactory implements
        RequiredActionFactory {

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new PasswordSetFlagFirstLoginRequiredActionProvider();
    }

    @Override
    public void init(Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public String getId() {
        return "record-first-login-password-set-action";
    }

    @Override
    public String getDisplayText() {
        return "Password Set Flag First Login Action";
    }
}
