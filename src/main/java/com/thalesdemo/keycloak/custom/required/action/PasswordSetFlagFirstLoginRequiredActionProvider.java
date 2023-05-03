package com.thalesdemo.keycloak.custom.required.action;

import static java.util.Arrays.asList;

import java.util.List;
import java.util.Map;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.UserModel;

public class PasswordSetFlagFirstLoginRequiredActionProvider implements
        RequiredActionProvider {

    private static final String PASSWORD_SET_FLAG = "password-set";
    private static final String PASSWORD_SET_STRING = "true";

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {

        UserModel user = context.getUser();

        Map<String, List<String>> attributes = user.getAttributes();
        List<String> list = attributes.get(PASSWORD_SET_FLAG);

        if (list == null || list.isEmpty()) {
            user.setAttribute(PASSWORD_SET_FLAG,
                    asList(PASSWORD_SET_STRING));
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        // NOOP
    }

    @Override
    public void processAction(RequiredActionContext context) {
        context.success();
    }
}