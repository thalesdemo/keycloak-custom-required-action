/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.thalesdemo.keycloak.custom.required.action;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:hello@onewelco.me">Cina Shaykhian</a>
 * @comments Mostly inspired on UpdatePassword.java from Keycloak, with a few
 *           modifications to satisfy the use case
 * @version $Revision: 2 $
 * 
 */
public class SafeNetOnboardingRequiredAction implements RequiredActionProvider, RequiredActionFactory {
    private static final Logger logger = Logger.getLogger(SafeNetOnboardingRequiredAction.class);
    private static final String REQUIRED_ACTION_ID = "safenet-mfa-onboarding";
    private static final String PASSWORD_SET_FLAG = "password-set";
    private static final String PASSWORD_SET_STRING = "true";

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {

        UserModel user = context.getUser();

        Map<String, List<String>> attributes = user.getAttributes();
        List<String> list = attributes.get(PASSWORD_SET_FLAG);

        if (list == null || list.isEmpty()) {
            user.addRequiredAction(REQUIRED_ACTION_ID);
        }

    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        Response challenge = context.form()
                .setAttribute("username", context.getAuthenticationSession().getAuthenticatedUser().getUsername())
                .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {

        UserModel user = context.getUser();

        Map<String, List<String>> attributes = user.getAttributes();
        List<String> list = attributes.get(PASSWORD_SET_FLAG);

        if (list != null && !list.isEmpty() && list.get(0).equalsIgnoreCase(PASSWORD_SET_STRING)) {
            logger.debug("User has already been onboarded: " + user.getUsername());
            return;
        }

        if (user.getRequiredActionsStream()
                .anyMatch(action -> action.equals(UserModel.RequiredAction.UPDATE_PASSWORD.name()))) {
            user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD.name());
        }

        EventBuilder event = context.getEvent();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        RealmModel realm = context.getRealm();

        KeycloakSession session = context.getSession();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        event.event(EventType.UPDATE_PASSWORD);
        String passwordNew = formData.getFirst("password-new");
        String passwordConfirm = formData.getFirst("password-confirm");

        EventBuilder errorEvent = event.clone().event(EventType.UPDATE_PASSWORD_ERROR)
                .client(authSession.getClient())
                .user(authSession.getAuthenticatedUser());

        if (Validation.isBlank(passwordNew)) {
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .addError(new FormMessage(Validation.FIELD_PASSWORD, Messages.MISSING_PASSWORD))
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_MISSING);
            return;
        } else if (!passwordNew.equals(passwordConfirm)) {
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .addError(new FormMessage(Validation.FIELD_PASSWORD_CONFIRM, Messages.NOTMATCH_PASSWORD))
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_CONFIRM_ERROR);
            return;
        }

        session.sessions().getUserSessionsStream(realm, user)
                .filter(s -> !Objects.equals(s.getId(), authSession.getParentSession().getId()))
                .collect(Collectors.toList()) // collect to avoid concurrent modification as backchannelLogout
                                              // removes the user sessions.
                .forEach(s -> {

                    AuthenticationManager.backchannelLogout(session, realm, s, session.getContext().getUri(),
                            context.getConnection(), context.getHttpRequest().getHttpHeaders(), true);
                    logger.info("User session " + s.getId() + " logged out after password update for user: "
                            + user.getUsername());
                });

        try {
            user.credentialManager().updateCredential(UserCredentialModel.password(passwordNew, false));
            logger.info("Password updated for user: " + user.getUsername());

            user.setAttribute(PASSWORD_SET_FLAG,
                    asList(PASSWORD_SET_STRING));

            user.removeRequiredAction(REQUIRED_ACTION_ID);

            String errorMessage = "Your password has been successfully updated, you must re-authenticate to access the application.";
            Response response = context.form()
                    .setError(errorMessage)
                    .createErrorPage(Response.Status.UNAUTHORIZED);
            context.challenge(response);

        } catch (ModelException me) {
            errorEvent.detail(Details.REASON, me.getMessage()).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .setError(me.getMessage(), me.getParameters())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            return;
        } catch (Exception ape) {
            errorEvent.detail(Details.REASON, ape.getMessage()).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setAttribute("username", authSession.getAuthenticatedUser().getUsername())
                    .setError(ape.getMessage())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            return;
        }
    }

    @Override
    public void close() {

    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getDisplayText() {
        return "SafeNet MFA Onboarding";
    }

    @Override
    public String getId() {
        return REQUIRED_ACTION_ID;
    }

    @Override
    public boolean isOneTimeAction() {
        return true;
    }
}