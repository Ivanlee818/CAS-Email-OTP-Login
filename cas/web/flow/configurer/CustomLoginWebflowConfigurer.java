package org.apereo.cas.web.flow.configurer;

import lombok.val;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.ActionState;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.ViewState;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.engine.Transition;
import org.springframework.webflow.engine.TransitionSet;
import org.springframework.webflow.engine.TransitionCriteria;
import org.springframework.webflow.execution.RequestContext;
import java.util.Iterator;

/**
 * Custom webflow configurer to add email verification login functionality.
 * This configurer extends the default login webflow and integrates the email/OTP flow.
 * 自定义Webflow配置器，用于添加邮箱验证码登录功能。
 */
public class CustomLoginWebflowConfigurer extends DefaultLoginWebflowConfigurer {

    private static final String ACTION_ID_EMAIL_LOGIN_ACTION = "emailLoginAction";
    private static final String STATE_ID_EMAIL_SUBMIT = "emailSubmit";
    private static final String STATE_ID_SEND_EMAIL_CODE = "sendEmailCode";
    private static final String STATE_ID_EMAIL_LOGIN_VIEW = "emailLoginView";

    public CustomLoginWebflowConfigurer(final FlowBuilderServices flowBuilderServices,
                                        final FlowDefinitionRegistry loginFlowRegistry,
                                        final ConfigurableApplicationContext applicationContext,
                                        final CasConfigurationProperties casProperties) {
        super(flowBuilderServices, loginFlowRegistry, applicationContext, casProperties);
    }

    @Override
    protected void doInitialize() {
        super.doInitialize();

        final Flow loginFlow = getLoginFlow();
        if (loginFlow != null) {
            createEmailLoginFlowStates(loginFlow);
            addEmailLoginTransition(loginFlow);
            createEmailSubmitAction(loginFlow);
            createSendEmailCodeAction(loginFlow);
            handleRealSubmitEmailFailure(loginFlow);
        }
    }

    /**
     * Creates email login related Webflow states and transitions.
     * @param flow The current login Webflow.
     */
    private void createEmailLoginFlowStates(final Flow flow) {
        // Create email verification code input view state
        final ViewState emailLoginView = createViewState(flow, STATE_ID_EMAIL_LOGIN_VIEW, "casEmailLoginView");

        // Add render actions to preserve messages when entering the view
        emailLoginView.getRenderActionList().add(createEvaluateAction("flowScope.email"));
        
        // Define transitions from the email login view
        emailLoginView.getTransitionSet().add(createTransition("sendCode", STATE_ID_SEND_EMAIL_CODE));
        emailLoginView.getTransitionSet().add(createTransition("emailSubmit", STATE_ID_EMAIL_SUBMIT));
        emailLoginView.getTransitionSet().add(createTransition(CasWebflowConstants.TRANSITION_ID_CANCEL, 
            CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM));
        
        // Add error transition to handle validation errors within the view
        emailLoginView.getTransitionSet().add(createTransition(CasWebflowConstants.TRANSITION_ID_ERROR, 
            STATE_ID_EMAIL_LOGIN_VIEW));
    }

    /**
     * Adds a transition from the main login form to the email login view.
     * @param loginFlow The current login Webflow.
     */
    private void addEmailLoginTransition(final Flow loginFlow) {
        final ViewState loginView = getState(loginFlow, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM, ViewState.class);

        if (loginView != null) {
            createTransitionForState(loginView, "emailLogin", STATE_ID_EMAIL_LOGIN_VIEW);
        }
    }

    /**
     * Creates the action state for the final email/OTP authentication submission.
     * @param flow The login flow.
     */
    private void createEmailSubmitAction(final Flow flow) {
        final ActionState emailSubmitActionState = createActionState(flow, STATE_ID_EMAIL_SUBMIT,
            createEvaluateAction(ACTION_ID_EMAIL_LOGIN_ACTION));

        // Configure transitions with proper message preservation
        createTransitionForState(emailSubmitActionState, CasWebflowConstants.TRANSITION_ID_SUCCESS,
            CasWebflowConstants.STATE_ID_REAL_SUBMIT);
        
        // Critical: Use a custom transition that preserves message context
        val errorTransition = createTransition(CasWebflowConstants.TRANSITION_ID_ERROR, STATE_ID_EMAIL_LOGIN_VIEW);
        // Add attributes to preserve message context (changed from getExecutionAttributes)
        errorTransition.getAttributes().put("preserveMessages", Boolean.TRUE);
        emailSubmitActionState.getTransitionSet().add(errorTransition);

        // Add other standard transitions
        createTransitionForState(emailSubmitActionState, CasWebflowConstants.TRANSITION_ID_WARN,
            CasWebflowConstants.STATE_ID_WARN);
        createTransitionForState(emailSubmitActionState, CasWebflowConstants.TRANSITION_ID_SUCCESS_WITH_WARNINGS,
            CasWebflowConstants.STATE_ID_SHOW_AUTHN_WARNING_MSGS);
        createTransitionForState(emailSubmitActionState, CasWebflowConstants.TRANSITION_ID_TICKET_GRANTING_TICKET_VALID,
            CasWebflowConstants.STATE_ID_SERVICE_CHECK);
        createTransitionForState(emailSubmitActionState, CasWebflowConstants.TRANSITION_ID_GENERATE_SERVICE_TICKET,
            CasWebflowConstants.STATE_ID_GENERATE_SERVICE_TICKET);
    }

    /**
     * Creates the action state for sending the email verification code.
     * @param flow The login flow.
     */
    private void createSendEmailCodeAction(final Flow flow) {
        final ActionState sendCodeActionState = createActionState(flow, STATE_ID_SEND_EMAIL_CODE,
            createEvaluateAction(ACTION_ID_EMAIL_LOGIN_ACTION));

        // Create transitions that preserve message context
        val successTransition = createTransition("success", STATE_ID_EMAIL_LOGIN_VIEW);
        successTransition.getAttributes().put("preserveMessages", Boolean.TRUE);
        sendCodeActionState.getTransitionSet().add(successTransition);
        
        val errorTransition = createTransition("error", STATE_ID_EMAIL_LOGIN_VIEW);
        errorTransition.getAttributes().put("preserveMessages", Boolean.TRUE);
        sendCodeActionState.getTransitionSet().add(errorTransition);
    }

    /**
     * Handles authentication failures from the 'realSubmit' state specifically for email login.
     * @param loginFlow The login flow.
     */
    private void handleRealSubmitEmailFailure(final Flow loginFlow) {
        val realSubmitState = getState(loginFlow, CasWebflowConstants.STATE_ID_REAL_SUBMIT);
        if (realSubmitState instanceof ActionState) {
            val actionState = (ActionState) realSubmitState;
            val transitionsToRemove = new TransitionSet();

            // Find and collect authentication failure transitions to remove
            for (final Transition transition : actionState.getTransitionSet()) {
                if (CasWebflowConstants.TRANSITION_ID_AUTHENTICATION_FAILURE.equals(transition.getId())) {
                    transitionsToRemove.add(transition);
                }
            }

            // Remove existing authentication failure transitions
            for (final Transition transition : transitionsToRemove) {
                actionState.getTransitionSet().remove(transition);
            }

            // Add custom authentication failure transition that checks credential type
            val authFailureTransition = createTransition(CasWebflowConstants.TRANSITION_ID_AUTHENTICATION_FAILURE, 
                STATE_ID_EMAIL_LOGIN_VIEW);
            authFailureTransition.getAttributes().put("preserveMessages", Boolean.TRUE);
            
            // Add a guard condition to only redirect email credentials to email login view
            // Create a custom TransitionCriteria instead of using createExpression directly
            authFailureTransition.setExecutionCriteria(new TransitionCriteria() {
                @Override
                public boolean test(RequestContext context) {
                    Object credential = context.getRequestScope().get("credential");
                    return credential != null && 
                           "EmailCodeLoginCredential".equals(credential.getClass().getSimpleName());
                }
            });
            
            actionState.getTransitionSet().add(authFailureTransition);
            
            // Add fallback transition for non-email credentials
            val defaultAuthFailureTransition = createTransition(CasWebflowConstants.TRANSITION_ID_AUTHENTICATION_FAILURE, 
                CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM);
            actionState.getTransitionSet().add(defaultAuthFailureTransition);
        }
    }
}
