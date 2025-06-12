package org.apereo.cas.web.flow.action;

import lombok.RequiredArgsConstructor;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.credential.EmailCodeLoginCredential;
import org.apereo.cas.web.flow.EmailVerificationService; // 导入邮件服务
import org.apereo.cas.web.support.WebUtils;
import org.springframework.binding.message.MessageBuilder;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.apereo.cas.authentication.principal.Service; // 导入 Service 类
import org.apereo.cas.authentication.principal.ServiceFactory; // Import ServiceFactory
import org.apereo.cas.configuration.CasConfigurationProperties; // Import CasConfigurationProperties


import jakarta.servlet.http.HttpServletRequest; // 使用jakarta for CAS 7.x
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * Spring Webflow action to handle both sending of email verification code
 * and processing the email/code submission for authentication.
 * 根据Webflow事件ID处理邮件验证码的发送和提交认证。\
 */
// Removed @RequiredArgsConstructor to allow for manual constructor with all final fields
public class EmailLoginAction extends AbstractAction {

    // 注入EmailVerificationService用于发送验证码
    private final EmailVerificationService emailVerificationService;
    private static final Logger log = LoggerFactory.getLogger(EmailLoginAction.class);
    private final AuthenticationSystemSupport authenticationSystemSupport;
    private final CasConfigurationProperties casProperties; // New: Inject CasConfigurationProperties
    private final ServiceFactory serviceFactory; // New: Inject ServiceFactory


    // Manual constructor to accommodate new final fields
    public EmailLoginAction(final EmailVerificationService emailVerificationService,
                            final AuthenticationSystemSupport authenticationSystemSupport,
                            final CasConfigurationProperties casProperties,
                            final ServiceFactory serviceFactory) {
        this.emailVerificationService = emailVerificationService;
        this.authenticationSystemSupport = authenticationSystemSupport;
        this.casProperties = casProperties;
        this.serviceFactory = serviceFactory;
    }


    @Override
    protected Event doExecute(final RequestContext context) {
        final HttpServletRequest request = WebUtils.getHttpServletRequestFromExternalWebflowContext(context);
        final String eventId = context.getRequestParameters().get("_eventId"); // 获取事件ID

        final String email = request.getParameter("email");
        final String verificationCode = request.getParameter("verificationCode");

        // --- Start: Service URL Preservation Logic ---
        // Get the service from the current request context.
        // This will retrieve the service if it was passed in the initial URL.
        Service service = WebUtils.getService(context);

        // If the service is found, put it into the flow scope.
        // This makes it persistent across the current webflow execution.
        if (service != null) {
            log.debug("Service [{}] found in request, storing in flowScope.", service.getId());
            context.getFlowScope().put("service", service);
        } else {
            // If service is not found in the current request, try to retrieve it from flowScope
            // This handles cases where the service might have been set in a previous step
            // and needs to be available for subsequent actions in the flow.
            service = (Service) context.getFlowScope().get("service");
            if (service == null) { // Only if still null after checking flowScope
                // If no service is found anywhere, use the default redirect URL from cas.properties
                final String defaultRedirectUrl = casProperties.getView().getDefaultRedirectUrl();
                if (defaultRedirectUrl != null && !defaultRedirectUrl.isEmpty()) {
                    service = serviceFactory.createService(defaultRedirectUrl);
                    log.debug("No service found, using default redirect URL: [{}]", defaultRedirectUrl);
                    context.getFlowScope().put("service", service); // Store the default service in flowScope
                } else {
                    log.warn("No service found in request or flowScope, and cas.view.defaultRedirectUrl is not configured. Service will remain null.");
                }
            } else {
                log.debug("Service [{}] retrieved from flowScope. It should already be available for CAS components.", service.getId());
                // No explicit WebUtils.putService(context, service) needed here.
                // The presence in flowScope should be sufficient for WebUtils.getService() later.
            }
        }
        // --- End: Service URL Preservation Logic ---

        if (email == null || email.trim().isEmpty()) {
            context.getMessageContext().addMessage(new MessageBuilder().error().defaultText("请输入邮箱地址 / Please enter email address").build());
            return error();
        }

        if ("sendCode".equals(eventId)) {
            // 处理发送验证码的逻辑
            return handleSendCode(context, email.trim());
        } else if ("emailSubmit".equals(eventId)) {
            // 处理提交邮箱和验证码进行认证的逻辑
            if (verificationCode == null || verificationCode.trim().isEmpty()) {
                context.getMessageContext().addMessage(new MessageBuilder().error().defaultText("请输入验证码 / Please enter verification code").build());
                return error();
            }
            return handleSubmitCode(context, email.trim(), verificationCode.trim());
        } else {
            log.warn("未知事件ID: {}", eventId);
            context.getMessageContext().addMessage(new MessageBuilder().error().defaultText("未知操作 / Unknown operation").build());
            return error();
        }
    }

    /**
     * 处理发送验证码的逻辑。
     * Handles the logic for sending the verification code.
     * @param context the request context
     * @param email the email address
     * @return the event
     */
    private Event handleSendCode(final RequestContext context, final String email) {
        try {
            final boolean success = emailVerificationService.sendVerificationCode(email);

            if (success) {
                context.getMessageContext().addMessage(new MessageBuilder().info().defaultText(
                    "验证码已发送到您的邮箱，请查收 / Verification code sent to your email").build());
                context.getFlowScope().put("email", email); // 将邮箱存入FlowScope，方便后续提交时自动填充
                log.info("发送验证码操作成功：邮箱[{}]。", email);
                return success();
            } else {
                context.getMessageContext().addMessage(new MessageBuilder().error().defaultText(
                    "发送失败，请检查邮箱地址或稍后重试 / Failed to send, please check email or try later").build());
                log.error("发送验证码操作失败：邮箱[{}]。", email);
                return error();
            }
        } catch (final Exception e) {
            log.error("发送验证码时发生错误，邮箱[{}]: {}", email, e.getMessage(), e);
            context.getMessageContext().addMessage(new MessageBuilder().error().defaultText(
                "系统错误，请稍后重试 / System error, please try again later").build());
            return error();
        }
    }

    /**
     * 处理提交邮箱和验证码进行认证的逻辑。
     * Handles the logic for submitting the email and verification code for authentication.
     * @param context the request context
     * @param email the email address
     * @param verificationCode the verification code
     * @return the event
     */
    private Event handleSubmitCode(final RequestContext context, final String email, final String verificationCode) {
        // 创建自定义的凭据对象
        final EmailCodeLoginCredential credential = new EmailCodeLoginCredential(email, verificationCode);
        // 将凭据放入Webflow上下文，供后续的认证处理器（EmailLoginAuthenticationHandler）使用
        WebUtils.putCredential(context, credential);

        log.info("准备EmailCodeLoginCredential凭据用于邮箱[{}]的认证。", email);
        // 返回success事件，Webflow将根据配置转换到实际的认证提交状态（例如realSubmit）
        return success();
    }
}
