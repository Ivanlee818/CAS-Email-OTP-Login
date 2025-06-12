package org.apereo.cas.config;

import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.AuthenticationSystemSupport;
import org.apereo.cas.authentication.EmailLoginAuthenticationHandler; // 导入自定义认证处理器
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.ServiceFactory; // New import: ServiceFactory
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.CasWebflowExecutionPlanConfigurer;
import org.apereo.cas.web.flow.EmailVerificationService; // 导入邮件服务
import org.apereo.cas.web.flow.action.EmailLoginAction; // 导入自定义Action
import org.apereo.cas.web.flow.configurer.CustomLoginWebflowConfigurer; // 导入自定义Webflow配置器
import org.springframework.beans.factory.ObjectProvider; // 用于延迟获取依赖
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean; // 可选，用于避免重复注册
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.execution.Action;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import javax.sql.DataSource;

/**
 * This is {@link EmailVerificationConfiguration}.
 * Wires in new beans and configurers for email verification login.
 * 邮箱验证码登录功能的Spring配置类。
 */
@AutoConfiguration
@EnableConfigurationProperties({CasConfigurationProperties.class})
public class EmailVerificationConfiguration {


//     @Bean
//    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
//        RedisTemplate<String, Object> template = new RedisTemplate<>();
//        template.setConnectionFactory(redisConnectionFactory);
//        return template;
//    }   
    // 邮箱验证码发送服务
    @Bean("emailVerificationService")
    public EmailVerificationService emailVerificationService(
            @Qualifier("dataSource")
            final DataSource dataSource,
            @Qualifier("redisTemplate") // 确保redisTemplate已正确配置并注入
            final RedisTemplate redisTemplate,
            final JavaMailSender javaMailSender,
            final CasConfigurationProperties casProperties,
            final MailProperties mailProperties) {
        return new EmailVerificationService(dataSource, redisTemplate, javaMailSender, casProperties, mailProperties);
    }

    // EmailLoginAction Bean，负责发送验证码和准备凭据
    @Bean("emailLoginAction")
    public Action emailLoginAction(
            @Qualifier("emailVerificationService")
            final EmailVerificationService emailVerificationService,
            @Qualifier("defaultAuthenticationSystemSupport") // 需要此bean来最终触发认证
            final AuthenticationSystemSupport authenticationSystemSupport,
            final CasConfigurationProperties casProperties, // New: Inject CasConfigurationProperties
            @Qualifier("webApplicationServiceFactory") // New: Inject ServiceFactory (assuming common CAS bean name)
            final ServiceFactory serviceFactory) {
        // EmailLoginAction现在同时接受emailVerificationService、authenticationSystemSupport、casProperties 和 serviceFactory
        return new EmailLoginAction(emailVerificationService, authenticationSystemSupport, casProperties, serviceFactory);
    }

    // EmailLoginAuthenticationHandler Bean，负责验证码和数据库用户验证
    @Bean
    @ConditionalOnMissingBean(name = "emailLoginAuthenticationHandler") // 如果已有同名Bean则不创建
    public AuthenticationHandler emailLoginAuthenticationHandler(
            final CasConfigurationProperties casProperties,
            @Qualifier("servicesManager")
            final ObjectProvider<ServicesManager> servicesManager, // 使用ObjectProvider延迟注入
            @Qualifier("principalFactory")
            final ObjectProvider<PrincipalFactory> principalFactory, // 使用ObjectProvider延迟注入
            @Qualifier("dataSource")
            final DataSource dataSource,
            @Qualifier("redisTemplate")
            final RedisTemplate redisTemplate) {

        final EmailLoginAuthenticationHandler handler = new EmailLoginAuthenticationHandler(
            "emailLoginAuthenticationHandler", // 唯一认证处理器名称
            servicesManager.getObject(),
            principalFactory.getObject(),
            10 // 认证处理器顺序，值越小优先级越高，可根据需要调整
        );
        handler.setRedisTemplate(redisTemplate);
        handler.setDataSource(dataSource);
        // 可选：从cas.properties中配置验证码过期时间和最大失败尝试次数
        // handler.setCodeExpirationMinutes(casProperties.getAuthn().getMfa().getEmail().getExpireMinutes());
        // handler.setMaxFailedAttempts(casProperties.getAuthn().getMfa().getEmail().getMaxAttempts());
        return handler;
    }

    // 将 EmailLoginAuthenticationHandler 注册到认证执行计划中
    @Bean
    public AuthenticationEventExecutionPlanConfigurer emailAuthenticationEventExecutionPlanConfigurer(
            @Qualifier("emailLoginAuthenticationHandler")
            final AuthenticationHandler emailLoginAuthenticationHandler) {
        return plan -> plan.registerAuthenticationHandler(emailLoginAuthenticationHandler);
    }

    // CustomLoginWebflowConfigurer Bean，用于扩展登录Webflow
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // 确保此Webflow配置器尽早运行，以注册其自定义状态
    public CasWebflowConfigurer customLoginWebflowConfigurer(
            @Qualifier("loginFlowRegistry")
            final FlowDefinitionRegistry loginFlowRegistry,
            final FlowBuilderServices flowBuilderServices,
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties) {
        return new CustomLoginWebflowConfigurer(flowBuilderServices,
                loginFlowRegistry, applicationContext, casProperties);
    }

    // 将 CustomLoginWebflowConfigurer 注册到Webflow执行计划中
    @Bean
    public CasWebflowExecutionPlanConfigurer customWebflowExecutionPlanConfigurer(
            @Qualifier("customLoginWebflowConfigurer")
            final CasWebflowConfigurer customLoginWebflowConfigurer) {
        return plan -> plan.registerWebflowConfigurer(customLoginWebflowConfigurer);
    }
}
