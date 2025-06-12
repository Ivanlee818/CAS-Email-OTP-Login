package org.apereo.cas.authentication;

import lombok.Setter;
import org.apereo.cas.authentication.credential.EmailCodeLoginCredential;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.services.ServicesManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;
import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Setter
public class EmailLoginAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Logger log = LoggerFactory.getLogger(EmailLoginAuthenticationHandler.class);
    private RedisTemplate<String, Object> redisTemplate;
    private DataSource dataSource;
    private long codeExpirationMinutes = 5;
    private int maxFailedAttempts = 5;

    public EmailLoginAuthenticationHandler(final String name, final ServicesManager servicesManager,
                                          final PrincipalFactory principalFactory, final Integer order) {
        super(name, servicesManager, principalFactory, order);
    }

    @Override
    protected AuthenticationHandlerExecutionResult doAuthentication(final Credential credential, final Service service)
            throws AuthenticationException {
        final EmailCodeLoginCredential emailCredential = (EmailCodeLoginCredential) credential;
        final String email = emailCredential.getId();
        final String verificationCode = emailCredential.getVerificationCode();

        try {
            if (email == null || email.trim().isEmpty() || verificationCode == null || verificationCode.trim().isEmpty()) {
                throw new FailedLoginException("Invalid email or verification code provided.");
            }

            final String trimmedEmail = email.trim();
            final String trimmedCode = verificationCode.trim();

            log.info("Starting authentication for email: [{}] with code: [{}]", trimmedEmail, trimmedCode);

            // 1. 验证邮箱格式
            if (!isValidEmail(trimmedEmail)) {
                throw new FailedLoginException("Invalid email format.");
            }

            // 2. 从Redis获取并验证验证码
            final String redisKey = "cas:email:code:" + trimmedEmail;
            log.debug("Looking for verification code in Redis with key: [{}]", redisKey);
            
            final Object storedCodeObj = redisTemplate.opsForValue().get(redisKey);
            final String storedCode = storedCodeObj != null ? storedCodeObj.toString() : null;
            
            log.debug("Retrieved stored code from Redis: [{}]", storedCode);
            log.debug("User provided code: [{}]", trimmedCode);

            if (storedCode == null) {
                log.warn("No verification code found in Redis for email: [{}]. Code may have expired.", trimmedEmail);
                throw new FailedLoginException("Verification code has expired or does not exist.");
            }

            if (!storedCode.equals(trimmedCode)) {
                final String attemptKey = "cas:email:attempts:" + trimmedEmail;
                Long attempts = redisTemplate.opsForValue().increment(attemptKey);
                if (attempts == null) {
                    attempts = 1L;
                }
                if (attempts == 1) { // Set expiry only for the first attempt in this window
                    redisTemplate.expire(attemptKey, codeExpirationMinutes, TimeUnit.MINUTES);
                }

                log.warn("Verification code mismatch for [{}]. Expected: [{}], Got: [{}]. Attempts: [{}].", 
                         trimmedEmail, storedCode, trimmedCode, attempts);

                if (attempts >= maxFailedAttempts) {
                    log.warn("Too many failed attempts for [{}]. Code disabled.", trimmedEmail);
                    redisTemplate.delete(redisKey); // Delete code to prevent further attempts
                    redisTemplate.delete(attemptKey); // Clean up attempts counter
                    throw new FailedLoginException("Too many failed attempts. Code disabled.");
                }
                throw new FailedLoginException("Verification code is incorrect. Attempts left: " + (maxFailedAttempts - attempts));
            }

            // 验证码验证成功，删除Redis中的验证码和尝试次数
            log.info("Verification code successfully validated for email: [{}]", trimmedEmail);
            redisTemplate.delete(redisKey);
            redisTemplate.delete("cas:email:attempts:" + trimmedEmail);
            log.debug("Cleaned up Redis keys for email: [{}]", trimmedEmail);

            // 3. 从数据库获取用户详细信息
            final JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
            final String sql = "SELECT userid, user_name, user_rights, user_email, mobile, disabled, expired FROM tbl_users1 WHERE user_email = ?";
            List<Map<String, Object>> users;
            try {
                users = jdbcTemplate.queryForList(sql, trimmedEmail);
                log.debug("Database query returned {} users for email: [{}]", users.size(), trimmedEmail);
            } catch (final Exception e) {
                log.error("Database query failed for email [{}]: {}", trimmedEmail, e.getMessage(), e);
                final Map<String, Throwable> errors = new HashMap<>();
                errors.put("DatabaseError", e);
                throw new AuthenticationException(errors);
            }

            if (users.isEmpty()) {
                log.warn("User with email [{}] not found in database.", trimmedEmail);
                throw new AccountNotFoundException("User not found in database.");
            }
            if (users.size() > 1) {
                log.error("Multiple accounts found for email [{}]. This indicates a data integrity issue.", trimmedEmail);
                throw new GeneralSecurityException("Multiple accounts associated with email. Contact administrator.");
            }

            final Map<String, Object> userRecord = users.get(0);
            log.debug("Retrieved user record: {}", userRecord);

            // 4. 检查用户账号状态
            final Boolean isDisabled = (Boolean) userRecord.get("disabled");
            final Boolean isExpired = (Boolean) userRecord.get("expired");

            if (Boolean.TRUE.equals(isDisabled)) {
                log.warn("Account [{}] is disabled.", trimmedEmail);
                throw new FailedLoginException("Account is disabled.");
            }
            if (Boolean.TRUE.equals(isExpired)) {
                log.warn("Account [{}] has expired.", trimmedEmail);
                throw new FailedLoginException("Account has expired.");
            }

            // 5. 构建认证结果 - 使用 'userid' 作为最终Principal ID
            final String principalId = (String) userRecord.get("userid");
            if (principalId == null || principalId.isEmpty()) {
                log.error("User record for email [{}] does not contain a 'userid'. Cannot establish principal.", trimmedEmail);
                throw new FailedLoginException("Missing user ID in database record.");
            }

            final Map<String, List<Object>> attributes = new HashMap<>();
            attributes.put("userid", List.of(userRecord.get("userid")));
            attributes.put("user_name", List.of(userRecord.get("user_name")));
            attributes.put("user_rights", List.of(userRecord.get("user_rights")));
            attributes.put("user_email", List.of(userRecord.get("user_email")));
            attributes.put("mobile", List.of(userRecord.get("mobile") != null ? userRecord.get("mobile") : ""));

            log.info("Successfully authenticated user [{}] with principal ID [{}]", trimmedEmail, principalId);

            try {
                return createHandlerResult(emailCredential,
                    this.principalFactory.createPrincipal(principalId, attributes),
                    new ArrayList<>());
            } catch (final Throwable t) {
                log.error("Failed to create principal for user [{}]: {}", principalId, t.getMessage(), t);
                final Map<String, Throwable> errors = new HashMap<>();
                errors.put("PrincipalCreationError", t);
                throw new AuthenticationException(errors);
            }

        } catch (final GeneralSecurityException e) {
            log.error("Email login handler failed for [{}]: {}", email, e.getMessage(), e);
            final Map<String, Throwable> errors = new HashMap<>();
            errors.put(e.getClass().getSimpleName(), e);
            throw new AuthenticationException(errors);
        } catch (final Exception e) {
            log.error("Unexpected error in email login handler for [{}]: {}", email, e.getMessage(), e);
            final Map<String, Throwable> errors = new HashMap<>();
            errors.put("UnexpectedAuthenticationError", e);
            throw new AuthenticationException(errors);
        }
    }

    @Override
    public boolean supports(final Credential credential) {
        return credential instanceof EmailCodeLoginCredential;
    }

    public void setCodeExpirationMinutes(final long codeExpirationMinutes) {
        this.codeExpirationMinutes = codeExpirationMinutes;
    }

    public void setMaxFailedAttempts(final int maxFailedAttempts) {
        this.maxFailedAttempts = maxFailedAttempts;
    }

    private boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }
}
