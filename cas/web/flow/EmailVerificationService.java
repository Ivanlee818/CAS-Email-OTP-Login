package org.apereo.cas.web.flow;

import lombok.RequiredArgsConstructor;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import javax.sql.DataSource;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RequiredArgsConstructor
public class EmailVerificationService {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Logger log = LoggerFactory.getLogger(EmailVerificationService.class);

    private final DataSource dataSource;
    private final RedisTemplate<String, Object> redisTemplate;
    private final JavaMailSender javaMailSender;
    private final CasConfigurationProperties casProperties;
    private final MailProperties mailProperties;
    private final SecureRandom secureRandom = new SecureRandom();

    private final long codeExpirationMinutes = 5; // 验证码有效分钟数

    public boolean sendVerificationCode(final String email) {
        if (!isValidEmail(email)) {
            log.warn("尝试向无效邮箱格式发送验证码: {}", email);
            return false;
        }

        final String trimmedEmail = email.trim();
        log.info("Processing verification code request for email: [{}]", trimmedEmail);

        // 1. 检查邮箱是否存在于数据库且未禁用/过期
        final JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        final String sql = "SELECT COUNT(*) FROM tbl_users1 WHERE user_email = ? AND (disabled IS NULL OR disabled = 0) AND (expired IS NULL OR expired = 0)";
        Integer count;
        try {
            count = jdbcTemplate.queryForObject(sql, Integer.class, trimmedEmail);
            log.debug("Database query result for email [{}]: {} active users found", trimmedEmail, count);
        } catch (final Exception e) {
            log.error("检查邮箱[{}]是否存在时数据库查询失败: {}", trimmedEmail, e.getMessage(), e);
            return false;
        }

        if (count == null || count == 0) {
            log.warn("尝试向不存在、已禁用或已过期的邮箱[{}]发送验证码。", trimmedEmail);
            // 出于安全考虑，不向用户透露邮箱是否存在。假装已发送成功。
            return true;
        }
        if (count > 1) {
            log.error("邮箱[{}]对应多个活跃用户，数据完整性问题。", trimmedEmail);
            return false; // 数据完整性问题，失败
        }

        // 2. 检查发送频率限制
        final String rateLimitKey = "cas:email:rate:" + trimmedEmail;
        if (Boolean.TRUE.equals(redisTemplate.hasKey(rateLimitKey))) {
            log.warn("邮箱[{}]的发送频率限制已触发，请稍后再试。", trimmedEmail);
            return false;
        }

        // 3. 生成并存储验证码到Redis
        final String verificationCode = generateVerificationCode();
        final String redisKey = "cas:email:code:" + trimmedEmail;
        
        log.info("Generated verification code [{}] for email [{}]", verificationCode, trimmedEmail);
        log.debug("Storing verification code in Redis with key: [{}]", redisKey);
        
        try {
            // Store as String to ensure consistent retrieval
            redisTemplate.opsForValue().set(redisKey, verificationCode, codeExpirationMinutes, TimeUnit.MINUTES);
            log.debug("验证码[{}]已为邮箱[{}]存储到Redis，过期时间{}分钟。", verificationCode, trimmedEmail, codeExpirationMinutes);
            
            // Verify storage by immediately retrieving
            Object storedValue = redisTemplate.opsForValue().get(redisKey);
            log.debug("Verification: stored value in Redis: [{}], type: [{}]", storedValue, storedValue != null ? storedValue.getClass().getSimpleName() : "null");
            
        } catch (final Exception e) {
            log.error("将验证码存储到Redis失败，邮箱[{}]: {}", trimmedEmail, e.getMessage(), e);
            return false;
        }

        // 4. 设置发送频率限制（60秒内不能重复发送）
        try {
            redisTemplate.opsForValue().set(rateLimitKey, "1", 60, TimeUnit.SECONDS);
            log.debug("设置邮件发送频率限制，邮箱[{}]", trimmedEmail);
        } catch (final Exception e) {
            log.error("设置邮件发送频率限制失败，邮箱[{}]: {}", trimmedEmail, e.getMessage(), e);
            // 这里的失败不应阻断邮件发送，但会影响频率控制。
        }

        // 5. 发送邮件
        try {
            sendEmail(trimmedEmail, verificationCode);
            log.info("验证码已成功发送至邮箱: {}", trimmedEmail);
            return true;
        } catch (final Exception e) {
            log.error("发送验证码邮件至邮箱[{}]失败: {}", trimmedEmail, e.getMessage(), e);
            // Clean up Redis if email sending fails
            try {
                redisTemplate.delete(redisKey);
                redisTemplate.delete(rateLimitKey);
                log.debug("Cleaned up Redis keys due to email sending failure for: [{}]", trimmedEmail);
            } catch (final Exception cleanupException) {
                log.error("Failed to clean up Redis keys after email failure: {}", cleanupException.getMessage());
            }
            return false;
        }
    }

    private String generateVerificationCode() {
        final int length = 6; // 验证码长度
        final StringBuilder code = new StringBuilder();
        for (int i = 0; i < length; i++) {
            code.append(secureRandom.nextInt(10));
        }
        return code.toString();
    }

    private void sendEmail(final String to, final String verificationCode) {
        try {
            final SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(mailProperties.getUsername()); // 从MailProperties获取发件人邮箱
            message.setTo(to);
            message.setSubject("SSO登录验证码 / SSO Login Verification Code");

            final String content = String.format(
                "您的SSO登录验证码是: %s%n"
                + "验证码有效期为%d分钟，请勿泄露给他人。%n%n"
                + "Your SSO login verification code is: %s%n"
                + "The code is valid for %d minutes. Please do not share it with others.",
                verificationCode, codeExpirationMinutes, verificationCode, codeExpirationMinutes
            );

            message.setText(content);
            javaMailSender.send(message);
            log.debug("邮件已发送至[{}]，包含验证码。", to);
        } catch (final Exception e) {
            log.error("发送邮件失败至邮箱[{}]：{}", to, e.getMessage(), e);
            throw new RuntimeException("Failed to send verification email", e);
        }
    }

    private boolean isValidEmail(final String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }
}
