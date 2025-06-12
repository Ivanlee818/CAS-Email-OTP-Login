package org.apereo.cas.authentication.credential;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apereo.cas.authentication.credential.AbstractCredential;

/**
 * Custom credential for email verification code login.
 * 用于邮箱验证码登录的自定义凭据。
 */
@Getter
@Setter
@NoArgsConstructor
public class EmailCodeLoginCredential extends AbstractCredential {

    private static final long serialVersionUID = 8110753063523588960L;

    private String email;
    private String verificationCode;

    public EmailCodeLoginCredential(final String email, final String verificationCode) {
        this.email = email;
        this.verificationCode = verificationCode;
    }

    /**
     * The ID of the credential is the email itself.
     * 凭据的ID即为邮箱地址。
     * @return the email address
     */
    @Override
    public String getId() {
        return email;
    }
}
