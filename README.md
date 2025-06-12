## Apereo CAS 

最新CAS 7.x 增加自定义登录方式，基于 CAS 7.1.6 Overlay , 实现了邮件一次性验证码登录


## 说明

邮件一次性验证码登录方式的主要功能工作正常，惟一遗留问题是，casEmailLoginView 未能正确显示错误消息，比如：如果用户提供了错误的一次性密码，casEmailLoginView不显示错误消息，只是停留在登录页，等待用户提供正确的code.
