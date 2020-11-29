package cn.wjw.winauth.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.kerberos.authentication.KerberosAuthenticationProvider;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosClient;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Value("${app.service-principal}")
  private String servicePrincipal;

  @Value("${app.keytab-location}")
  private String keytabLocation;


  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // 未验证时发起SPNEGO协商
    http.exceptionHandling().authenticationEntryPoint(spnegoEntryPoint())
        .and().authorizeRequests()
        // 所有的请求都需要验证
        .anyRequest().authenticated()
        // 拦截并验证请求的SPNEGO令牌
        .and().addFilterBefore(spnegoAuthenticationProcessingFilter(authenticationManagerBean()),
            BasicAuthenticationFilter.class);
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    // 使用kerberos提供身份验证
    auth.authenticationProvider(kerberosAuthenticationProvider())
        .authenticationProvider(kerberosServiceAuthenticationProvider());
  }

  @Bean
  public KerberosAuthenticationProvider kerberosAuthenticationProvider() {
    KerberosAuthenticationProvider provider =
        new KerberosAuthenticationProvider();
    SunJaasKerberosClient client = new SunJaasKerberosClient();
    provider.setKerberosClient(client);
    provider.setUserDetailsService(dummyUserDetailsService());
    return provider;
  }

  /**
   * kerberos身份验证Bean.
   */
  @Bean
  public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
    KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
    provider.setTicketValidator(sunJaasKerberosTicketValidator());
    provider.setUserDetailsService(dummyUserDetailsService());
    return provider;
  }

  /**
   * 用户信息获取Bean.
   */
  @Bean
  public DummyUserDetailsService dummyUserDetailsService() {
    return new DummyUserDetailsService();
  }

  /**
   * ST校验器。使用keytab和SPN解析请求携带的ST。
   */
  @Bean
  public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
    SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
    ticketValidator.setServicePrincipal(servicePrincipal);
    ticketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
    return ticketValidator;
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  /**
   * SPNEGO协商入口点Bean.尝试与浏览器协商使用SPNEGO令牌携带ST.
   */
  @Bean
  public SpnegoEntryPoint spnegoEntryPoint() {
    return new SpnegoEntryPoint();
  }

  /**
   * SPNEGO令牌验证拦截器.拦截请求，调用Kerberos验证器校验SPNEGO令牌中的ST.
   */
  @Bean
  public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
      AuthenticationManager authenticationManager) {
    SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
    filter.setAuthenticationManager(authenticationManager);
    return filter;
  }

}
