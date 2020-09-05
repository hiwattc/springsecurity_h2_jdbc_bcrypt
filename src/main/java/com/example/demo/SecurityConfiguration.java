package com.example.demo;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
//public class SecurityConfiguration extends WebSecurityConfigurerAdapter implements WebMvcConfigurer{
    public class SecurityConfiguration extends WebSecurityConfigurerAdapter{
	@Autowired
    private DataSource dataSource;

    //@Autowired
    //private CustomLoginSuccessHandler customLoginSuccessHandler;

	//@Autowired
    //private UserDetailsServiceImpl userService;

    /*
    @Autowired
    private PasswordEncoder passwordEncoder;
    */

    /*
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("index");
        registry.addViewController("/login.html").setViewName("login"); // 매핑
    } */

    ///테스트성공
    /*
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .passwordEncoder(NoOpPasswordEncoder.getInstance())
            .withUser("admin").password("1").authorities("ROLE_ADMIN").and()
            .withUser("user1").password("1").authorities("ROLE_USER").and()
            .withUser("user2").password("1").authorities("ROLE_USER");
    }*/
    //https://www.websparrow.org/spring/spring-boot-security-remember-me-example
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
                .withUser("test").password("{noop}test").roles("ADMIN");
                /*                
                .inMemoryAuthentication()
                .withUser("admin")
                .password(passwordEncoder().encode("admin123"))
                .roles("ADMIN").authorities("ACCESS_TEST1", "ACCESS_TEST2")
                */
    }   
    @Bean
    public AuthenticationSuccessHandler successHandler() {
      return new CustomLoginSuccessHandler("/admin");
    }

    
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .rolePrefix("ROLE_")
                
                //아래치환($2y -> $2a 는 spring security bug관련 내용인듯함)
                //자세한 설명 : http://yoonbumtae.com/?p=1202
                //.usersByUsernameQuery("SELECT USERNAME, replace(PASSWORD, '$2y', '$2a') AS PASSWORD, 'TRUE' as enabled FROM USERS WHERE USERNAME = ?")
                .usersByUsernameQuery("SELECT USERNAME, PASSWORD AS PASSWORD, 'TRUE' as enabled FROM USERS WHERE USERNAME = ?")
                .authoritiesByUsernameQuery("SELECT A.USERNAME AS USERNAME, B.AUTHORITY AS AUTHORITIES " +
                        "FROM USERS as A INNER JOIN AUTHORITIES as B " +
                        "ON A.USERNAME = B.USERNAME " +
                        "WHERE A.USERNAME = ?");
    }



/*
    ///테스트하기전
    @Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
			.dataSource(dataSource)
			.withDefaultSchema()
			.withUser(User.withUsername("admin").password("password").roles("ADMIN"))
			.withUser(User.withUsername("user").password("password").roles("USER"));
    }
*/
/*
    ///테스트하기전
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                //.antMatchers("/").permitAll()
                .antMatchers("/h2-console/**").permitAll();

        http.csrf().disable();
        //http.headers().frameOptions().disable();
        http.headers().frameOptions().sameOrigin(); //x-frame-options 동일 출처일경우만
    }
*/
    @Override
    public void configure(WebSecurity web) throws Exception
    {
        web.ignoring().antMatchers("/css/**", "/script/**", "image/**", "/fonts/**", "lib/**");
    }

    //테스트성공
    //참고url : https://blog.naver.com/spring1a/221764267556
    //https://docs.spring.io/spring-security/site/docs/4.2.13.RELEASE/apidocs/org/springframework/security/config/annotation/web/builders/HttpSecurity.html
    @Override
	protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
			.antMatchers("/admin").hasRole("ADMIN")
			.antMatchers("/user").hasAnyRole("ADMIN", "USER")
			.antMatchers("/").permitAll()
            .antMatchers("/h2-console/**").permitAll()
				//.and()
				//.loginPage("/login")
				//.permitAll()
                //.formLogin()
               
            .and()
               .formLogin()
               .loginPage("/login.html")
               //.successHandler(new CustomLoginSuccessHandler("/"))
               .defaultSuccessUrl("/admin")
               .successHandler(successHandler())
               .failureUrl("/login.html?error=true")
               .permitAll()
            .and()
               .logout()
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                    .permitAll();

                    //[출처] [Spring Security] Remember-me(자동 로그인) 설정|작성자 쮸니a
                    //참고2 : https://www.websparrow.org/spring/spring-boot-security-remember-me-example
                    http.rememberMe()
                    .key("uniqueAndSecret")
                    //.tokenValiditySeconds(10000000);
                    .tokenValiditySeconds(60 * 60 * 24 * 5) // 시간 유지 시간 설정
                    .rememberMeParameter("remember-me") // login form의 체크박스name
                    .rememberMeCookieName("remember-me") // 실제 쿠키에 저장될 이름
                    .tokenRepository(tokenRepository());
                    //.userDetailsService(userService) // userDtailService 구현체
                    //.rememberMeServices(persistentTokenBasedRememberMeServices());
    
    
                    

                
                //http.csrf().disable();
                //http.headers().frameOptions().disable();
                http.headers().frameOptions().sameOrigin(); //x-frame-options 동일 출처일경우만

                /*
                http
               .authorizeRequests()
               .antMatchers("/tokens").access(
                "hasIpAddress('10.0.0.0/16') or hasIpAddress('127.0.0.1/32')")
                */
        
    }
    //[출처] [Spring Security] Remember-me(자동 로그인) 설정|작성자 쮸니a
    @Bean(name = "persistentTokenRepository")
    public PersistentTokenRepository tokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }
    //[출처] [Spring Security] Remember-me(자동 로그인) 설정|작성자 쮸니a
    /*
    @Bean(name = "persistentTokenBasedRememberMeServices")
    public PersistentTokenBasedRememberMeServices persistentTokenBasedRememberMeServices() {
        PersistentTokenBasedRememberMeServices persistentTokenBasedRememberMeServices = new
                PersistentTokenBasedRememberMeServices("uniqueAndSecret",userService, tokenRepository());
        persistentTokenBasedRememberMeServices.setParameter("remember-me");
        persistentTokenBasedRememberMeServices.setAlwaysRemember(false);
        persistentTokenBasedRememberMeServices.setCookieName("remember-me");
        persistentTokenBasedRememberMeServices.setTokenValiditySeconds( 60 * 60 * 24 *5);
        return persistentTokenBasedRememberMeServices;
    }
*/





    /*
	@Bean
	public PasswordEncoder getPasswordEncoder() {
		return NoOpPasswordEncoder.getInstance();
    }*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }    

}