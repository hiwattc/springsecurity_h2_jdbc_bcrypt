package com.example.demo;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
//public class SecurityConfiguration extends WebSecurityConfigurerAdapter implements WebMvcConfigurer{
    public class SecurityConfiguration extends WebSecurityConfigurerAdapter{
	@Autowired
    private DataSource dataSource;
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

    //테스트성공
    @Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/admin").hasRole("ADMIN")
				.antMatchers("/user").hasAnyRole("ADMIN", "USER")
				.antMatchers("/").permitAll()
                .antMatchers("/h2-console/**").permitAll()
				//.and()
				//.loginPage("/login")
				//.permitAll()
                //.formLogin()
            
               .and().formLogin().loginPage("/login.html").defaultSuccessUrl("/admin").failureUrl("/login.html?error=true").permitAll()
        
				.and()
			    .logout()
                .permitAll();
                
                http.csrf().disable();
                //http.headers().frameOptions().disable();
                http.headers().frameOptions().sameOrigin(); //x-frame-options 동일 출처일경우만
        
    }
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