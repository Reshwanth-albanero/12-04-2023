package com.example.demo.Config;

import com.example.demo.Service.CustomUser;
import org.hibernate.validator.internal.engine.messageinterpolation.el.NoOpElResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import uk.co.ticklethepanda.spring.auth.jwt.JwtAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class UserConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    CustomUser customUser;
    @Autowired
    JwtAuthenticationFilter jwtAuthenticationFilter;
//  changing the authorization to base http
    /*




    this is for user spring security









    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//                .authorizeHttpRequests()
//                .anyRequest()
//                .authenticated()
//                .and()
//                .httpBasic();
                // to make the connections secure then we can use csrf tocken
                .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                // to here to make the connect restricted if we want to make the connection then we need to pass the cookie value from that repository
                .authorizeHttpRequests().antMatchers("/home","/Second-home").permitAll() // in place of permit i can use hasrole() to specify which one should use ut
                .anyRequest().authenticated().and()
                //.httpBasic();
        // in form based athen in place of http basic
                .formLogin()
                .loginPage("/home")
                .loginProcessingUrl("/dologin")
                .defaultSuccessUrl("/users");
    }
    */
//  set custom user and password for the web security
    @Override
    protected  void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .cors().disable()
                .authorizeRequests()
                .antMatchers("/token").permitAll()
                .anyRequest().authenticated().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUser);
//        auth.inMemoryAuthentication().withUser("Raju").password("123").roles("NORMAL");
//        auth.inMemoryAuthentication().withUser("Ravi").password(this.passwordEncoder().encode("321")).roles("ADMIN");
    }
//  to set the readable password
    @Bean
    public PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
// to set the non-readable password
//    @Bean
//    public PasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder(10);
//    }
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
