package com.nikp.payment.infrastructure.configuration;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.nikp.payment.infrastructure.filter.InterceptRequestResponseFilter;

@Configuration
public class FilterConfig {


    @Bean
    public FilterRegistrationBean<InterceptRequestResponseFilter> loggingFilter() {
        FilterRegistrationBean<InterceptRequestResponseFilter> registrationBean = new FilterRegistrationBean<>();

        registrationBean.setFilter(new InterceptRequestResponseFilter());

        registrationBean.addUrlPatterns("/users/*");

        return registrationBean;

    }

}
