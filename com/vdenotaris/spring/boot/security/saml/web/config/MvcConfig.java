/*
 * Decompiled with CFR 0.146.
 * 
 * Could not load the following classes:
 *  com.vdenotaris.spring.boot.security.saml.web.config.MvcConfig
 *  com.vdenotaris.spring.boot.security.saml.web.core.CurrentUserHandlerMethodArgumentResolver
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.context.annotation.Configuration
 *  org.springframework.web.method.support.HandlerMethodArgumentResolver
 *  org.springframework.web.servlet.config.annotation.ResourceHandlerRegistration
 *  org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry
 *  org.springframework.web.servlet.config.annotation.ViewControllerRegistration
 *  org.springframework.web.servlet.config.annotation.ViewControllerRegistry
 *  org.springframework.web.servlet.config.annotation.WebMvcConfigurer
 */
package com.vdenotaris.spring.boot.security.saml.web.config;

import com.vdenotaris.spring.boot.security.saml.web.core.CurrentUserHandlerMethodArgumentResolver;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig
implements WebMvcConfigurer {
    @Autowired
    CurrentUserHandlerMethodArgumentResolver currentUserHandlerMethodArgumentResolver;

    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("pages/index");
    }

    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        if (!registry.hasMappingForPattern("/static/**")) {
            registry.addResourceHandler(new String[]{"/static/**"}).addResourceLocations(new String[]{"/static/"});
        }
    }

    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add((HandlerMethodArgumentResolver)this.currentUserHandlerMethodArgumentResolver);
    }
}

