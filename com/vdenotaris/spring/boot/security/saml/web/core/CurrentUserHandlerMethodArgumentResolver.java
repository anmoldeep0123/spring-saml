/*
 * Decompiled with CFR 0.146.
 * 
 * Could not load the following classes:
 *  com.vdenotaris.spring.boot.security.saml.web.core.CurrentUserHandlerMethodArgumentResolver
 *  com.vdenotaris.spring.boot.security.saml.web.stereotypes.CurrentUser
 *  org.springframework.core.MethodParameter
 *  org.springframework.security.core.Authentication
 *  org.springframework.security.core.userdetails.User
 *  org.springframework.stereotype.Component
 *  org.springframework.web.bind.support.WebArgumentResolver
 *  org.springframework.web.bind.support.WebDataBinderFactory
 *  org.springframework.web.context.request.NativeWebRequest
 *  org.springframework.web.method.support.HandlerMethodArgumentResolver
 *  org.springframework.web.method.support.ModelAndViewContainer
 */
package com.vdenotaris.spring.boot.security.saml.web.core;

import com.vdenotaris.spring.boot.security.saml.web.stereotypes.CurrentUser;
import java.lang.annotation.Annotation;
import java.security.Principal;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebArgumentResolver;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

@Component
public class CurrentUserHandlerMethodArgumentResolver
implements HandlerMethodArgumentResolver {
    public boolean supportsParameter(MethodParameter methodParameter) {
        return methodParameter.getParameterAnnotation(CurrentUser.class) != null && methodParameter.getParameterType().equals(User.class);
    }

    public Object resolveArgument(MethodParameter methodParameter, ModelAndViewContainer mavContainer, NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
        if (this.supportsParameter(methodParameter)) {
            Principal principal = webRequest.getUserPrincipal();
            return (User)((Authentication)principal).getPrincipal();
        }
        return WebArgumentResolver.UNRESOLVED;
    }
}

