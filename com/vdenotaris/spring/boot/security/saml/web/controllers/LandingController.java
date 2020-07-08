/*
 * Decompiled with CFR 0.146.
 * 
 * Could not load the following classes:
 *  com.vdenotaris.spring.boot.security.saml.web.controllers.LandingController
 *  com.vdenotaris.spring.boot.security.saml.web.stereotypes.CurrentUser
 *  org.slf4j.Logger
 *  org.slf4j.LoggerFactory
 *  org.springframework.security.core.Authentication
 *  org.springframework.security.core.context.SecurityContextHolder
 *  org.springframework.security.core.userdetails.User
 *  org.springframework.stereotype.Controller
 *  org.springframework.ui.Model
 *  org.springframework.web.bind.annotation.RequestMapping
 */
package com.vdenotaris.spring.boot.security.saml.web.controllers;

import com.vdenotaris.spring.boot.security.saml.web.stereotypes.CurrentUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LandingController {
    private static final Logger LOG = LoggerFactory.getLogger(LandingController.class);

    @RequestMapping(value={"/landing"})
    public String landing(@CurrentUser User user, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            LOG.debug("Current authentication instance from security context is null");
        } else {
            LOG.debug("Current authentication instance from security context: " + this.getClass().getSimpleName());
        }
        model.addAttribute("username", (Object)user.getUsername());
        return "pages/landing";
    }
}

