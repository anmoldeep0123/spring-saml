/*
 * Decompiled with CFR 0.146.
 * 
 * Could not load the following classes:
 *  com.vdenotaris.spring.boot.security.saml.web.controllers.SSOController
 *  javax.servlet.http.HttpServletRequest
 *  org.slf4j.Logger
 *  org.slf4j.LoggerFactory
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.security.authentication.AnonymousAuthenticationToken
 *  org.springframework.security.core.Authentication
 *  org.springframework.security.core.context.SecurityContextHolder
 *  org.springframework.security.saml.metadata.MetadataManager
 *  org.springframework.stereotype.Controller
 *  org.springframework.ui.Model
 *  org.springframework.web.bind.annotation.RequestMapping
 *  org.springframework.web.bind.annotation.RequestMethod
 */
package com.vdenotaris.spring.boot.security.saml.web.controllers;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping(value={"/saml"})
public class SSOController {
    private static final Logger LOG = LoggerFactory.getLogger(SSOController.class);
    @Autowired
    private MetadataManager metadata;

    @RequestMapping(value={"/discovery"}, method={RequestMethod.GET})
    public String idpSelection(HttpServletRequest request, Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            LOG.debug("Current authentication instance from security context is null");
        } else {
            LOG.debug("Current authentication instance from security context: " + this.getClass().getSimpleName());
        }
        if (auth == null || auth instanceof AnonymousAuthenticationToken) {
            Set idps = this.metadata.getIDPEntityNames();
            for (String idp : idps) {
                LOG.info("Configured Identity Provider for SSO: " + idp);
            }
            model.addAttribute("idps", (Object)idps);
            return "pages/discovery";
        }
        LOG.warn("The current user is already logged.");
        return "redirect:/landing";
    }
}

