/*
 * Decompiled with CFR 0.146.
 * 
 * Could not load the following classes:
 *  com.vdenotaris.spring.boot.security.saml.web.core.SAMLUserDetailsServiceImpl
 *  org.opensaml.saml2.core.NameID
 *  org.slf4j.Logger
 *  org.slf4j.LoggerFactory
 *  org.springframework.security.core.authority.SimpleGrantedAuthority
 *  org.springframework.security.core.userdetails.User
 *  org.springframework.security.core.userdetails.UsernameNotFoundException
 *  org.springframework.security.saml.SAMLCredential
 *  org.springframework.security.saml.userdetails.SAMLUserDetailsService
 *  org.springframework.stereotype.Service
 */
package com.vdenotaris.spring.boot.security.saml.web.core;

import java.util.ArrayList;
import java.util.Collection;
import org.opensaml.saml2.core.NameID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class SAMLUserDetailsServiceImpl
implements SAMLUserDetailsService {
    private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

    public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
        String userID = credential.getNameID().getValue();
        LOG.info(userID + " is logged in");
        ArrayList<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(authority);
        return new User(userID, "<abc123>", true, true, true, true, authorities);
    }
}

