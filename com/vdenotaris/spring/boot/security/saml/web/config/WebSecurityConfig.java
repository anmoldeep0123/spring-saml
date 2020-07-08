/*
 * Decompiled with CFR 0.146.
 * 
 * Could not load the following classes:
 *  com.vdenotaris.spring.boot.security.saml.web.config.WebSecurityConfig
 *  com.vdenotaris.spring.boot.security.saml.web.core.SAMLUserDetailsServiceImpl
 *  javax.servlet.Filter
 *  org.apache.commons.httpclient.HttpClient
 *  org.apache.commons.httpclient.HttpConnectionManager
 *  org.apache.commons.httpclient.MultiThreadedHttpConnectionManager
 *  org.apache.velocity.app.VelocityEngine
 *  org.opensaml.saml2.metadata.provider.HTTPMetadataProvider
 *  org.opensaml.saml2.metadata.provider.MetadataProvider
 *  org.opensaml.saml2.metadata.provider.MetadataProviderException
 *  org.opensaml.xml.parse.ParserPool
 *  org.opensaml.xml.parse.StaticBasicParserPool
 *  org.springframework.beans.factory.DisposableBean
 *  org.springframework.beans.factory.InitializingBean
 *  org.springframework.beans.factory.annotation.Autowired
 *  org.springframework.beans.factory.annotation.Qualifier
 *  org.springframework.context.annotation.Bean
 *  org.springframework.context.annotation.Configuration
 *  org.springframework.core.io.DefaultResourceLoader
 *  org.springframework.core.io.Resource
 *  org.springframework.security.authentication.AuthenticationManager
 *  org.springframework.security.authentication.AuthenticationProvider
 *  org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
 *  org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
 *  org.springframework.security.config.annotation.web.HttpSecurityBuilder
 *  org.springframework.security.config.annotation.web.builders.HttpSecurity
 *  org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
 *  org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
 *  org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer
 *  org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer$AuthorizedUrl
 *  org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer$ExpressionInterceptUrlRegistry
 *  org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer
 *  org.springframework.security.config.annotation.web.configurers.LogoutConfigurer
 *  org.springframework.security.saml.SAMLAuthenticationProvider
 *  org.springframework.security.saml.SAMLBootstrap
 *  org.springframework.security.saml.SAMLDiscovery
 *  org.springframework.security.saml.SAMLEntryPoint
 *  org.springframework.security.saml.SAMLLogoutFilter
 *  org.springframework.security.saml.SAMLLogoutProcessingFilter
 *  org.springframework.security.saml.SAMLProcessingFilter
 *  org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter
 *  org.springframework.security.saml.context.SAMLContextProviderImpl
 *  org.springframework.security.saml.key.JKSKeyManager
 *  org.springframework.security.saml.key.KeyManager
 *  org.springframework.security.saml.log.SAMLDefaultLogger
 *  org.springframework.security.saml.metadata.CachingMetadataManager
 *  org.springframework.security.saml.metadata.ExtendedMetadata
 *  org.springframework.security.saml.metadata.ExtendedMetadataDelegate
 *  org.springframework.security.saml.metadata.MetadataDisplayFilter
 *  org.springframework.security.saml.metadata.MetadataGenerator
 *  org.springframework.security.saml.metadata.MetadataGeneratorFilter
 *  org.springframework.security.saml.parser.ParserPoolHolder
 *  org.springframework.security.saml.processor.HTTPArtifactBinding
 *  org.springframework.security.saml.processor.HTTPPAOS11Binding
 *  org.springframework.security.saml.processor.HTTPPostBinding
 *  org.springframework.security.saml.processor.HTTPRedirectDeflateBinding
 *  org.springframework.security.saml.processor.HTTPSOAP11Binding
 *  org.springframework.security.saml.processor.SAMLBinding
 *  org.springframework.security.saml.processor.SAMLProcessor
 *  org.springframework.security.saml.processor.SAMLProcessorImpl
 *  org.springframework.security.saml.userdetails.SAMLUserDetailsService
 *  org.springframework.security.saml.util.VelocityFactory
 *  org.springframework.security.saml.websso.ArtifactResolutionProfile
 *  org.springframework.security.saml.websso.ArtifactResolutionProfileImpl
 *  org.springframework.security.saml.websso.SingleLogoutProfile
 *  org.springframework.security.saml.websso.SingleLogoutProfileImpl
 *  org.springframework.security.saml.websso.WebSSOProfile
 *  org.springframework.security.saml.websso.WebSSOProfileConsumer
 *  org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl
 *  org.springframework.security.saml.websso.WebSSOProfileConsumerImpl
 *  org.springframework.security.saml.websso.WebSSOProfileECPImpl
 *  org.springframework.security.saml.websso.WebSSOProfileImpl
 *  org.springframework.security.saml.websso.WebSSOProfileOptions
 *  org.springframework.security.web.AuthenticationEntryPoint
 *  org.springframework.security.web.DefaultSecurityFilterChain
 *  org.springframework.security.web.FilterChainProxy
 *  org.springframework.security.web.access.channel.ChannelProcessingFilter
 *  org.springframework.security.web.authentication.AuthenticationFailureHandler
 *  org.springframework.security.web.authentication.AuthenticationSuccessHandler
 *  org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
 *  org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
 *  org.springframework.security.web.authentication.logout.LogoutHandler
 *  org.springframework.security.web.authentication.logout.LogoutSuccessHandler
 *  org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
 *  org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
 *  org.springframework.security.web.authentication.www.BasicAuthenticationFilter
 *  org.springframework.security.web.csrf.CsrfFilter
 *  org.springframework.security.web.util.matcher.AntPathRequestMatcher
 *  org.springframework.security.web.util.matcher.RequestMatcher
 */
package com.vdenotaris.spring.boot.security.saml.web.config;

import com.vdenotaris.spring.boot.security.saml.web.core.SAMLUserDetailsServiceImpl;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import javax.servlet.Filter;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpConnectionManager;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLDiscovery;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.SAMLWebSSOHoKProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessor;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileECPImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled=true)
public class WebSecurityConfig
extends WebSecurityConfigurerAdapter
implements InitializingBean,
DisposableBean {
    private Timer backgroundTaskTimer;
    private MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager;
    @Autowired
    private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;

    public void init() {
        this.backgroundTaskTimer = new Timer(true);
        this.multiThreadedHttpConnectionManager = new MultiThreadedHttpConnectionManager();
    }

    public void shutdown() {
        this.backgroundTaskTimer.purge();
        this.backgroundTaskTimer.cancel();
        this.multiThreadedHttpConnectionManager.shutdown();
    }

    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }

    @Bean(initMethod="initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }

    @Bean(name={"parserPoolHolder"})
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }

    @Bean
    public HttpClient httpClient() {
        return new HttpClient((HttpConnectionManager)this.multiThreadedHttpConnectionManager);
    }

    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
        samlAuthenticationProvider.setUserDetails((SAMLUserDetailsService)this.samlUserDetailsServiceImpl);
        samlAuthenticationProvider.setForcePrincipalAsString(false);
        return samlAuthenticationProvider;
    }

    @Bean
    public SAMLContextProviderImpl contextProvider() {
        return new SAMLContextProviderImpl();
    }

    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new SAMLBootstrap();
    }

    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }

    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    @Bean
    public WebSSOProfileECPImpl ecpprofile() {
        return new WebSSOProfileECPImpl();
    }

    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }

    @Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader.getResource("classpath:/saml/samlKeystore.jks");
        String storePass = "nalle123";
        HashMap<String, String> passwords = new HashMap<String, String>();
        passwords.put("apollo", "nalle123");
        String defaultKey = "apollo";
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
    }

    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(Boolean.valueOf(false));
        return webSSOProfileOptions;
    }

    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(this.defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }

    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(true);
        extendedMetadata.setSigningAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        extendedMetadata.setSignMetadata(true);
        extendedMetadata.setEcpEnabled(true);
        return extendedMetadata;
    }

    @Bean
    public SAMLDiscovery samlIDPDiscovery() {
        SAMLDiscovery idpDiscovery = new SAMLDiscovery();
        idpDiscovery.setIdpSelectionPath("/saml/discovery");
        return idpDiscovery;
    }

    @Bean
    @Qualifier(value="idp-ssocircle")
    public ExtendedMetadataDelegate ssoCircleExtendedMetadataProvider() throws MetadataProviderException {
        String idpSSOCircleMetadataURL = "https://idp.ssocircle.com/meta-idp.xml";
        HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(this.backgroundTaskTimer, this.httpClient(), idpSSOCircleMetadataURL);
        httpMetadataProvider.setParserPool((ParserPool)this.parserPool());
        ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate((MetadataProvider)httpMetadataProvider, this.extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(true);
        extendedMetadataDelegate.setMetadataRequireSignature(false);
        this.backgroundTaskTimer.purge();
        return extendedMetadataDelegate;
    }

    @Bean
    @Qualifier(value="metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        ArrayList<ExtendedMetadataDelegate> providers = new ArrayList<ExtendedMetadataDelegate>();
        providers.add(this.ssoCircleExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }

    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId("com:vdenotaris:spring:sp");
        metadataGenerator.setExtendedMetadata(this.extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(this.keyManager());
        return metadataGenerator;
    }

    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/landing");
        return successRedirectHandler;
    }

    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl("/error");
        return failureHandler;
    }

    @Bean
    public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
        SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler((AuthenticationSuccessHandler)this.successRedirectHandler());
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(this.authenticationManager());
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler((AuthenticationFailureHandler)this.authenticationFailureHandler());
        return samlWebSSOHoKProcessingFilter;
    }

    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(this.authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler((AuthenticationSuccessHandler)this.successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler((AuthenticationFailureHandler)this.authenticationFailureHandler());
        return samlWebSSOProcessingFilter;
    }

    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(this.metadataGenerator());
    }

    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl("/");
        return successLogoutHandler;
    }

    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter((LogoutSuccessHandler)this.successLogoutHandler(), new LogoutHandler[]{this.logoutHandler()});
    }

    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter((LogoutSuccessHandler)this.successLogoutHandler(), new LogoutHandler[]{this.logoutHandler()}, new LogoutHandler[]{this.logoutHandler()});
    }

    private ArtifactResolutionProfile artifactResolutionProfile() {
        ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(this.httpClient());
        artifactResolutionProfile.setProcessor((SAMLProcessor)new SAMLProcessorImpl((SAMLBinding)this.soapBinding()));
        return artifactResolutionProfile;
    }

    @Bean
    public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        return new HTTPArtifactBinding(parserPool, velocityEngine, this.artifactResolutionProfile());
    }

    @Bean
    public HTTPSOAP11Binding soapBinding() {
        return new HTTPSOAP11Binding((ParserPool)this.parserPool());
    }

    @Bean
    public HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding((ParserPool)this.parserPool(), this.velocityEngine());
    }

    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding((ParserPool)this.parserPool());
    }

    @Bean
    public HTTPSOAP11Binding httpSOAP11Binding() {
        return new HTTPSOAP11Binding((ParserPool)this.parserPool());
    }

    @Bean
    public HTTPPAOS11Binding httpPAOS11Binding() {
        return new HTTPPAOS11Binding((ParserPool)this.parserPool());
    }

    @Bean
    public SAMLProcessorImpl processor() {
        ArrayList<Object> bindings = new ArrayList<Object>();
        bindings.add((Object)this.httpRedirectDeflateBinding());
        bindings.add((Object)this.httpPostBinding());
        bindings.add((Object)this.artifactBinding((ParserPool)this.parserPool(), this.velocityEngine()));
        bindings.add((Object)this.httpSOAP11Binding());
        bindings.add((Object)this.httpPAOS11Binding());
        return new SAMLProcessorImpl(bindings);
    }

    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        ArrayList<DefaultSecurityFilterChain> chains = new ArrayList<DefaultSecurityFilterChain>();
        chains.add(new DefaultSecurityFilterChain((RequestMatcher)new AntPathRequestMatcher("/saml/login/**"), new Filter[]{this.samlEntryPoint()}));
        chains.add(new DefaultSecurityFilterChain((RequestMatcher)new AntPathRequestMatcher("/saml/logout/**"), new Filter[]{this.samlLogoutFilter()}));
        chains.add(new DefaultSecurityFilterChain((RequestMatcher)new AntPathRequestMatcher("/saml/metadata/**"), new Filter[]{this.metadataDisplayFilter()}));
        chains.add(new DefaultSecurityFilterChain((RequestMatcher)new AntPathRequestMatcher("/saml/SSO/**"), new Filter[]{this.samlWebSSOProcessingFilter()}));
        chains.add(new DefaultSecurityFilterChain((RequestMatcher)new AntPathRequestMatcher("/saml/SSOHoK/**"), new Filter[]{this.samlWebSSOHoKProcessingFilter()}));
        chains.add(new DefaultSecurityFilterChain((RequestMatcher)new AntPathRequestMatcher("/saml/SingleLogout/**"), new Filter[]{this.samlLogoutProcessingFilter()}));
        chains.add(new DefaultSecurityFilterChain((RequestMatcher)new AntPathRequestMatcher("/saml/discovery/**"), new Filter[]{this.samlIDPDiscovery()}));
        return new FilterChainProxy(chains);
    }

    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().authenticationEntryPoint((AuthenticationEntryPoint)this.samlEntryPoint());
        http.addFilterBefore((Filter)this.metadataGeneratorFilter(), ChannelProcessingFilter.class).addFilterAfter((Filter)this.samlFilter(), BasicAuthenticationFilter.class).addFilterBefore((Filter)this.samlFilter(), CsrfFilter.class);
        ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)http.authorizeRequests().antMatchers(new String[]{"/"})).permitAll().antMatchers(new String[]{"/saml/**"})).permitAll().antMatchers(new String[]{"/css/**"})).permitAll().antMatchers(new String[]{"/img/**"})).permitAll().antMatchers(new String[]{"/js/**"})).permitAll().anyRequest()).authenticated();
        http.logout().disable();
    }

    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider((AuthenticationProvider)this.samlAuthenticationProvider());
    }

    public void afterPropertiesSet() throws Exception {
        this.init();
    }

    public void destroy() throws Exception {
        this.shutdown();
    }
}

