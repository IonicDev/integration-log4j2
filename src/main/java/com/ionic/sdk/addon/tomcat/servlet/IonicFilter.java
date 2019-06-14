package com.ionic.sdk.addon.tomcat.servlet;

import com.ionic.sdk.addon.tomcat.servlet.http.IonicServletResponseWrapper;
import com.ionic.sdk.agent.Agent;
import com.ionic.sdk.agent.AgentSdk;
import com.ionic.sdk.agent.cipher.file.GenericFileCipher;
import com.ionic.sdk.core.res.Resource;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPlainText;
import com.ionic.sdk.device.profile.persistor.ProfilePersistor;
import com.ionic.sdk.error.IonicException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.servlet.FilterChain;
import javax.servlet.GenericFilter;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.security.Security;
import java.util.Collection;

public class IonicFilter extends GenericFilter {

    private final Logger logger = LogManager.getLogger(getClass());

    private Agent agent = null;

    public void init() /*throws ServletException*/ {
        logger.traceEntry();
        final String ionicProfile = getFilterConfig().getInitParameter("ionic-profile");
        agent = null;
        if (ionicProfile != null) {
            try {
                AgentSdk.initialize(Security.getProvider("SunJCE"));
                final URL urlIonicProfile = Resource.resolve(ionicProfile);
                final ProfilePersistor profilePersistor = new DeviceProfilePersistorPlainText(urlIonicProfile);
                agent = new Agent(profilePersistor);
                logger.debug(agent.toString());
            } catch (IonicException e) {
                logger.error(e.getMessage(), e);
            }
        }
        logger.traceExit();
    }

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
                         final FilterChain filterChain) throws IOException, ServletException {
        final boolean isHttpServletRequest = (servletRequest instanceof HttpServletRequest);
        final boolean isHttpServletResponse = servletResponse instanceof HttpServletResponse;
        if (isHttpServletRequest && isHttpServletResponse) {
            doFilter((HttpServletRequest) servletRequest, (HttpServletResponse) servletResponse, filterChain);
        } else {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    private void doFilter(final HttpServletRequest servletRequest, final HttpServletResponse servletResponse,
                          final FilterChain filterChain) throws IOException, ServletException {
        logger.traceEntry();
        // get the response entity
        final IonicServletResponseWrapper wrapper = new IonicServletResponseWrapper(servletResponse);
        filterChain.doFilter(servletRequest, wrapper);
        final byte[] responseEntity = wrapper.getBytes();
        // filter response headers
        final Collection<String> headerNames = wrapper.getHeaderNames();
        for (String headerName : headerNames) {
            final Collection<String> headerValues = wrapper.getHeaders(headerName);
            for (String headerValue : headerValues) {
                if ("Content-Type".equalsIgnoreCase(headerName)) {

                } else if ("Content-Length".equalsIgnoreCase(headerName)) {

                } else {
                    (servletResponse).setHeader(headerName, headerValue);
                }
            }
        }
        // tell client not to cache
        servletResponse.setHeader("Cache-Control", "no-store, must-revalidate");
        // make decision whether to apply Ionic file cipher based on request file name
        final String servletPath = servletRequest.getServletPath();
        if ((servletPath.contains("ionic") && (agent != null))) {
            try {
                final Agent agentFilter = Agent.clone(agent);
                final GenericFileCipher fileCipher = new GenericFileCipher(agentFilter);
                final byte[] responseEntityPlain = fileCipher.decrypt(responseEntity);
                servletResponse.setHeader("Content-Type", "text/plain");
                servletResponse.setHeader("Content-Length", Integer.toString(responseEntityPlain.length));
                servletResponse.getOutputStream().write(responseEntityPlain);
            } catch (IonicException e) {
                servletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            }
        } else {
            servletResponse.setHeader("Content-Type", wrapper.getHeader("Content-Type"));
            servletResponse.setHeader("Content-Length", wrapper.getHeader("Content-Length"));
            servletResponse.getOutputStream().write(responseEntity);
        }
        logger.traceExit();
    }
}
