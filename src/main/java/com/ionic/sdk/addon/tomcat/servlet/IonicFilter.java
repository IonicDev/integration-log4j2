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

/**
 * Implementation of {@link javax.servlet.Filter}, which performs conditional Ionic decryption of HTTP response body.
 */
public class IonicFilter extends GenericFilter {

    /**
     * Class scoped logger.  In this sample webapp, Tomcat logging is redirected into log4j library.  Each request
     * into the sample webapp causes log lines to be written, which are persisted into the log files specified in the
     * webapp configuration.
     */
    private final Logger logger = LogManager.getLogger(getClass());

    /**
     * Ionic state.
     * <p>
     * The main point of interaction with the Ionic SDK. This class performs all client/server communications with
     * Ionic.com.
     */
    private Agent agent = null;

    /**
     * Initialize the filter.  For this filter, initialization loads the DeviceProfile and initializes the member
     * Ionic Agent object.
     */
    public void init() /*throws ServletException*/ {
        logger.traceEntry();
        // query webapp filter configuration for location of Ionic Secure Enrollment Profile
        final String ionicProfile = getFilterConfig().getInitParameter("ionic-profile");
        agent = null;
        // if
        if (ionicProfile != null) {
            try {
                AgentSdk.initialize(Security.getProvider("SunJCE"));
                // location of Ionic SEP is relative to the webapp classpath
                final URL urlIonicProfile = Resource.resolve(ionicProfile);
                final ProfilePersistor profilePersistor = new DeviceProfilePersistorPlainText(urlIonicProfile);
                // instantiation of the Agent performs an implicit initialization, which loads the DeviceProfile
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

    /**
     * Perform filter operation on request.  All HTTP accesses to the sample webapp will cause this method to be
     * invoked.  When HTTP response body evaluates as being encrypted, {@link GenericFileCipher} is used to decrypt the
     * response, and the decrypted response is passed on to HTTP requester.
     *
     * @param servletRequest  the HTTP request being serviced
     * @param servletResponse the HTTP response to the request
     * @param filterChain     the list of filters configured for this request
     * @throws IOException      on failure to service the request, on failure of Ionic cryptography operation
     * @throws ServletException on {@link FilterChain} failure
     */
    private void doFilter(final HttpServletRequest servletRequest, final HttpServletResponse servletResponse,
                          final FilterChain filterChain) throws IOException, ServletException {
        logger.traceEntry();
        // get the response entity
        final IonicServletResponseWrapper wrapper = new IonicServletResponseWrapper(servletResponse);
        filterChain.doFilter(servletRequest, wrapper);
        final byte[] responseEntity = wrapper.getBytes();
        // filter response headers
        //   if decrypted content is being returned to caller, filter will supply its own Content-Type/Content-Length
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
        // tell HTTP client not to cache
        servletResponse.setHeader("Cache-Control", "no-store, must-revalidate");
        // make decision whether to apply Ionic file cipher based on request file name
        final String servletPath = servletRequest.getServletPath();
        if ((servletPath.contains("ionic") && (agent != null))) {
            try {
                // decrypt content
                final Agent agentFilter = Agent.clone(agent);
                final GenericFileCipher fileCipher = new GenericFileCipher(agentFilter);
                final byte[] responseEntityPlain = fileCipher.decrypt(responseEntity);
                // update HTTP response
                servletResponse.setHeader("Content-Type", "text/plain");
                servletResponse.setHeader("Content-Length", Integer.toString(responseEntityPlain.length));
                servletResponse.getOutputStream().write(responseEntityPlain);
            } catch (IonicException e) {
                servletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            }
        } else {
            // send original (unaltered) response
            servletResponse.setHeader("Content-Type", wrapper.getHeader("Content-Type"));
            servletResponse.setHeader("Content-Length", wrapper.getHeader("Content-Length"));
            servletResponse.getOutputStream().write(responseEntity);
        }
        logger.traceExit();
    }
}
