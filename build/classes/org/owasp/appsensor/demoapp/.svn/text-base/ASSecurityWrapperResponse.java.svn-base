/**
 * OWASP Enterprise Security API (ESAPI) This file is part of the Open Web
 * Application Security Project (OWASP) Enterprise Security API (ESAPI) project.
 * For details, please see <a
 * href="http://www.owasp.org/index.php/ESAPI">http://
 * www.owasp.org/index.php/ESAPI</a>. Copyright (c) 2007 - The OWASP Foundation
 * The ESAPI is published by OWASP under the BSD license. You should read and
 * accept the LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect
 *         Security</a>
 * @created 2007
 */
package org.owasp.appsensor.demoapp;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.filters.SecurityWrapperResponse;

/**
 * This response wrapper simply overrides unsafe methods in the
 * HttpServletResponse API with safe versions.
 */
public class ASSecurityWrapperResponse extends SecurityWrapperResponse {

    private final Logger logger = ESAPI.getLogger("SecurityWrapperResponse");

    // modes are "log", "skip", "sanitize", "throw"
    private String mode = "log";

    /**
     * Construct a safe response that overrides the default response methods
     * with safer versions.
     * 
     * @param response
     */
    public ASSecurityWrapperResponse(HttpServletResponse response) {
    	super( response );
    }

    /**
     *
     * @param response
     * @param mode
     */
    public ASSecurityWrapperResponse(HttpServletResponse response, String mode) {
    	super( response );
        this.mode = mode;
    }


    private HttpServletResponse getHttpServletResponse() {
    	return (HttpServletResponse)super.getResponse();
    }

    /**
     * Add a cookie to the response after ensuring that there are no encoded or
     * illegal characters in the name and name and value. This method also sets
     * the secure and HttpOnly flags on the cookie. This implementation uses a
     * custom "set-cookie" header instead of using Java's cookie interface which
     * doesn't allow the use of HttpOnly.
     * @param cookie
     */
    public void addCookie(Cookie cookie) {
        String name = cookie.getName();
        String value = cookie.getValue();
        int maxAge = cookie.getMaxAge();
        String domain = cookie.getDomain();
        String path = cookie.getPath();
        boolean secure = cookie.getSecure();

        // validate the name and value
        ValidationErrorList errors = new ValidationErrorList();
        String cookieName = ESAPI.validator().getValidInput("cookie name", name, "HTTPCookieName", 50, false, errors);
        String cookieValue = ESAPI.validator().getValidInput("cookie value", value, "HTTPCookieValue", 5000, true, errors);

        // if there are no errors, then just set a cookie header
        if (errors.size() == 0) {
            String header = createCookieHeader(name, value, maxAge, domain, path, secure);
            this.addHeader("Set-Cookie", header);
            return;
        }

        // if there was an error
        if (mode.equals("skip")) {
            logger.warning(Logger.SECURITY_FAILURE, "Attempt to add unsafe data to cookie (skip mode). Skipping cookie and continuing.");
            return;
        }

        // add the original cookie to the response and continue
        if (mode.equals("log")) {
            logger.warning(Logger.SECURITY_FAILURE, "Attempt to add unsafe data to cookie (log mode). Adding unsafe cookie anyway and continuing.");
            getHttpServletResponse().addCookie(cookie);
            return;
        }

        // create a sanitized cookie header and continue
        if (mode.equals("sanitize")) {
            logger.warning(Logger.SECURITY_FAILURE, "Attempt to add unsafe data to cookie (sanitize mode). Sanitizing cookie and continuing.");
            String header = createCookieHeader(cookieName, cookieValue, maxAge, domain, path, secure);
            this.addHeader("Set-Cookie", header);
            return;
        }

        // throw an exception if necessary or add original cookie header
        throw new IntrusionException("Security error", "Attempt to add unsafe data to cookie (throw mode)");
    }

    private String createCookieHeader(String name, String value, int maxAge, String domain, String path, boolean secure) {
        // create the special cookie header instead of creating a Java cookie
        // Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
        // domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
        String header = name + "=" + value;
        header += "; Max-Age=" + maxAge;
        if (domain != null) {
            header += "; Domain=" + domain;
        }
        if (path != null) {
            header += "; Path=" + path;
        }
        // if ( secure || ESAPI.securityConfiguration().forceSecureCookies() ) {
        header += "; Secure";
        // }
        // if ( ESAPI.securityConfiguration().forceHttpOnly() ) {
        header += "; HttpOnly";
        // }
        return header;
    }

    /**
     * Add a header to the response after ensuring that there are no encoded or
     * illegal characters in the name and name and value. This implementation
     * follows the following recommendation: "A recipient MAY replace any linear
     * white space with a single SP before interpreting the field value or
     * forwarding the message downstream."
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec2.html#sec2.2
     * @param name
     * @param value
     */
    public void addHeader(String name, String value) {
        try {
            String strippedName = StringUtilities.stripControls(name);
            String strippedValue = StringUtilities.stripControls(value);
            String safeName = ESAPI.validator().getValidInput("addHeader", strippedName, "HTTPHeaderName", 20, false);
            String safeValue = ESAPI.validator().getValidInput("addHeader", strippedValue, "HTTPHeaderValue", 500, false);
            getHttpServletResponse().setHeader(safeName, safeValue);
        } catch (ValidationException e) {
            logger.warning(Logger.SECURITY_FAILURE, "Attempt to add invalid header denied", e);
        }
    }
}

