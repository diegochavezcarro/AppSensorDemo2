package org.owasp.appsensor.demoapp;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.filters.SecurityWrapperRequest;

public class ASSecurityWrapperRequest extends SecurityWrapperRequest {

    /**
     * Construct a safe request that overrides the default request methods with
     * safer versions.
     * 
     * @param request The {@code HttpServletRequest} we are wrapping.
     */
    public ASSecurityWrapperRequest(HttpServletRequest request) {
    	super( request );
    }

    private HttpServletRequest getHttpServletRequest() {
    	return (HttpServletRequest)super.getRequest();
    }
    
    /**
     * jtm - had to copy and override this method to get it to allow nulls
     * 
     * Returns the path info from the HttpServletRequest after canonicalizing
     * and filtering out any dangerous characters.
     * @return Returns any extra path information, appropriately scrubbed,
     *         associated with the URL the client sent when it made this request.
     */
    public String getPathInfo() {
        String path = getHttpServletRequest().getPathInfo();
        String clean = "";
        try {
            clean = ESAPI.validator().getValidInput("HTTP path: " + path, path, "HTTPPath", 150, true);
        } catch (ValidationException e) {
            // already logged
        }
        return clean;
    }
}
