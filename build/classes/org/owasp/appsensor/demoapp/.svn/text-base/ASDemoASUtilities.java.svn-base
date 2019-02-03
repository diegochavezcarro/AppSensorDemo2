package org.owasp.appsensor.demoapp;

import javax.servlet.http.HttpServletRequest;

import org.owasp.appsensor.ASLogger;
import org.owasp.appsensor.ASUser;
import org.owasp.appsensor.ASUtilities;
import org.owasp.appsensor.reference.adapters.ESAPIASLogger;
import org.owasp.esapi.ESAPI;

public class ASDemoASUtilities implements ASUtilities {
	public ASUser getCurrentUser() {
		return new ASDemoASUserAdapter();
	}
	public ASLogger getLogger(String className) {
		return new ESAPIASLogger(className);
	}
	public HttpServletRequest getCurrentRequest() {
		return ESAPI.httpUtilities().getCurrentRequest();
	}
}
