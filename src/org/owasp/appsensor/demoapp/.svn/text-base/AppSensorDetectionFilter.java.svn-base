package org.owasp.appsensor.demoapp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.owasp.appsensor.errors.AppSensorException;

public class AppSensorDetectionFilter implements Filter {

	@SuppressWarnings("unchecked")
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		// HttpServletResponse response = (HttpServletResponse) res;
		//AppSensorUser user = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(request);
		
		// AppSensor - RE1
		if (!(request.getMethod().equalsIgnoreCase("GET") || request.getMethod().equalsIgnoreCase("POST") || request.getMethod().equalsIgnoreCase("HEAD"))) {
			// @AppSensor Attack Detection - RE1
			new AppSensorException("RE1", "AppSensorUser Message RE1", "Attacker is sending an invalid command (" + request.getMethod() + ") to the application");
		}

		// AppSensor - RE2
		ArrayList<String> expectedHeaders = new ArrayList<String>();
		expectedHeaders.add("accept");
		expectedHeaders.add("accept-charset");
		expectedHeaders.add("accept-encoding");
		expectedHeaders.add("accept-language");
		expectedHeaders.add("accept-ranges");
		expectedHeaders.add("authorization");
		expectedHeaders.add("cache-control");
		expectedHeaders.add("connection");
		expectedHeaders.add("content-length");
		expectedHeaders.add("content-type");
		expectedHeaders.add("cookie");
		expectedHeaders.add("date");
		expectedHeaders.add("expect");
		expectedHeaders.add("from");
		expectedHeaders.add("host");
		expectedHeaders.add("if-match");
		expectedHeaders.add("if-modified-since");
		expectedHeaders.add("if-none-match");
		expectedHeaders.add("if-range");
		expectedHeaders.add("if-unmodified-since");
		expectedHeaders.add("keep-alive");
		expectedHeaders.add("max-forwards");
		expectedHeaders.add("pragma");
		expectedHeaders.add("proxy-authorization");
		expectedHeaders.add("range");
		expectedHeaders.add("referer");
		expectedHeaders.add("te");
		expectedHeaders.add("upgrade");
		expectedHeaders.add("user-agent");
		expectedHeaders.add("via");
		expectedHeaders.add("warn");
		expectedHeaders.add("x-bluecoat-via");
		expectedHeaders.add("x-forwarded-for");

		Enumeration<String> headerNames = request.getHeaderNames();
		int numberOfHeaders = 0;
		while (headerNames.hasMoreElements()) {
			numberOfHeaders = numberOfHeaders + 1;
			String nextHeader = headerNames.nextElement().toLowerCase().trim();
			if (null != nextHeader) {
				if (!(expectedHeaders.contains(nextHeader))) {
					// String s=request.getServletPath();
					// @AppSensor Attack Detection - RE2
					/*
					 * Holding off on this one for now, too many false positives and malformed headers caught below new AppSensorIntrusionException(request.getServletPath(), "RE2", user,"AppSensorUser Message RE2" ,"Attacker is sending an invalid header ("+nextHeader+ ") to the application - this detection point is under testing" );
					 */

				}
				String regex = "[^A-Z\\-a-z]{1,20}";
				if (null != Utility.regexFind(nextHeader, regex)) {
					new AppSensorException("RE2", "AppSensorUser Message RE2", "Attacker is sending a malformed header (" + nextHeader + ") to the application ");
				}
			}
		}
		// AppSensor - RE5
		int headerThreshold = 20;
		if (numberOfHeaders > headerThreshold) {
			// @AppSensor Attack Detection - RE5
			new AppSensorException("RE5", "AppSensorUser Message RE5", "Attacker is sending a large number of headers (" + numberOfHeaders + ") to the application");

		}
		// chain.doFilter(request, response);
		chain.doFilter(req, res);
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
	}
	
	@Override
	public void destroy() {	
	}

}