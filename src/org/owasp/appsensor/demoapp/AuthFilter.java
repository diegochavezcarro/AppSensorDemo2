package org.owasp.appsensor.demoapp;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet Filter implementation class LoginFilter
 */
public class AuthFilter implements Filter {

	/**
	 * Default constructor.
	 */
	public AuthFilter() {
	}

	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {
	}

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		// resp.sendRedirect("https://localhost:8443/AppSensorDemo/login.jsp");
		if (org.owasp.appsensor.demoapp.UserManager.isSessionValid(request)) {
			// logged in, continue filters
			// chain.doFilter(request, response);
			chain.doFilter(req, res);
		} else {
			// not logged in, redirect to login page, unless is login request
			// last exception is for REST communication point
			String URI = request.getRequestURI();
			if (URI.contains("login.jsp") || URI.contains("Login") || URI.contains("AppSensorResponseAgent") || URI.contains(".jpg")) {
				chain.doFilter(req, res);
			} else {
				// String redirectURL="https://"+request.getServerName()+":"+request.getServerPort()+"/AppSensorDemo/"+"login.jsp";
				String contextPath = request.getContextPath(); // gives "/AppSensorDemo" as result or wherever this is deployed
				String redirectURL = contextPath + "/login.jsp";
				// resp.sendRedirect("https://localhost:8443/AppSensorDemo/login.jsp");
				response.sendRedirect(redirectURL);
			}
		}

	}

	/**
	 * @see Filter#init(FilterConfig)
	 */
	public void init(FilterConfig fConfig) throws ServletException {
	}

}
