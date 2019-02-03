package org.owasp.appsensor.demoapp;

import java.io.IOException;
import java.util.Date;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.appsensor.APPSENSOR;
import org.owasp.appsensor.AppSensorServiceController;
import org.owasp.appsensor.trendmonitoring.TrendEvent;

/**
 * Servlet Filter implementation class AppSensorLoggerFilter
 */
public class AppSensorLoggerFilter implements Filter {

	/**
	 * Default constructor.
	 */
	public AppSensorLoggerFilter() {
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
		
		//log for trend monitoring
		APPSENSOR.trendLogger().log(
				new TrendEvent(new Date(), request.getRequestURI(), 
						APPSENSOR.asUtilities().getCurrentUser().getAccountName(), 
						request.getRemoteAddr()
				)
		);
		
		if (org.owasp.appsensor.demoapp.UserManager.isSessionValid(request)) {
			// is page disabled or active?
			// System.out.println("Filter sees: "+req.getRequestURI());
			boolean isActive = AppSensorServiceController.isServiceActive(request.getRequestURI());
			if (!(isActive)) {
				System.out.println("Not Active, redirecting to locked page");
				Long reactivation = AppSensorServiceController.getServiceReactivationTime(request.getRequestURI(), APPSENSOR.asUtilities().getCurrentUser());
				response.sendRedirect("appsensor_locked.jsp?time=" + reactivation);
				// important: can't add chain.dofilter here. else, blocking by appsensor is negated
			} else { 
				// log the request with appsensor
				org.owasp.appsensor.demoapp.AppSensorLogger.log(request);
				// send the user to the page
				chain.doFilter(req, res);
			}
		} else {
			// chain.doFilter(request, response);
			chain.doFilter(req, res);
		}
	}

	/**
	 * @see Filter#init(FilterConfig)
	 */
	public void init(FilterConfig fConfig) throws ServletException {
	}

}
