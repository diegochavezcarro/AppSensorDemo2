package org.owasp.appsensor.demoapp;

import java.util.Date;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.owasp.appsensor.DateUtils;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;

public class AppSensorLogger {

	public static void log(ServletRequest request) {

		HttpServletRequest req = (HttpServletRequest) request;

		boolean shouldLog = true;
		/*
		 * if (req.getRequestURI().endsWith(".jpg") || req.getRequestURI().endsWith(".css")){ shouldLog=false; }
		 */
		if (shouldLog) {
			Long currentTime = DateUtils.getCurrentTime();

			String logEntry = "time:" + new Date(currentTime) + ";" + "remoteAddr:" + req.getRemoteAddr() + ";" + "remoteHost:" + req.getRemoteHost() + ";" + "requestURL:" + req.getRequestURL() + ";" + "requestURI:" + req.getRequestURI() + ";" + "contextPath:" + req.getContextPath() + ";" + "queryString:" + req.getQueryString();

			final Logger esapiLogger = ESAPI.getLogger("AppSensorTrendMonitor");
			esapiLogger.info(Logger.EVENT_SUCCESS, logEntry);
		}

	}

}
