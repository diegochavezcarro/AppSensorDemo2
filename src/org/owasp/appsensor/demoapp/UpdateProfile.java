package org.owasp.appsensor.demoapp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.appsensor.errors.AppSensorException;

/**
 * Servlet implementation class UpdateProfile
 */
public class UpdateProfile extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public UpdateProfile() {
		super();
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// to simplify worm creation
		doPost(request, response);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	@SuppressWarnings("unchecked")
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// Contains no input validation - security issue by design
		String newStatus = Utility.safeGetParam("status", request);
		String newProfile = Utility.safeGetParam("profile", request);
		//AppSensorUser user = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(request);

		// @AppSensor Attack Detection - IE4
		if (!(request.getParameterMap().containsKey("status")) || !(request.getParameterMap().containsKey("profile"))) {
			new AppSensorException("IE4", "AppSensorUser Message", "Tampering with POST to remove expected posted paramaters");
		}
		ArrayList<String> attackPatterns = new ArrayList<String>();
		attackPatterns.add("\"><script>");
		attackPatterns.add("script.*document.cookie");
		attackPatterns.add("<script>");
		attackPatterns.add("<IMG.*SRC.*=.*script");
		attackPatterns.add("<iframe>.*</iframe>");

		// old way
		ArrayList<String> params = new ArrayList<String>();
		params.add(newStatus);
		params.add(newProfile);
		// Iterator<String> paramIterator=params.iterator();

		// new way
		HashMap<String, String> params2 = new HashMap<String, String>();
		Enumeration<String> parameterNames = request.getParameterNames();
		while (parameterNames.hasMoreElements()) {
			String nextParameterName = parameterNames.nextElement().trim();
			String nextParameterValue = request.getParameter(nextParameterName);
			params2.put(nextParameterName, nextParameterValue);
		}

		Collection<String> parameterNames2 = params2.keySet();
		Iterator<String> parameterNameIterator = parameterNames2.iterator();
		while (parameterNameIterator.hasNext()) {
			String parameterNameToVerify = parameterNameIterator.next();
			String parameterValueToVerify = params2.get(parameterNameToVerify);

			Iterator<String> iteratorAttackPatterns = attackPatterns.iterator();
			if (null != newStatus) {
				while (iteratorAttackPatterns.hasNext()) {
					if (null != Utility.regexFind(parameterValueToVerify, iteratorAttackPatterns.next())) {
						// @AppSensor Attack Detection - IE1
						// @AppSensor Attacker is sending a XSS attempt
						new AppSensorException("IE1", "AppSensorUser Message IE1", "Attacker is sending a likely XSS attempt (" + parameterValueToVerify + ") within parameter \"" + parameterNameToVerify + "\"");
						newStatus = "xxxx";
						newProfile = "xxxx";
					}
				}
			}
		}

		/*
		 * while(paramIterator.hasNext()){ String parameterToVerify=paramIterator.next();
		 * 
		 * Iterator<String> iteratorAttackPatterns=attackPatterns.iterator(); if (null!=newStatus){ while(iteratorAttackPatterns.hasNext()){ if (null!=Utility.regexFind(parameterToVerify, iteratorAttackPatterns.next())){ //@AppSensor Attack Detection - IE1 //@AppSensor Attacker is sending a XSS attempt new AppSensorIntrusionException(request.getServletPath(), "IE1", user,"AppSensorUser Message IE1" ,"Attacker is sending a likely XSS attempt ("+parameterToVerify+") within parameter "+parameterToVerify);
		 * newStatus="xxxx"; newProfile="xxxx"; } } } }
		 */
		if (null != newStatus && newStatus.length() > 0) {
			UserManager.setStatus(request, newStatus);
			System.out.println("Updating Status to " + newStatus);
		}
		if (null != newStatus && newProfile.length() > 0) {
			UserManager.setProfile(request, newProfile);
			System.out.println("Updating Profile to " + newProfile);
		}
		try {
			response.sendRedirect("updateProfile.jsp");
		} catch (Exception e) {
			// do nothing. this is caused when page is locked and two redirects are attempted at once
		}

		// response.setHeader("Location","https://localhost:8443/AppSensorDemo/updateProfile.jsp");

	}

}
