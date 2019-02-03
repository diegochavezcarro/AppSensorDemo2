package org.owasp.appsensor.demoapp;

import javax.servlet.http.HttpServletRequest;

public class Message {
	public static String getMessage() {
		return "<i>Going Fishing</i>";
	}

	public static String getMessage(HttpServletRequest request) {
		int userID = UserManager.getLoggedInUserID(request);
		String status = UserManager.idStatusMap.get(userID);
		if (status != null) {
			return status;
		}

		return "<i>Going Fishing</i>";
	}

	public static String getUserNameFromSessionObject(HttpServletRequest request) {
		return UserManager.getNameFromID(UserManager.getLoggedInUserID(request));
	}

	public static String getUserProfile(HttpServletRequest request) {
		int userID = UserManager.getLoggedInUserID(request);
		String profile = UserManager.idProfileMap.get(userID);
		if (profile != null) {
			return profile;
		}

		return "The concept of AppSensor is to detect malicious activity within an application before a user is able to identify and" + " exploit a vulnerability. This objective is possible because many vulnerabilities will only be discovered as a result of" + " trial and error by the attacker. If AppSensor can identify an attacker probing for potential vulnerabilities and take"
				+ " responsive action quickly, it may be possible to prevent the attacker from identifying an exploitable vulnerability.";
	}
}
