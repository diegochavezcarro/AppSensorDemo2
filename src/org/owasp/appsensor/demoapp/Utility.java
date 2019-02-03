package org.owasp.appsensor.demoapp;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;

public abstract class Utility {

	public static String MD5encode(String value) {
		String encoded_value = "";
		MessageDigest digest = null;
		try {
			digest = java.security.MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		digest.update(value.getBytes());
		byte[] md5hash = digest.digest();
		String hash = new String(md5hash);

		encoded_value = Base64Coder.encodeString(hash);
		return encoded_value;
	}

	public static int getRandom(int maxValue) {
		SecureRandom random = null;
		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte bytes[] = new byte[024 / 8];
		random.nextBytes(bytes);
		return random.nextInt(maxValue);

	}

	/*
	 * public static String getHeader(HttpServletRequest request){ String header=""; header=header+"<table>\n"; header=header+"<tr>\n"; header=header+"<td>\n"; header=header+"Logged in as: <b>"+UserManager.getLoggedInUser (request)+"</b>\n"; header=header+"</td>\n"; header=header+"<td>\n"; header =header+"<a href=\"/se473/servlet/project.HomeServlet\">Home</a>\n"; header=header+"</td>\n"; header=header+"<td>\n";header=header+ "<a href=\"/se473/servlet/project.EditProfile\">Edit Profile</a>\n";
	 * header=header+"</td>\n"; header=header+"<td>\n";header=header+ "<a href=\"/se473/servlet/message.DisplayServlet\">Display Messages</a>\n" ; header=header+"</td>\n"; header=header+"<td>\n";header=header+ "<a href=\"/se473/servlet/message.SendServlet\">Send Message</a>\n"; header=header+"</td>\n"; header=header+"<td>\n"; header=header+"<a href=\"/se473/APPids/project_login.html\">Login Page</a>\n" ; header=header+"</td>\n"; header=header+"</tr>\n"; header=header+"</table>\n";
	 * 
	 * //String security_message=appIDS.IDSManager.GetSecurityMessage(request); header=header+"<font color=\"red\">"+security_message+"</font>";
	 * 
	 * header=header+"<hr>\n"; return header; }
	 */

	public static boolean checkValidSession(HttpServletRequest request, HttpServletResponse response) {
		boolean UserinSession = false;
		if (UserManager.getLoggedInUser(request) == null) {
			UserinSession = false;
		} else {
			UserinSession = true;
		}
		boolean validSession = request.isRequestedSessionIdValid();

		// sessionID must be valid and a username must be registered in the
		// session
		if ((validSession) && (UserinSession)) {
			// System.out.println("SessionID is valid");
			return true;
		} else {
			PrintWriter pw = null;
			try {
				pw = response.getWriter();
			} catch (IOException e) {
				e.printStackTrace();
			}
			System.out.println("Session not valid - redirecting user to homepage");
			pw.println("<meta http-equiv=\"REFRESH\" content=\"0;url=http://localhost:38080/se473/APPids/project_login.html\">");
		}
		return false;
	}

	public static String safeGetParam(String paramName, HttpServletRequest request) {
		String parmValue = "";
		try {
			parmValue = request.getParameter(paramName);
		} catch (Exception e) {
			return null;
		}
		if (parmValue == null) {
			return null;
		}
		return parmValue;
	}

	public static String safeOut(String dirty) {
		// http://www.owasp.org/index.php/How_to_perform_HTML_entity_encoding_in_Java
		String s = dirty;
		StringBuffer buf = new StringBuffer();
		int len = (s == null ? -1 : s.length());

		for (int i = 0; i < len; i++) {
			char c = s.charAt(i);
			if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				buf.append(c);
			} else {
				buf.append("&#" + (int) c + ";");
			}
		}
		return buf.toString();
	}

	// AppSensor related
	public static void configureSystem() {
		// set esapi path
		/*
		 * System.setProperty("org.owasp.esapi.resources","c:\\ESAPI\\"); String resources=System.getProperty("org.owasp.esapi.resources"); System.out.println("org.owasp.esapi.resources= "+resources);
		 */

		// Configure logger
		/*
		 * final String LOG_PROPERTIES_FILE = "c:/resources/log4j.properties"; PropertyConfigurator.configure(LOG_PROPERTIES_FILE);
		 */
		// Setup EASPI Intrusion Detection
		final org.owasp.esapi.Logger esapiLogger = ESAPI.getLogger("AppSensor");
		esapiLogger.info(Logger.EVENT_SUCCESS, "Test log from configuresystem");
//		AppSensorIntrusionDetector appsensorID = new AppSensorIntrusionDetector();
//		ESAPI.setIntrusionDetector(appsensorID);
//		//adding dummy authenticator b/c we need to use the getCurrentUser() method for integration
//		ESAPI.setAuthenticator(new AppSensorDummyESAPIAuthenticator());

		// Populate Users
		UserManager.populateUserTable();

	}

	public static String regexFind(String targetString, String regEx) {
		String foundMatch = null;
		if (targetString == null) {
			return null;
		}

		String RegEx = regEx; // make it case insensitive
		// Compile and get a reference to a Pattern object.
		Pattern pattern = Pattern.compile(RegEx, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
		// Get a Matcher based on the target string.
		Matcher matcher = pattern.matcher(targetString);
		// Find all the matches.
		while (matcher.find()) {
			if (matcher.groupCount() > 0) {
				foundMatch = matcher.group(1).trim();
			} else {
				foundMatch = matcher.group(0).trim();
			}
			return foundMatch;
		}

		return null;
	}

	public static boolean regexContains(String targetString, String regEx) {
		return false;
	}
}
