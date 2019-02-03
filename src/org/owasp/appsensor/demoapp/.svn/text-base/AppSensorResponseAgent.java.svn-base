package org.owasp.appsensor.demoapp;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AppSensorResponseAgent extends HttpServlet {

	private static final long serialVersionUID = 1L;

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		handleRequest(request, response);
		PrintWriter pw = response.getWriter();
		pw.println("Example:");
		pw.println("https://localhost:8443/AppSensorDemo/AppSensorResponseAgent?action=suspendService&service=/AppSensorDemo/updateProfile.jsp&duration=10&timeScale=m");
		// org.owasp.appsensor.demoapp.AppSensorUser u = new org.owasp.appsensor.demoapp.AppSensorUser(null, null);
		//AppSensorResponseAgent?action=suspendService&service=/AppSensorDemo2/friends.jsp&duration=10&timeScale=m
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		handleRequest(request, response);
	}

	private void handleRequest(HttpServletRequest request, HttpServletResponse response) throws IOException {
		// System.out.println("AppSensorResponseAgent");
		PrintWriter pw = response.getWriter();
		pw.println("This is the AppSensorHook");
		String action = "";
		action = request.getParameter("action");
		if (action != null && action != "") {
			pw.println("Received action " + Utility.safeOut(action));

			if (action.equals("suspendService")) {
				String service = Utility.safeGetParam("service", request);
				int duration = Integer.parseInt(Utility.safeGetParam("duration", request)); // TODO: this blows up with non-ints
				String timeScale = Utility.safeGetParam("timeScale", request);
				pw.println("TrendResponseHook: Suspending Service <" + service + "> for <" + duration + "> +<" + timeScale + ">");
				suspendService(service, duration, timeScale);
			} else {
				pw.println("Unkown action received");
			}
		}
	}

	private void suspendService(String service, int duration, String timeScale) {
		// System.out.println("AppSensorResponseAgent: Suspending Service <"+service+"> for <"+duration+"> +<"+timeScale+">");
		org.owasp.appsensor.AppSensorServiceController.disableService(service, duration, timeScale);
	}

}
