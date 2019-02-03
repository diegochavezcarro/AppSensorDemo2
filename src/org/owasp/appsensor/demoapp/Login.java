package org.owasp.appsensor.demoapp;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Servlet implementation class Login
 */
public class Login extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#HttpServlet()
	 */
	public Login() {
		super();
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		PrintWriter pw = response.getWriter();
		pw.print("This is a get to the login. Eventually throw error");
		String newStatus = "";
		newStatus = Utility.safeGetParam("status", request);
		pw.println("You sent me the following value for status:" + newStatus);
		pw.println("<a href=\"res://ieframe.dll/invalidcert.htm\">click</a>");
	}

	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		if (UserManager.getTotalUsers() < 1) {
			Utility.configureSystem();

		}
		// PrintWriter pw = response.getWriter();

		if (UserManager.validateLogin(request, request.getParameter("username"), request.getParameter("password"))) {

			// pw.println("Success<br>");
			// pw.println("Get Current AppSensorUser: "+UserManager.getLoggedInUser(request));
			HttpServletRequest httpRequest = request;
			HttpSession session = httpRequest.getSession(true);

			int userID = ((AppSensorUser) UserManager.userStorage.get(request.getParameter("username"))).getID();
			session.setAttribute("userID", userID);

			RequestDispatcher dispatcher = request.getRequestDispatcher("/home.jsp");
			dispatcher.forward(request, response);
		} else {
			response.sendRedirect("login.jsp");

		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */

}
