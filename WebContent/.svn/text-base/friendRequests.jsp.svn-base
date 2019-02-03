<%@page import="java.util.ArrayList"%>
<%@page import="org.owasp.appsensor.demoapp.Utility"%>
<%@page import="org.owasp.appsensor.demoapp.*"%>
<%@page import="org.owasp.appsensor.intrusiondetection.*"%>
<%@page import="org.owasp.appsensor.errors.AppSensorException"%>

<b>Pending Friend Requests</b>
<br>
<% 
	int id = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserID(request);
	AppSensorUser u = UserManager.getUserObjectfromID(id);
	ArrayList<Integer> friendRequests = u.getFriendRequestList();
	HttpServletResponse res = (HttpServletResponse) response;
%>
<%
	int profileID = 0;
	int accept = -1;
	String expectedMethod = "GET";
	AppSensorUser user = UserManager.getLoggedInUserObject(request);

	//AppSensorDetector.VerifyRequestMethod(request,request.getServletPath(),user, expectedMethod);

	if (request.getMethod().equalsIgnoreCase(expectedMethod) && request.getParameterMap().containsKey("profileID") && request.getParameterMap().containsKey("accept")) {

		//Check for attacks in parameters
		try {
			profileID = Integer.parseInt(request.getParameter("profileID"));
		} catch (NumberFormatException nfe) {
			//@AppSensor Attack Detection - ACE1
			//Attacker is using direct object tampering in a POST		
			new AppSensorException("ACE1", "User Message ACE", "Direct object tampering with Parameter 'profileID' to add a non-existent ID(");
			profileID = 0;
			accept = -1;
		}
		try {
			accept = Integer.parseInt(request.getParameter("accept"));
		} catch (NumberFormatException nfe) {
			//@AppSensor Attack Detection - ACE1
			//Attacker is using direct object tampering in a POST		
			new AppSensorException("ACE1", "User Message ACE", "Direct object tampering with {arameter 'accept'");
			profileID = 0;
			accept = -1;
		}

		//check if referenced ID is a valid user
		if (UserManager.getNameFromID(profileID) == null) {
			//@AppSensor Attack Detection - ACE1
			new AppSensorException("ACE1", "User Message ACE", "Direct object tampering with Parameter ID to attempt to add a non-existent ID");
			profileID = 0;
			accept = -1;
		}
		//check if friend is already a friend
		if (user.containsFriend(profileID)) {
			new AppSensorException("ACE1", "User Message ACE", "Direct object tampering with Parameter ID to attempt to re-add an existing friend");
		}
		//process the response
		if (accept == 1 || accept == 0) {
			//the executor of this call is the "receiver" of the friend request
			// @AppSensor Detect something happened. We'll try to fix it for you.ion			
			try {
				UserManager.resolveFriendRequest(profileID, u.getID(), accept);
			} catch (IllegalArgumentException e) {
				new AppSensorException("ACE1", "User Message ACE", "Direct object tampering with Parameter ID to attempt to accept/reject non-existent friend request");
			}

		}

	}

	res.sendRedirect("home.jsp");
%>

