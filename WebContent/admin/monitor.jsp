<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@page import="java.util.ArrayList"%>
<%@page import="java.util.Iterator"%>
<%@page import="org.owasp.appsensor.demoapp.AppSensorUser.*"%>
<%@page import="java.text.SimpleDateFormat"%>
<%@page import="java.util.Calendar"%>
<%@page import="java.util.Hashtable"%>
<%@page import="java.util.TimeZone"%>
<%@page import="org.owasp.appsensor.demoapp.DemoUtils"%>
<%@page import="org.owasp.appsensor.demoapp.Utility"%>


<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>AppSensor Monitoring</title>
</head>
<body>
Monitoring Friend Information....
<%
	String user;
	user = Utility.safeGetParam("user", request);
	int dur = 5;
	String duration = Utility.safeGetParam("duration", request);
	try {
		dur = Integer.parseInt(duration);
	} catch (Exception e) {
	}

	if (user == null) {
		user = "charlie";
	}
	ArrayList<String> friendCountTrack = DemoUtils.monitorUserFriends(user, 1, dur);
	if (!(friendCountTrack == null)) {
		%><br><%=Utility.safeOut(user)%>
		<br>
		<u>FriendCount, TimeStamp</u>
		<br>
		<%
			for (String tracker : friendCountTrack) {
		%>
				<%=Utility.safeOut(tracker)%><br>
		<%
			}
	}
%>




</body>
</html>