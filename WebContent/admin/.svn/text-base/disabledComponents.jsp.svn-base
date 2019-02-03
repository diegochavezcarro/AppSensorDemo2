<%@page import="org.owasp.appsensor.demoapp.Utility"%>
<%@page import="org.owasp.appsensor.demoapp.*"%>
<%@page import="org.owasp.appsensor.*"%>
<%@page import="org.owasp.appsensor.intrusiondetection.*"%>
<%@page import="java.util.*"%>
<%@page import="org.owasp.esapi.*"%>
<%@page import="org.owasp.esapi.errors.*"%>
<html>
<body>

<h1>Disabled Components:</h1><br>

<table border="1">
	<tr>
		<th>Service</th>
		<th>Reactivation Time</th>
	</tr>
<%

try {
	Hashtable<String, AppSensorServiceMonitor> serviceStorage = AppSensorServiceController.getServiceStorage();
	
	for (String service : serviceStorage.keySet()) {
		AppSensorServiceMonitor monitor = (AppSensorServiceMonitor)serviceStorage.get(service);
		if (! monitor.isActive()) {
			out.println("<tr>");
			out.println("<td>"+ESAPI.encoder().encodeForHTML(service)+"</td>");
			
			long reActivateTime = monitor.getReActivateTime();
			
			if (reActivateTime == AppSensorServiceMonitor.PERMANENT_LOCK_DURATION) {
				out.println("<td>"+ESAPI.encoder().encodeForHTML(service)+"</td>");
			} else {
				Date displayDate = new Date(reActivateTime);
				out.println("<td>"+ESAPI.encoder().encodeForHTML(displayDate.toString())+"</td>");
			}
			
			out.println("</tr>");
		}
	}

} catch(Exception e) {
	out.println("<b>No Attacks Recorded</b><br><br>");
}	
out.print("</table>");
%>
</table>

<h1>Disabled Components (User Specific):</h1><br>

<table border="1">
	<tr>
		<th>Service</th>
		<th>User</th>
		<th>Reactivation Time</th>
	</tr>

<%
try {
	Hashtable<String, AppSensorServiceMonitor> perUserServiceStorage = AppSensorServiceController.getPerUserServiceStorage();
	
	for (String service : perUserServiceStorage.keySet()) {
		AppSensorServiceMonitor monitor = (AppSensorServiceMonitor)perUserServiceStorage.get(service);
		if (! monitor.isActive()) {
			String[] serviceUserArray = service.split("--");
			String serviceName = serviceUserArray[0].trim();
			long userId = Long.parseLong(serviceUserArray[1].trim());
			User user = ESAPI.authenticator().getUser(userId);
			String userName = user.getAccountName();
			
			out.println("<tr>");
			out.println("<td>"+ESAPI.encoder().encodeForHTML(serviceName)+"</td>");
			out.println("<td>"+ESAPI.encoder().encodeForHTML(userName)+"</td>");
			
			long reActivateTime = monitor.getReActivateTime();
			
			if (reActivateTime == AppSensorServiceMonitor.PERMANENT_LOCK_DURATION) {
				out.println("<td>PERMANENTLY LOCKED</td>");
			} else {
				Date displayDate = new Date(reActivateTime);
				out.println("<td>"+ESAPI.encoder().encodeForHTML(displayDate.toString())+"</td>");
			}
			
			out.println("</tr>");
		}
	}

} catch(Exception e) {
	out.println("<b>No Attacks Recorded</b><br><br>");
}	
out.print("</table>");
%>
</table>



<%@include file="../footer.jsp" %>
