<%@page import="org.owasp.appsensor.demoapp.Utility"%>
<%@page import="org.owasp.appsensor.demoapp.*"%>
<%@page import="org.owasp.appsensor.*"%>
<%@page import="org.owasp.appsensor.intrusiondetection.*"%>
<%@page import="java.util.*"%>
<%@page import="org.owasp.esapi.*"%>
<%@page import="org.owasp.esapi.errors.*"%>

<html>
<body>

<h1>Attacks Observed For Current User:</h1><br>

<table border="1"><tr>
<td>TimeStamp</td>
<td>EventCode</td>
<td>Location</td>
<td>LogMessage</td>
<td>User</td>

</tr> 
<% 
	try {
		List<IntrusionRecord> allRecords = new AppSensorIntrusionDetector().getIntrusionStore().getAllIntrusionRecords();
		for (IntrusionRecord air : allRecords) {
			List<AppSensorIntrusion> aieCopy = air.getCopyIntrusionsObserved();
			 
			for (AppSensorIntrusion intrusion : aieCopy) {
					
				long timestamp = intrusion.getTimeStamp(); 
				java.util.Date d = new java.util.Date(timestamp);  
				out.println("<tr>");
				out.println("<td>"+d.toString()+"</td>");
				out.println("<td>"+ESAPI.encoder().encodeForHTML(intrusion.getEventCode())+"</td>");
				out.println("<td>"+ESAPI.encoder().encodeForHTML(intrusion.getLocation())+"</td>");
				out.println("<td>"+ESAPI.encoder().encodeForHTML(intrusion.getSecurityExceptionLogMessage())+"</td>");
				out.println("<td>"+ESAPI.encoder().encodeForHTML(intrusion.getUser().getAccountName())+"</td>");
				out.println("</tr>");		
				
			}	
		}
	}catch(NullPointerException e){
		out.print("<b>No Attacks Recorded</b><br><br>");
	}
out.print("</table>");
%>




<%@include file="../footer.jsp" %>
