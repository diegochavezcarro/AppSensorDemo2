<%@include file="header.jsp"%>
<%@page import="java.util.Enumeration"%>

We're sorry, you've requested a non-existent page.
<br>
Perhaps we've made a mistake, or maybe you are spidering through our
site.
<br> 
<br>
Happy browsing, we're watching...
<br>

<%
	String requestedPage = String.valueOf(request.getAttribute("javax.servlet.error.request_uri"));
	org.owasp.appsensor.demoapp.AppSensorUser user = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(request);
	//@AppSensor Attack Detection - ACE3
	new org.owasp.appsensor.errors.AppSensorException("ACE3", "User Message ACE3", "Attacker is requesting a non-existent (404) page (" + requestedPage + ")");
%> 
<%@include file="footer.jsp"%>