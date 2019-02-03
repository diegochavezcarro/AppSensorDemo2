<%@include file="header.jsp"%>

<%@page import="java.text.SimpleDateFormat"%>
<%@page import="java.util.*"%>
<%@page import="org.owasp.appsensor.*"%>
 
<h2>Disabled by AppSensor</h2>
<%
long reActivateTime=0;
try{
 reActivateTime=Long.parseLong(request.getParameter("time"));
}catch(Exception e){}
 
Long currentTime = DateUtils.getCurrentTime();
Long waitTime=reActivateTime-currentTime;

%>

The page you've requested has been temporarily disabled by AppSensor.<br>
<br>
Service will return in <b><%=waitTime / 1000%></b> seconds<br>
Current Time: <%=currentTime %><br>
ReActivate Time: <%=reActivateTime %><br>

<br>

Current Date / Time: <%=new Date(currentTime) %><br>
ReActivate Date / Time: <%=new Date(reActivateTime) %><br>

<%@include file="footer.jsp" %>
