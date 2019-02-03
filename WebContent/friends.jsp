<%@include file="header.jsp"%>
<%@page import="org.owasp.appsensor.demoapp.*"%>
<%@page import="java.util.ArrayList"%>
<%@page import="org.owasp.appsensor.demoapp.Utility"%>

<b>Friends</b>

<% 
	int id = UserManager.getLoggedInUserID(request);
	AppSensorUser u = UserManager.getUserObjectfromID(id);
	ArrayList<Integer> friends = u.getFriends();
%>
<br>
<a href="addFriend.jsp"> Add a Friend</a>

<table border="0">
	<tr>
		<td align="center">Friend</td>
		<td width="100"></td>
		<td align="center">Status</td>
	</tr>

	<%
		for (int friendId : friends) {
			AppSensorUser friend = UserManager.getUserObjectfromID(friendId);
	%>
	<tr>
		<td>Friend: <b> <a
			href="viewProfile.jsp?profileID=<%=friend.getID()%>"> <%=Utility.safeOut(friend.getUsername())%></a></b></td>
		<td></td>
		<td><%=Utility.safeOut(friend.getStatus())%></td>
	</tr>
	<%
		}
	%>
</table>
<br>
<a href="addFriend.jsp"> Add a Friend</a>

<%@include file="footer.jsp"%>
