package org.owasp.appsensor.demoapp;

import java.util.ArrayList;

import org.owasp.appsensor.DateUtils;

public class DemoUtils {
	/*
	 * 
	 */
	
	public static ArrayList<String> monitorUserFriends(String user, int interval, int duration) {
		long currentTime = DateUtils.getCurrentTime();
		long endTime = currentTime + duration; // duration specified in seconds

		ArrayList<String> friendHistory = new ArrayList<String>();
		org.owasp.appsensor.demoapp.AppSensorUser u = org.owasp.appsensor.demoapp.UserManager.getUserObjectfromName(user);
		if (u == null) {
			return null;
		}

		String record = u.getFriendCount() + "," + currentTime;
		while (currentTime < endTime) {
			try {
				Thread.sleep((long) interval * 1000);
			} catch (InterruptedException e) {
			}
			record = u.getFriendCount() + "," + currentTime;
			friendHistory.add(record);
			currentTime = currentTime + 1;
		}

		return friendHistory;
	}

}
