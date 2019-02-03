/**
 * OWASP AppSensor
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * AppSensor project. For details, please see
 * <a href="http://www.owasp.org/index.php/Category:OWASP_AppSensor_Project">
 * 	http://www.owasp.org/index.php/Category:OWASP_AppSensor_Project</a>.
 *
 * Copyright (c) 2010 - The OWASP Foundation
 * 
 * AppSensor is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Michael Coates <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author John Melton <a href="http://www.jtmelton.com/">jtmelton</a>
 * @created 2010
 */
package org.owasp.appsensor.demoapp.trend;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.owasp.appsensor.errors.AppSensorException;
import org.owasp.appsensor.errors.AppSensorSystemException;
import org.owasp.appsensor.trendmonitoring.TrendEvent;
import org.owasp.appsensor.trendmonitoring.reference.InMemoryTrendDataStore;

/**
 * This class is a proof of concept class to display some of the possible ways 
 * that different user and system trend events might be detected.  It uses 
 * the "toy" in memory data store to monitor events (application accesses) and then 
 * creates (not throws) AppSensorExceptions when a trend is determined to be an attack.
 * 
 * @author Michael Coates (michael.coates .at. owasp.org) 
 *         <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author John Melton (jtmelton .at. gmail.com)
 *         <a href="http://www.jtmelton.com/">jtmelton</a>
 * @since June 17, 2010
 */
public class InMemoryTrendMonitor {
	
	private static String LOGIN_URI = "/AppSensorDemo2/Login";
	private static String LOGOUT_URI = "/AppSensorDemo2/logout.jsp";
	
	/**
	 * check if a user accesses a given page too many times to be normal
	 */
	public static void checkUT1() {
		//let's just say 100 times in an hour for a given user
		HashMap<String, List<TrendEvent>> trends = 
			InMemoryTrendDataStore.getInstance().getCopyOfAllEventsByUserAddress();
		
		Calendar cal = new GregorianCalendar();
		cal.add(Calendar.HOUR, -1);	//go back 1 hr
		Date oneHourAgo = cal.getTime();
		
		for (String userAddress : trends.keySet()) {
			List<TrendEvent> eventsForUser = trends.get(userAddress);
			HashMap<String, Integer> resourceUsageMap = new HashMap<String, Integer>();
			
			for (TrendEvent te : eventsForUser) {
				if (te.getTime().after(oneHourAgo)) {	//only check issues in the last hour
					String resource = te.getResourceAccessed();
					if (resourceUsageMap.containsKey(resource)) {
						Integer i = resourceUsageMap.get(resource);
						i++;	//add 1
						resourceUsageMap.put(resource, i);
					} else {	//resource is not yet in map
						resourceUsageMap.put(resource, 1);
					}
				}
			}
			
			for (String resource : resourceUsageMap.keySet()) {
				int numberOfAccesses = resourceUsageMap.get(resource);
				if (numberOfAccesses >= 100) {
					//over limit, fire violation
					new AppSensorException("UT1", "AppSensorUser Message UT1", "Attacker at address [" + userAddress + "] has sent [" +
							numberOfAccesses + "] requests to resource [" + resource + "] in the last hour");
				}
			}
		}

	}

	/**
	 * check if a user accesses too many pages in a short period of time to be normal
	 */
	public static void checkUT2() {
		//let's just say 300 times in an hour for a given user
		HashMap<String, List<TrendEvent>> trends = 
			InMemoryTrendDataStore.getInstance().getCopyOfAllEventsByUserAddress();
		
		Calendar cal = new GregorianCalendar();
		cal.add(Calendar.MINUTE, -5);	//go back 5 minutes
		Date fiveMinutesAgo = cal.getTime();
		
		for (String userAddress : trends.keySet()) {
			List<TrendEvent> eventsForUser = trends.get(userAddress);
			
			int numberOfAccesses = 0;
			for (TrendEvent te : eventsForUser) {
				if (te.getTime().after(fiveMinutesAgo)) {	//only check issues in the last 5 minutes
					numberOfAccesses++;
				}
			}
			
			if (numberOfAccesses >= 300) {
				//over limit, fire violation
				new AppSensorException("UT2", "AppSensorUser Message UT2", "Attacker at address [" + userAddress + "] has sent [" +
						numberOfAccesses + "] requests to the application in the last 5 minutes");
			}
		}

	}

	/**
	 * check if user deviates from normal access for overall site - sharp increase in usage
	 */
	public static void checkUT3() {
		HashMap<String, List<TrendEvent>> trends = 
			InMemoryTrendDataStore.getInstance().getCopyOfAllEventsByUserAddress();
		
		Calendar cal = new GregorianCalendar();
		cal.add(Calendar.HOUR, -24);	//go back 1 day
		Date oneDayAgo = cal.getTime();
		
		for (String userAddress : trends.keySet()) {
			List<TrendEvent> eventsForUser = trends.get(userAddress);
			Date firstAccess = new GregorianCalendar().getTime();
			for (TrendEvent te : eventsForUser) {
				if (te.getTime().before(firstAccess)) {
					firstAccess = te.getTime();
				}
			}
			
			//now we have the firstAccess set to the earliest access 
			//average the number of accesses/day for all days from first access through yesterday
			//and compare that to today's access numbers
			int beforeTodayCount = 0;
			int todayCount = 0;
			
			for (TrendEvent te : eventsForUser) {
				if (te.getTime().before(oneDayAgo)) {
					beforeTodayCount++;
				}
				if (te.getTime().after(oneDayAgo)) {
					todayCount++;
				}
			}
			
			//have the count - now let's get the # of days between first access and yesterday
			long differenceInDaysMillis = oneDayAgo.getTime() - firstAccess.getTime();
			long differenceInDays = differenceInDaysMillis / (24 * 60 * 60 * 1000); 
			
			if (differenceInDays < 1) {
				differenceInDays = 1;	//reset if too small
			}
			
			long average = beforeTodayCount / differenceInDays;	
			
			if (todayCount > (average * 20)) {	//if usage jumps more than 20X average
				//over limit, fire violation
				new AppSensorException("UT3", "AppSensorUser Message UT3", "Attacker at address [" + userAddress + "] has sent [" +
						todayCount + "] requests to the application in the last day when the previous per-day access average" +
								"for this user was [" + average + "]");
			}
		}
	}

	/**
	 * check if user deviates from normal access for specific function - sharp increase in usage
	 */
	public static void checkUT4() {
		HashMap<String, List<TrendEvent>> trends = 
			InMemoryTrendDataStore.getInstance().getCopyOfAllEventsByUserAddress();
		
		Calendar cal = new GregorianCalendar();
		cal.add(Calendar.HOUR, -24);	//go back 1 day
		Date oneDayAgo = cal.getTime();
		
		for (String userAddress : trends.keySet()) {
			List<TrendEvent> eventsForUser = trends.get(userAddress);
			Set<String> uniqueResourcesForUser = new HashSet<String>();
			
			for (TrendEvent te : eventsForUser) {
				uniqueResourcesForUser.add(te.getResourceAccessed());
			}

			for (String resourceAccessedByUser : uniqueResourcesForUser) {
				Date firstAccess = new GregorianCalendar().getTime();
				for (TrendEvent te : eventsForUser) {
					if (resourceAccessedByUser.equals(te.getResourceAccessed())) {
						if (te.getTime().before(firstAccess)) {
							firstAccess = te.getTime();
						}
					}
				}
				//now we have the firstAccess set to the earliest access 
				//average the number of accesses/day for all days from first access through yesterday
				//and compare that to today's access numbers
				int beforeTodayCount = 0;
				int todayCount = 0;
				
				for (TrendEvent te : eventsForUser) {
					if (resourceAccessedByUser.equals(te.getResourceAccessed())) {
						if (te.getTime().before(oneDayAgo)) {
							beforeTodayCount++;
						}
						if (te.getTime().after(oneDayAgo)) {
							todayCount++;
						}
					}
				}
				
				//have the count - now let's get the # of days between first access and yesterday
				long differenceInDaysMillis = oneDayAgo.getTime() - firstAccess.getTime();
				long differenceInDays = differenceInDaysMillis / (24 * 60 * 60 * 1000); 
				
				if (differenceInDays < 1) {
					differenceInDays = 1;	//reset if too small
				}
				
				long average = beforeTodayCount / differenceInDays;	
				
				if (todayCount > (average * 20)) {	//if usage jumps more than 20X average
					//over limit, fire violation
					new AppSensorException("UT4", "AppSensorUser Message UT4", "Attacker at address [" + userAddress + "] has sent [" +
							todayCount + "] requests to the resource [" + resourceAccessedByUser + "] in the last day when the previous per-day access average" +
									"for this user was [" + average + "]");
				}
			}
		}
	}

	/**
	 * check if login is accessed much more frequently (indicating worm)
	 */
	public static void checkSTE1() {
		Calendar cal = new GregorianCalendar();
		cal.add(Calendar.HOUR, -2);	//go back 2 hours
		Date twoHoursAgo = cal.getTime();
		
		cal = new GregorianCalendar();
		cal.add(Calendar.HOUR, -1);	//go back 1 hour
		Date oneHourAgo = cal.getTime();
		
		List<TrendEvent> allEvents = InMemoryTrendDataStore.getInstance().getCopyOfAllEvents();
		
		int cnt2hrsago = 0;
		int cntlasthour = 0;
		
		for (TrendEvent te : allEvents) {
			String resource = te.getResourceAccessed();
			Date date = te.getTime();
			if (resource.equals(LOGIN_URI)) {
				if (date.after(twoHoursAgo) && date.before(oneHourAgo)) {
					cnt2hrsago++;
				} else if (date.after(oneHourAgo)) {
					cntlasthour++;
				}
				//ignore other cases
			}
		}
		
		if (cntlasthour > (cnt2hrsago * 5)) {
			//over limit, fire violation
			new AppSensorSystemException("STE1", "AppSensorUser Message STE1", "System login resource [" + LOGIN_URI + "] has seen sharply increased " +
					"activity in the last hour.  Two hours ago the number of accesses was [" +
					cnt2hrsago + "] and there have been [" + cntlasthour + "] accesses in the last hour");
		}
	}

	/**
	 * check if logout is accessed much more frequently (indicating worm)
	 */
	public static void checkSTE2() {
		Calendar cal = new GregorianCalendar();
		cal.add(Calendar.HOUR, -2);	//go back 2 hours
		Date twoHoursAgo = cal.getTime();
		
		cal = new GregorianCalendar();
		cal.add(Calendar.HOUR, -1);	//go back 1 hour
		Date oneHourAgo = cal.getTime();
		
		List<TrendEvent> allEvents = InMemoryTrendDataStore.getInstance().getCopyOfAllEvents();
		
		int cnt2hrsago = 0;
		int cntlasthour = 0;
		
		for (TrendEvent te : allEvents) {
			String resource = te.getResourceAccessed();
			Date date = te.getTime();
			if (resource.equals(LOGOUT_URI)) {
				if (date.after(twoHoursAgo) && date.before(oneHourAgo)) {
					cnt2hrsago++;
				} else if (date.after(oneHourAgo)) {
					cntlasthour++;
				}
				//ignore other cases
			}
		}
		
		if (cntlasthour > (cnt2hrsago * 5)) {
			//over limit, fire violation
			new AppSensorSystemException("STE2", "AppSensorUser Message STE2", "System logout resource [" + LOGOUT_URI + "] has seen sharply increased " +
					"activity in the last hour.  Two hours ago the number of accesses was [" +
					cnt2hrsago + "] and there have been [" + cntlasthour + "] accesses in the last hour");
		}
	}

	/**
	 * check if any resource (other than login or logout) is accessed much more frequently (indicating worm)
	 */
	public static void checkSTE3() {
		Calendar cal = new GregorianCalendar();
		cal.add(Calendar.HOUR, -2);	//go back 2 hours
		Date twoHoursAgo = cal.getTime();
		
		cal = new GregorianCalendar();
		cal.add(Calendar.HOUR, -1);	//go back 1 hour
		Date oneHourAgo = cal.getTime();
		
		HashMap<String, List<TrendEvent>> eventsByResource = InMemoryTrendDataStore.getInstance().getCopyOfAllEventsByResource();
		
		for (String resource : eventsByResource.keySet()) {
			if ((! resource.equals(LOGIN_URI)) && (! resource.equals(LOGOUT_URI))) {
				int cnt2hrsago = 0;
				int cntlasthour = 0;
				
				List<TrendEvent> allEvents = eventsByResource.get(resource);
				for (TrendEvent te : allEvents) {
					Date date = te.getTime();
					if (date.after(twoHoursAgo) && date.before(oneHourAgo)) {
						cnt2hrsago++;
					} else if (date.after(oneHourAgo)) {
						cntlasthour++;
					}
					//ignore other cases
				}
				
				if (cntlasthour > (cnt2hrsago * 5)) {
					//over limit, fire violation
					new AppSensorSystemException("STE3", "AppSensorUser Message STE3", "System resource [" + resource + "] has seen sharply increased " +
							"activity in the last hour.  Two hours ago the number of accesses was [" +
							cnt2hrsago + "] and there have been [" + cntlasthour + "] accesses in the last hour");
				}
			}
		}
		
		
	}
}
