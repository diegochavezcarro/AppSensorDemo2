package org.owasp.appsensor.demoapp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Random;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.appsensor.DateUtils;

public class UserManager {

	// Hashtable of username to user object
	public static Hashtable<String, AppSensorUser> userStorage = new Hashtable<String, AppSensorUser>();

	// Hashtable of userID to username
	public static Hashtable<Integer, String> idUserMap = new Hashtable<Integer, String>();

	// HashTable of userID to Profile text
	public static Hashtable<Integer, String> idProfileMap = new Hashtable<Integer, String>();

	// HashTable of userID to Status text
	public static Hashtable<Integer, String> idStatusMap = new Hashtable<Integer, String>();

	public static void populateUserTable() {
		AppSensorUser defaultUser1 = new AppSensorUser("charlie", "charlie");
		defaultUser1.ID = 555;
		AppSensorUser defaultUser2 = new AppSensorUser("foo", "foo");
		AppSensorUser defaultUser3 = new AppSensorUser("sue", "sue");
		AppSensorUser defaultUser4 = new AppSensorUser("molly", "molly");
		AppSensorUser defaultUser5 = new AppSensorUser("bob", "bob");
		addNewUser(defaultUser1);
		addNewUser(defaultUser2);
		addNewUser(defaultUser3);
		addNewUser(defaultUser4);
		addNewUser(defaultUser5);

		ArrayList<String> names = new ArrayList<String>();
		names.add("Mary");
		names.add("Peter");
		names.add("Paul");
		names.add("George");
		names.add("Fred");
		names.add("Tom");
		names.add("Bill");
		names.add("Angie");
		names.add("Jules");
		names.add("Britney");
		names.add("Liz");

		ArrayList<String> names2 = new ArrayList<String>();
		names2.add("Jones");
		names2.add("Smith");
		names2.add("Adams");
		names2.add("Orwell");
		names2.add("Chen");
		names2.add("Owen");
		names2.add("Thomas");
		names2.add("Lee");
		names2.add("Cook");
		names2.add("Davidson");
		names2.add("Parker");

		ArrayList<String> status = new ArrayList<String>();
		status.add("Going Fishing");
		status.add("Reading a book");
		status.add("Playing guitar");
		status.add("Totally lost");
		status.add("Looking at bears");
		status.add("Running");
		status.add("Swimming");
		status.add("Evading police");
		status.add("Sleeping");
		status.add("At work");
		status.add("Eating a burger");

		for (int usercount = 0; usercount < 100; usercount++) {
			Random r = new Random();
			int randomNum = r.nextInt(10000);

			int rnum = r.nextInt(names.size());
			int rnum2 = r.nextInt(names2.size());
			String name = names.get(rnum) + "_" + names2.get(rnum2) + "_" + randomNum;
			AppSensorUser u = new AppSensorUser(name, "pass");

			int rnum3 = r.nextInt(status.size());
			String newStatus = status.get(rnum3);
			u.setStatus(newStatus);

			addNewUser(u);
		}

		populateFriends(8);

		// String date = (new SimpleDateFormat ("yyyy-MM-dd HH:mm:ss").format (Calendar.getInstance (TimeZone.getDefault ()).getTime ()));

		/*
		 * Message m1=new Message(defaultUser1.getID(),defaultUser2.getID(),date,"Hey how's it going? I hope you like this message. See you later!"); Message m2=new Message(defaultUser1.getID(),defaultUser1.getID(),date,"Where were you the other day? Didn't you get my phone call?"); Message m3=new Message(defaultUser2.getID(),defaultUser1.getID(),date,"Please return my book. I let you borrow it last year!"); Message m4=new
		 * Message(defaultUser2.getID(),defaultUser2.getID(),date,"I think my cat is stuck in a tree. Crud."); MessageManager.AddMessage(m1); MessageManager.AddMessage(m2); MessageManager.AddMessage(m3); MessageManager.AddMessage(m4);
		 * 
		 * System.out.println("Trying to add friends..."); friend.FriendManager.AddFriend(defaultUser1, defaultUser2); friend.FriendManager.AddFriend(defaultUser1, defaultUser4); friend.FriendManager.AddFriend(defaultUser1, defaultUser5); friend.FriendManager.AddFriend(defaultUser2, defaultUser1); friend.FriendManager.AddFriend(defaultUser2, defaultUser3);
		 */

	}

	private static void populateFriends(int numRandomFriends) {
		Set<Integer> userIDs = idUserMap.keySet();
		Object[] userIDsArrays = userIDs.toArray();
		Iterator<Integer> uID = userIDs.iterator();

		while (uID.hasNext()) {
			int id = uID.next().intValue();
			AppSensorUser u = getUserObjectfromID(id);

			for (int k = 0; k < numRandomFriends; k++) {
				Random r = new Random();
				int randomNum = r.nextInt(userIDs.size());

				// add a random friend
				int friendID = Integer.parseInt(userIDsArrays[randomNum].toString());
				if (!(u.containsFriend(friendID))) {
					u.addFriend(friendID);
					AppSensorUser friend = UserManager.getUserObjectfromID(friendID);
					friend.addFriend(u.getID());
				}
			}
		}

	}

	public static void addNewUser(AppSensorUser u) {
		userStorage.put(u.getUsername(), u);
		idUserMap.put(u.getID(), u.getUsername());
	}

	public static String getNameFromID(int ID) {
		return idUserMap.get(ID);
	}

	public static int getTotalUsers() {
		return userStorage.size();
	}

	public static String getLoggedInUser(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		int ownerID = 0;
		if (session != null) {
			if (session.getAttribute("userID") != null) {
				ownerID = Integer.parseInt(session.getAttribute("userID").toString());
			}
		}
		return getNameFromID(ownerID);
	}

	public static AppSensorUser getLoggedInUserObject(HttpServletRequest request) {
		int ownerID = getLoggedInUserID(request);
		if (ownerID != -1) {
			return getUserObjectfromID(ownerID);
		} else {
			return null;
		}

	}

	public static int getLoggedInUserID(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		// int ownerID=Integer.parseInt(session.getAttribute("userID").toString());
		int ownerID = -1;
		if (session != null) {
			if (session.getAttribute("userID") != null) {
				ownerID = Integer.parseInt(session.getAttribute("userID").toString());
			}
		}
		return ownerID;
	}

	public static AppSensorUser getUserObjectfromID(int ID) throws NullPointerException {
		String tempname;
		AppSensorUser u = null;
		if (idUserMap.containsKey(ID)) {
			tempname = idUserMap.get(ID);
			if (userStorage.containsKey(tempname)) {
				u = userStorage.get(tempname);
				return u;
			}
		}
		return null;
		// TODO: add attack detection here
		// throw new NullPointerException(); //Invalid ID submitted let calling class handle this.
	}

	public static AppSensorUser getUserObjectfromName(String name) {
		@SuppressWarnings("unused")
		Hashtable<String, AppSensorUser> userStorage2 = userStorage;
		if (userStorage.containsKey(name)) {
			return userStorage.get(name);
		}
		return null;
	}

	public static boolean validateLogin(HttpServletRequest request, String username, String password) {
		System.out.println("----Validating Login of " + username + "---");
		if (username != null && userStorage.containsKey(username)) { // verify valid user
			AppSensorUser u = (AppSensorUser) userStorage.get(username);
			String StoredPassword = u.getMD5Password();
			boolean acct_locked = u.acct_locked;
			if (acct_locked && u.acct_unlock_time != 0) {
				// it is locked, check the time
				acct_locked = UserManager.checkLockoutTime(u);
				if (acct_locked) {
					long date = DateUtils.getCurrentTime();
					long timetounlock = (u.acct_unlock_time - date) / 100;
					System.out.println("Account locked: Will unlock in < " + timetounlock + " minutes");
				} else {
					System.out.println("Account now unlocked");
				}
			} else if (acct_locked && u.acct_unlock_time != 0) {
				System.out.println("Account locked indefinitely. Admin intervention required");
			}

			String ProvidedPassword = Utility.MD5encode(password);

			// Now verify correct password supplied & acct not locked
			if ((StoredPassword.equals(ProvidedPassword)) && (!acct_locked)) {
				int userID = ((AppSensorUser) userStorage.get(username)).getID();
				HttpSession session = request.getSession(true);
				session.setAttribute("userID", userID);
				u.setSession(session);
				return true;
			}
		}
		return false; // always fail close
	}

	public static ArrayList<Integer> getAllUserIDs() {
		ArrayList<Integer> al = new ArrayList<Integer>();
		for (int x : idUserMap.keySet()) {
			al.add(x);
		}
		Collections.sort(al);
		return al;
	}

	public static boolean checkLockoutTime(AppSensorUser u) {
		boolean acct_still_locked = true;
		long date = DateUtils.getCurrentTime();
		long lockouttime = u.acct_unlock_time;
		if (lockouttime > 0) {
			if (date > lockouttime) {
				setUnlockAccount(u);
				acct_still_locked = false;
			}
		}
		return acct_still_locked;
	}

	public static void setUnlockAccount(AppSensorUser u) {
		u.acct_locked = false;
		u.acct_unlock_time = 0;
	}

	public static void setLockAccountIndefinite(AppSensorUser u) {
		u.acct_locked = true;
		u.acct_unlock_time = 0;
	}

	public static void setLockAccountMinutes(AppSensorUser u, int minutesLocked) {
		u.acct_locked = true;
		long date = DateUtils.getCurrentTime();

		long unlockdate = date + (minutesLocked * 100);
		System.out.println("Locking for minues: " + minutesLocked);
		System.out.println("Current time: " + date);
		System.out.println("Unlock  time: " + unlockdate);
		u.acct_unlock_time = (int) unlockdate;
	}

	public static boolean isSessionValid(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		AppSensorUser user = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(request);
		if (session != null && user != null) {

			boolean sessionValid = request.isRequestedSessionIdValid();
			return sessionValid;
		}
		return false;
	}

	public static void logout(HttpServletRequest request, HttpServletResponse response) {
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.invalidate();
		}
		Cookie[] cookies = request.getCookies();
		for (int ii = 0; ii < cookies.length; ii++) {
			if (cookies[ii] != null) {
				Cookie cookie = cookies[ii];
				cookie.setMaxAge(0);
				cookie.setValue("");
				response.addCookie(cookie);
			}
		}
	}

	public static String getProfile(HttpServletRequest request) {
		String profile = "notloggedin";
		int userID = UserManager.getLoggedInUserID(request);
		if (userID != -1) {
			AppSensorUser u = getUserObjectfromID(userID);
			if (u != null) {
				profile = u.getProfile();
			}
		}
		return profile;
	}

	public static void setProfile(HttpServletRequest request, String newProfile) {
		int userID = UserManager.getLoggedInUserID(request);
		AppSensorUser u = getUserObjectfromID(userID);
		if (u != null) {
			u.setProfile(newProfile);
		}
		// IDProfileMap.put(userID, newProfile);

	}

	public static String getStatus(HttpServletRequest request) {
		String status = "notloggedin";
		int userID = UserManager.getLoggedInUserID(request);
		if (userID != -1) {
			AppSensorUser u = getUserObjectfromID(userID);
			if (u != null) {
				status = u.getStatus();
			}
		}
		return status;
	}

	public static void setStatus(HttpServletRequest request, String newStatus) {
		int userID = UserManager.getLoggedInUserID(request);
		AppSensorUser u = getUserObjectfromID(userID);
		if (u != null) {
			u.setStatus(newStatus);
		} else {
			// redirect to login page
		}

		// IDStatusMap.put(userID, newStatus);
	}

	public static void addFriendRequest(int senderUserID, int receiverUserID) {
		AppSensorUser sender = getUserObjectfromID(senderUserID);
		sender.addPendingFriendRequest(receiverUserID);
		AppSensorUser receiver = getUserObjectfromID(receiverUserID);
		receiver.addFriendRequest(senderUserID);
	}

	public static void resolveFriendRequest(int senderUserID, int receiverUserID, int accept) {
		AppSensorUser sender = getUserObjectfromID(senderUserID);
		AppSensorUser receiver = getUserObjectfromID(receiverUserID);
		if (accept == 1) {
			if (receiver.getFriendRequestList().contains(senderUserID) && sender.getPendingFriendRequestList().contains(receiverUserID)) {
				receiver.addFriend(senderUserID);
				sender.addFriend(receiverUserID);
			} else {
				// attack detection here
				throw new IllegalArgumentException();
			}
		}
		receiver.removeFriendRequest(senderUserID);
		sender.removePendingFriendRequest(receiverUserID);
	}

	public static void logout(AppSensorUser u) {
		System.out.println("Logging out user " + u.getUsername());
		if (u.session != null) {
			u.session.invalidate();
		}
	}
}
