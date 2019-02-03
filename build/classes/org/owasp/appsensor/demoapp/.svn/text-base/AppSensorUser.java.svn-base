package org.owasp.appsensor.demoapp;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Set;

import javax.servlet.http.HttpSession;

import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.AuthenticationHostException;
import org.owasp.esapi.errors.EncryptionException;


public class AppSensorUser implements org.owasp.esapi.User {		//implementing ESAPI's user so we can integrate w/ the framework
	private static final long serialVersionUID = 5919140434334098407L;

	public int ID;
	private String username = "";
	private String passwordMD5Hash = "";

	private String status = "Gone Fishing";
	private String profile = "";

	public boolean acct_locked;
	public int acct_unlock_time;

	// ArrayList of Friends (userID)
	private ArrayList<Integer> FriendList = new ArrayList<Integer>();

	// ArrayList of FriendRequests (userID) - these are requests the user has received
	private ArrayList<Integer> FriendRequestList = new ArrayList<Integer>();

	// ArrayList of PendingFriendRequests - these are request the user has sent out
	private ArrayList<Integer> PendingFriendRequestList = new ArrayList<Integer>();
	public HttpSession session;

	public AppSensorUser(String u, String p) {
		username = u;
		passwordMD5Hash = Utility.MD5encode(p); // yes, md5 is broken. this is a demo app
		profile = "Default Profile for: " + u
				+ "<br><br>The concept of AppSensor is to detect malicious activity within an application before a user is able to identify andexploit a vulnerability. This objective is possible because many vulnerabilities will only be discovered as a result oftrial and error by the attacker. If AppSensor can identify an attacker probing for potential vulnerabilities and takeresponsive action quickly, it may be possible to prevent the attacker from identifying an exploitable vulnerability.";
		ID = Utility.getRandom(999999);
	}

	public String getUsername() {
		return this.username;
	}

	public String toString() {
		return this.username;
	}

	public String getMD5Password() {
		return this.passwordMD5Hash;
	}

	public int getID() {
		return this.ID;
	}

	public void setProfile(String newprofile) {
		this.profile = newprofile;
		System.out.println("Profile is " + newprofile);
	}

	public String getProfile() {
		return this.profile;
	}

	public void addFriend(int id) {
		if (!(UserManager.getNameFromID(id) == null)) {

			FriendList.add(id);
		}
	}

	public void delFriend(int id) {
		if (!(UserManager.getNameFromID(id) == null)) {
			FriendList.remove(id);
		}
	}

	public boolean containsFriend(int userID) {
		return FriendList.contains(userID);
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Integer> getFriends() {
		return (ArrayList<Integer>) FriendList.clone();
	}

	public int getFriendCount() {
		return FriendList.size();
	}

	public void setStatus(String newStatus) {
		this.status = newStatus;

	}

	public String getStatus() {
		return this.status;
	}

	public void addFriendRequest(int userID) {
		if (!(FriendRequestList.contains(userID))) {
			FriendRequestList.add(userID);
		}
	}

	public void removeFriendRequest(int userID) {
		if (FriendRequestList.contains(userID)) {
			FriendRequestList.remove(Integer.valueOf(userID));
		} else {
			// TODO attack detection here
			System.err.println("USER:removeFriendRequest FriendID " + userID + " not present in FriendRequestList");
			System.err.println("Size of friend list for " + this.ID + " is " + FriendRequestList.size());
		}
	}

	@SuppressWarnings("unchecked")
	public ArrayList<Integer> getFriendRequestList() {
		return (ArrayList<Integer>) FriendRequestList.clone();
	}

	public void addPendingFriendRequest(int userID) {
		if (!(PendingFriendRequestList.contains(userID))) {
			PendingFriendRequestList.add(userID);
		}

	}

	public void removePendingFriendRequest(int userID) {
		if (PendingFriendRequestList.contains(userID)) {
			// System.err.println("I am"+this.ID+" "+this.username+" and removing "+userID);
			PendingFriendRequestList.remove(Integer.valueOf(userID));
		} else {
			// TODO attack detection here
			System.err.println("USER:removeFriendRequest FriendID " + userID + " not present in FriendRequestList");
			System.err.println("Size of friend list for " + this.ID + " is " + FriendRequestList.size());
		}

	}

	@SuppressWarnings("unchecked")
	public ArrayList<Integer> getPendingFriendRequestList() {
		return (ArrayList<Integer>) PendingFriendRequestList.clone();
	}

	public void setSession(HttpSession session) {
		this.session = session;

	}

	////////////////////////////////////////////////
	// Overriding User methods below ///////////////
	////////////////////////////////////////////////
	
	@Override
	public void addRole(String arg0) throws AuthenticationException {
		
	}

	@Override
	public void addRoles(Set<String> arg0) throws AuthenticationException {
		
	}

	@Override
	public void addSession(HttpSession arg0) {
		
	}

	@Override
	public void changePassword(String arg0, String arg1, String arg2) throws AuthenticationException, EncryptionException {
		
	}

	@Override
	public void disable() {
		this.acct_locked = true;
	}

	@Override
	public void enable() {
		this.acct_locked = false;
	}

	@Override
	public long getAccountId() {
		return getID();
	}

	@Override
	public String getAccountName() {
		return getUsername();
	}

	@Override
	public String getCSRFToken() {
		return null;
	}

	@SuppressWarnings("unchecked")
	@Override
	public HashMap getEventMap() {
		return null;
	}

	@Override
	public Date getExpirationTime() {
		return null;
	}

	@Override
	public int getFailedLoginCount() {
		return 0;
	}

	@Override
	public Date getLastFailedLoginTime() throws AuthenticationException {
		return null;
	}

	@Override
	public String getLastHostAddress() {
		return null;
	}

	@Override
	public Date getLastLoginTime() {
		return null;
	}

	@Override
	public Date getLastPasswordChangeTime() {
		return null;
	}

	@Override
	public Locale getLocale() {
		return null;
	}

	@Override
	public Set<String> getRoles() {
		return null;
	}

	@Override
	public String getScreenName() {
		return null;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Set getSessions() {
		return null;
	}

	@Override
	public void incrementFailedLoginCount() {
		
	}

	@Override
	public boolean isAnonymous() {
		return false;
	}

	@Override
	public boolean isEnabled() {
		return ! this.acct_locked;
	}

	@Override
	public boolean isExpired() {
		return false;
	}

	@Override
	public boolean isInRole(String arg0) {
		return false;
	}

	@Override
	public boolean isLocked() {
		return false;
	}

	@Override
	public boolean isLoggedIn() {
		return false;
	}

	@Override
	public boolean isSessionAbsoluteTimeout() {
		return false;
	}

	@Override
	public boolean isSessionTimeout() {
		return false;
	}

	@Override
	public void lock() {
		UserManager.setLockAccountIndefinite(this);
	}

	@Override
	public void loginWithPassword(String arg0) throws AuthenticationException {
		
	}

	@Override
	public void logout() {
		UserManager.logout(this);
	}

	@Override
	public void removeRole(String arg0) throws AuthenticationException {
		
	}

	@Override
	public void removeSession(HttpSession arg0) {
		
	}

	@Override
	public String resetCSRFToken() throws AuthenticationException {
		return null;
	}

	@Override
	public void setAccountName(String arg0) {
		
	}

	@Override
	public void setExpirationTime(Date arg0) {
		
	}

	@Override
	public void setLastFailedLoginTime(Date arg0) {
		
	}

	@Override
	public void setLastHostAddress(String arg0) throws AuthenticationHostException {
		
	}

	@Override
	public void setLastLoginTime(Date arg0) {
		
	}

	@Override
	public void setLastPasswordChangeTime(Date arg0) {
		
	}

	@Override
	public void setLocale(Locale arg0) {
		
	}

	@Override
	public void setRoles(Set<String> arg0) throws AuthenticationException {
		
	}

	@Override
	public void setScreenName(String arg0) {
		
	}

	@Override
	public void unlock() {
		
	}

	@Override
	public boolean verifyPassword(String arg0) throws EncryptionException {
		return false;
	}

	@Override
	public String getName() {
		return null;
	}

}
