package org.owasp.appsensor.demoapp;

import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.EncryptionException;

/**
 * Just a class to override getCurrentUser() for integration w/ ESAPI
 * @author jtmelton
 *
 */
public class AppSensorDummyESAPIAuthenticator implements Authenticator {

	@Override
	public void changePassword(User arg0, String arg1, String arg2, String arg3) throws AuthenticationException {

	}

	@Override
	public void clearCurrent() {
				
	}

	@Override
	public User createUser(String arg0, String arg1, String arg2) throws AuthenticationException {
		AppSensorUser user = new AppSensorUser(arg0, arg1);
		UserManager.addNewUser(user);
		return user;
	}

	@Override
	public boolean exists(String arg0) {
		return false;
	}

	@Override
	public String generateStrongPassword() {
		return null;
	}

	@Override
	public String generateStrongPassword(User arg0, String arg1) {
		return null;
	}

	@Override
	public User getCurrentUser() {
        User user = UserManager.getLoggedInUserObject(ESAPI.currentRequest());
        if (user == null) {
            user = User.ANONYMOUS;
        }
        return user;
	}

	@Override
	public User getUser(long arg0) {
		User user = UserManager.getUserObjectfromID(Integer.parseInt(String.valueOf(arg0)));
        if (user == null) {
            user = User.ANONYMOUS;
        }
        return user;
	}

	@Override
	public User getUser(String arg0) {
		User user = UserManager.getUserObjectfromName(arg0);
        if (user == null) {
            user = User.ANONYMOUS;
        }
        return user;
	}

	@Override
	@SuppressWarnings("unchecked")
	public Set getUserNames() {
		return null;
	}

	@Override
	public String hashPassword(String arg0, String arg1) throws EncryptionException {
		return null;
	}

	@Override
	public User login() throws AuthenticationException {
		return null;
	}

	@Override
	public User login(HttpServletRequest arg0, HttpServletResponse arg1) throws AuthenticationException {
		return null;
	}

	@Override
	public void logout() {
		
	}

	@Override
	public void removeUser(String arg0) throws AuthenticationException {
		
	}

	@Override
	public void setCurrentUser(User arg0) {
		
	}

	@Override
	public void verifyAccountNameStrength(String arg0) throws AuthenticationException {
		
	}

	@Override
	public boolean verifyPassword(User arg0, String arg1) {
		return false;
	}

	@Override
	public void verifyPasswordStrength(String arg0, String arg1) throws AuthenticationException {
		
	}

}
