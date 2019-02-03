package org.owasp.appsensor.demoapp;

import java.io.Serializable;

import org.owasp.appsensor.APPSENSOR;
import org.owasp.appsensor.ASUser;

/**
 * Just a test showing an adapter for the demo
 * @author jtmelton
 */
public class ASDemoASUserAdapter implements ASUser, Serializable {

	/**
	 * Serial version UID for serialization
	 */
	private static final long serialVersionUID = 5833018498426057264L;

	/**
	 * {@inheritDoc}
	 */
	public long getAccountId() {
		org.owasp.appsensor.demoapp.AppSensorUser u = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(APPSENSOR.asUtilities().getCurrentRequest());
		if (u == null) {
			return -1;
		} else {
			long acctId = u.getAccountId();
			return acctId;
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String getAccountName() {
		org.owasp.appsensor.demoapp.AppSensorUser u = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(APPSENSOR.asUtilities().getCurrentRequest());
		String accountName;
		if (u == null) {
			accountName = "ANONYMOUS-USER";
		} else {
			accountName = u.getAccountName();
		}
		return accountName;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isAnonymous() {
		org.owasp.appsensor.demoapp.AppSensorUser u = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(APPSENSOR.asUtilities().getCurrentRequest());
		if (u == null) {
			return true;
		} else {
			boolean isAnonymous = u.isAnonymous();
			return isAnonymous;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void disable() {
		org.owasp.appsensor.demoapp.AppSensorUser u = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(APPSENSOR.asUtilities().getCurrentRequest());
		u.disable();
	}

	/**
	 * {@inheritDoc}
	 */
	public void logout() {
		org.owasp.appsensor.demoapp.AppSensorUser u = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(APPSENSOR.asUtilities().getCurrentRequest());
		u.logout();
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isEnabled() {
		org.owasp.appsensor.demoapp.AppSensorUser u = org.owasp.appsensor.demoapp.UserManager.getLoggedInUserObject(APPSENSOR.asUtilities().getCurrentRequest());
		boolean isEnabled = u.isEnabled();
		return isEnabled;
	}

}
