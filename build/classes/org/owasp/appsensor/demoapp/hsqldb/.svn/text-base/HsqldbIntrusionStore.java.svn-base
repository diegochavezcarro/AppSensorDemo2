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
 * @author John Melton <a href="http://www.jtmelton.com/">jtmelton</a>
 * @created 2010
 */
package org.owasp.appsensor.demoapp.hsqldb;

import java.io.Serializable;
import java.util.List;

import org.owasp.appsensor.APPSENSOR;
import org.owasp.appsensor.ASUser;
import org.owasp.appsensor.AppSensorIntrusion;
import org.owasp.appsensor.AppSensorSystemUser;
import org.owasp.appsensor.errors.AppSensorSystemException;
import org.owasp.appsensor.intrusiondetection.IntrusionRecord;
import org.owasp.appsensor.intrusiondetection.IntrusionStore;


/**
 * This is a database driven implementation of the Intrusion Storage 
 * mechanism.  It uses a simple hsqldb database.  The idea
 * is to give database driven implementations a starting point to 
 * work from.  This will include a basic schema and some sample 
 * code to get started. 
 * <p>
 * The intrusion store stores IntrusionRecord's on a per-user 
 * basis.  Each user has an IntrusionRecord, and if one does not
 * yet exist, it will be automatically created when an exception 
 * is added for this user.  The unique identifier used to determine
 * the user is the account id. 
 * Note: This implementation does include a default system account
 * that is used when exceptions are added that are not user-specific, 
 * ie. the exception is of type AppSensorSystemException.  A similar
 * mechanism is recommended for alternative implementations.
 * <p>
 * This example is NOT optimized.  There is no caching and optimal 
 * performance was not a key design issue.  The goal was simply to 
 * provide a working example of a DB driven implementation.
 *
 * @author John Melton (jtmelton .at. gmail.com)
 *         <a href="http://www.jtmelton.com/">jtmelton</a>
 * @since September 16, 2010
 * @see org.owasp.appsensor.intrusiondetection.IntrusionStore
 */
public class HsqldbIntrusionStore implements IntrusionStore, Serializable  {
	
	/**
	 * Serial Version ID for serialization
	 */
	private static final long serialVersionUID = -5161832855380258234L;
	
	private static volatile IntrusionStore singletonInstance;

    public static IntrusionStore getInstance()
    {
        if ( singletonInstance == null ) {
            synchronized ( HsqldbIntrusionStore.class ) {
                if ( singletonInstance == null ) {
                    singletonInstance = new HsqldbIntrusionStore();
                }
            }
        }
        return singletonInstance;
    }
	
	/** The hashmap for storing intrusions */
	//private static HashMap<String, IntrusionRecord> intrusionStore = new HashMap<String, IntrusionRecord>();
	
	/**
	 * {@inheritDoc}
	 */
	public AppSensorIntrusion addExceptionToIntrusionStore(Exception e) {		
		//check the exception when adding it to the intrusion store.
		//if it is a system exception (AppSensorSystemException), use the
		//system user id to store it, otherwise use the current user
		
		IntrusionRecord intrusionRecord;
		if (e instanceof AppSensorSystemException) {
			//get intrusion record for system user
			intrusionRecord = getIntrusionRecordForSystemUser();
		} else {
			//get intrusion record for current user 
			intrusionRecord = getIntrusionRecordForCurrentUser();
		}
		
		//create AppSensorIntrusion container that will initialize all necessary fields
		AppSensorIntrusion asi = new AppSensorIntrusion(e);
		
		// add intrusion to air record 
		intrusionRecord.addIntrusionToRecord(asi);
		return asi;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public IntrusionRecord getIntrusionRecordForCurrentUser() {
		//get current user
		ASUser user = APPSENSOR.asUtilities().getCurrentUser();
		return getIntrusionRecordForUser(user);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public IntrusionRecord getIntrusionRecordForSystemUser() {
		ASUser user = new AppSensorSystemUser();
		return getIntrusionRecordForUser(user);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public IntrusionRecord getIntrusionRecordForUser(ASUser user) {
		//TODO: ----NOW---- select record for given user - if not exists - create new and store it in DB
		String userId = String.valueOf(user.getAccountId());
		HsqldbManager manager = new HsqldbManager();
		IntrusionRecord intrusionRecord = manager.getIntrusionRecordForUser(userId);
		return intrusionRecord;
	}

	/**
	 * {@inheritDoc}
	 */
	public List<IntrusionRecord> getAllIntrusionRecords() {
		HsqldbManager manager = new HsqldbManager();
		List<IntrusionRecord> allRecords = manager.getAllIntrusionRecords();
		return allRecords;
	}

}
