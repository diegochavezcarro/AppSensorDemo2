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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.owasp.appsensor.ASUser;
import org.owasp.appsensor.AppSensorIntrusion;
import org.owasp.appsensor.intrusiondetection.IntrusionRecord;

/**
 * This is a simple database manager for use by the DB driven  
 * intrusion store.  It uses a simple hsqldb database.  The idea
 * is to give database driven implementations a starting point to 
 * work from.  This will include a basic schema and some sample 
 * code to get started. 
 * <p>
 * This example is NOT optimized.  There is no caching and optimal 
 * performance was not a key design issue.  The goal was simply to 
 * provide a working example of a DB driven implementation. 
 *
 * @author John Melton (jtmelton .at. gmail.com)
 *         <a href="http://www.jtmelton.com/">jtmelton</a>
 * @since September 16, 2010
 */
public class HsqldbManager {

	/*
	 * go to directory where your hsqldb data resides
	 * java -cp hsqldb.jar org.hsqldb.server.Server --database.0 file:appsensordbfiles --dbname.0 appsensordb
	 *
	 */
	// path for standalone mode
	private static final String dbPathStandAlone = "jdbc:hsqldb:file:";
	// path for server mode
	private static final String dbPathWithServer = "jdbc:hsqldb:hsql://";
	
	private static final String DEFAULT_DB_NAME = "appsensordb";
	private static final String DEFAULT_DB_HOST = "localhost";

	
	// the unique Connection object used and shared by all tables
	private static Connection con = null;


	//default constructor - assumes basic config
	HsqldbManager() {
		//bdName load HSQLdb driver
		loadDriver();
		// try to connect to the server
		try {
			if (con == null) {
				con = DriverManager.getConnection(dbPathWithServer + DEFAULT_DB_HOST + "/" + DEFAULT_DB_NAME, "sa", "");
				createSchemaAndLoadData();
				System.out.println("Correctly connected in to the server.");
			}
		}
		catch (SQLException e) {
			int code = e.getErrorCode();
			System.out.println("getConnection failed: " + code + " " + e);
			throw new IllegalStateException("Cannot connect to DB server.");
		}
	}
	
	// In process mode receives the name of the DB filename
	HsqldbManager(String dbName) {
		// load HSQLdb driver
		loadDriver();
		// try to connect in standalone mode
		try {
			if (con == null) {
				con = DriverManager.getConnection(dbPathStandAlone + dbName, "sa", "");
				createSchemaAndLoadData();
				System.out.println("Correctly connected in StandAlone mode.");
			}
		}
		catch (SQLException e) {
			int code = e.getErrorCode();
			System.out.println("getConnection failed: " + code + " " + e);
			throw new IllegalStateException("Cannot connect to DB in StandAlone mode.");
		}
	}

	// Server mode receives pseudo name of the bd offerered by the server and server IP address
	HsqldbManager(String dbName, String host) {
		//bdName load HSQLdb driver
		loadDriver();
		// try to connect to the server
		try {
			if (con == null) {
				con = DriverManager.getConnection(dbPathWithServer + host + "/" + dbName, "sa", "");
				createSchemaAndLoadData();
				System.out.println("Correctly connected in to the server.");
			}
		}
		catch (SQLException e) {
			int code = e.getErrorCode();
			System.out.println("getConnection failed: " + code + " " + e);
			throw new IllegalStateException("Cannot connect to DB server.");
		}
	}

	public Collection<AppSensorIntrusion> getAllIntrusionsForUser(String userId) {
		Collection<AppSensorIntrusion> intrusionsCommitted = new ArrayList<AppSensorIntrusion>();
		try {
			PreparedStatement ps = con.prepareStatement(
				"SELECT AI.SECURITY_EXCEPTION OBJECT,AI.EVENT_CODE,AI.USER_OBJ,AI.TIME_COMMITTED,AI.LOCATION" +
				" FROM APPSENSOR_INTRUSIONS AI" +
				" INNER JOIN APPSENSOR_INTRUSION_RECORD_INSTRUSIONS AIRI ON AI.ID = AIRI.INT_ID" +
				" INNER JOIN APPSENSOR_INTRUSION_RECORDS AIR ON AIRI.INT_REC_ID = AIR.ID" +
				" WHERE AIR.USER_ID = ?");
			ps.setString(1, userId);
			ResultSet rs = ps.executeQuery();
			
			while (rs.next()) {
				Exception securityException = (Exception)rs.getObject("SECURITY_EXCEPTION");
				String eventCode = rs.getString("EVENT_CODE");
				ASUser user = (ASUser)rs.getObject("USER_OBJ");
				long timeStamp = rs.getTimestamp("TIME_COMMITTED").getTime();
				String location = rs.getString("LOCATION");
				
				AppSensorIntrusion asi = AppSensorIntrusion.reconstruct(securityException, eventCode, user, timeStamp, location);
				intrusionsCommitted.add(asi);
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		return intrusionsCommitted;
	}
	
	public Collection<AppSensorIntrusion> getIntrusionsForUserByEventCode(String userId, String searchEventCode) {
		Collection<AppSensorIntrusion> intrusionsCommitted = new ArrayList<AppSensorIntrusion>();
		try {
			PreparedStatement ps = con.prepareStatement(
				"SELECT AI.SECURITY_EXCEPTION OBJECT,AI.EVENT_CODE,AI.USER_OBJ,AI.TIME_COMMITTED,AI.LOCATION" +
				" FROM APPSENSOR_INTRUSIONS AI" +
				" INNER JOIN APPSENSOR_INTRUSION_RECORD_INSTRUSIONS AIRI ON AI.ID = AIRI.INT_ID" +
				" INNER JOIN APPSENSOR_INTRUSION_RECORDS AIR ON AIRI.INT_REC_ID = AIR.ID" +
				" WHERE AIR.USER_ID = ?" +
				" AND AI.EVENT_CODE = ?");
			ps.setString(1, userId);
			ps.setString(2, searchEventCode);
			ResultSet rs = ps.executeQuery();
			
			while (rs.next()) {
				Exception securityException = (Exception)rs.getObject("SECURITY_EXCEPTION");
				String eventCode = rs.getString("EVENT_CODE");
				ASUser user = (ASUser)rs.getObject("USER_OBJ");
				long timeStamp = rs.getTimestamp("TIME_COMMITTED").getTime();
				String location = rs.getString("LOCATION");
				
				AppSensorIntrusion asi = AppSensorIntrusion.reconstruct(securityException, eventCode, user, timeStamp, location);
				intrusionsCommitted.add(asi);
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		return intrusionsCommitted;
	}
	
	public void addIntrusionForUser(String userId, AppSensorIntrusion aie) {
		//get intrusion record id
		int intrusionRecordId = getIntrusionRecordIdForUser(userId);
		
		//insert intrusion and get id of inserted intrusion
		int intrusionId = addIntrusionToUserRecord(intrusionRecordId, aie);
		
		//add irid/intrid pair to join table
		linkIntrusionRecordToIntrusion(intrusionRecordId, intrusionId);
	}
	
	public int getIntrusionRecordIdForUser(String userId) {
		int irId = -1;
		try {
			PreparedStatement ps = con.prepareStatement(
					"SELECT ID FROM APPSENSOR_INTRUSION_RECORDS WHERE USER_ID = ?");
			ps.setString(1, userId);
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				irId = rs.getInt("ID");
			} else {
				//doesn't exist yet - create it, then recursively call self to get the new ID
				createIntrusionRecordForUser(userId);
				return getIntrusionRecordIdForUser(userId);
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		return irId;
	}
	
	public void createIntrusionRecordForUser(String userId) {
		try {
			PreparedStatement ps = con.prepareStatement("INSERT INTO APPSENSOR_INTRUSION_RECORDS" +
					" (USER_ID,LAST_VIOLATION,LAST_RESPONSE_ACTION_MAP)" +
					" VALUES (?,?,?)");  
			ps.setString(1, userId);
			ps.setString(2, null);
			ps.setObject(3, null);
			ps.executeUpdate();
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}
	
	public int addIntrusionToUserRecord(int intrusionRecord, AppSensorIntrusion aie) {
		try {
			PreparedStatement ps = con.prepareStatement("INSERT INTO APPSENSOR_INTRUSIONS" +
					" (SECURITY_EXCEPTION,EVENT_CODE,USER_OBJ,TIME_COMMITTED,LOCATION)" +
					" VALUES (?,?,?,?,?)");  
			ps.setObject(1, aie.getSecurityException());
			ps.setString(2, aie.getEventCode());
			ps.setObject(3, aie.getUser());
			ps.setTimestamp(4, new Timestamp(aie.getTimeStamp()));
			ps.setString(5, aie.getLocation());
			ps.executeUpdate();
			
			ps = con.prepareStatement("CALL IDENTITY();");
			ResultSet rs = ps.executeQuery();
			rs.next();
			int generatedId = rs.getInt(1); 
			return generatedId;
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}
	
	public void linkIntrusionRecordToIntrusion(int intrusionRecordId, int intrusionId) {
		try {
			PreparedStatement ps = con.prepareStatement("INSERT INTO APPSENSOR_INTRUSION_RECORD_INSTRUSIONS" +
					" (INT_REC_ID,INT_ID)" +
					" VALUES (?,?)");  
			ps.setInt(1, intrusionRecordId);
			ps.setInt(2, intrusionId);
			ps.executeUpdate();
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}
	
	public void insertLastViolation(String userId, String violation) {
		try {
			PreparedStatement ps = con.prepareStatement("UPDATE APPSENSOR_INTRUSION_RECORDS" +
					" SET LAST_VIOLATION = ?" +
					" WHERE USER_ID = ?");  
			ps.setString(1, violation);
			ps.setString(2, userId);
			ps.executeUpdate();
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}
	
	public String retrieveLastViolation(String userId) {
		String lastViolation = "NONE";
		try {
			PreparedStatement ps = con.prepareStatement(
					"SELECT LAST_VIOLATION FROM APPSENSOR_INTRUSION_RECORDS WHERE USER_ID = ?");
			ps.setString(1, userId);
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				lastViolation = rs.getString("LAST_VIOLATION");
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		return lastViolation;
	}
	
	@SuppressWarnings("unchecked")
	public Map<String, LinkedList<String>> retrieveLastResponseActionMapForUser(String userId) {
		Map<String, LinkedList<String>> lastResponseActionMap = new HashMap<String, LinkedList<String>>();
		try {
			PreparedStatement ps = con.prepareStatement(
					"SELECT LAST_RESPONSE_ACTION_MAP FROM APPSENSOR_INTRUSION_RECORDS WHERE USER_ID = ?");
			ps.setString(1, userId);
			ResultSet rs = ps.executeQuery();
			if (rs.next()) {
				Map<String, LinkedList<String>> temp = (Map<String, LinkedList<String>>)rs.getObject("LAST_RESPONSE_ACTION_MAP");
				if (temp != null) {
					//only set value if it exists
					lastResponseActionMap = temp;
				}
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		return lastResponseActionMap;
	}
	
	public void insertLastResponseActionMap(String userId, Map<String, LinkedList<String>> lastResponseActionMap) {
		try {
			PreparedStatement ps = con.prepareStatement("UPDATE APPSENSOR_INTRUSION_RECORDS" +
					" SET LAST_RESPONSE_ACTION_MAP = ?" +
					" WHERE USER_ID = ?");  
			ps.setObject(1, lastResponseActionMap);
			ps.setString(2, userId);
			ps.executeUpdate();
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
	}
	
	public IntrusionRecord getIntrusionRecordForUser(String userId) {
		//all the methods in the HsqldbIntrusionRecord class actually do DB interaction
		//so no data has to be preloaded
		IntrusionRecord intrusionRecord = new HsqldbIntrusionRecord(userId);
		return intrusionRecord;
	}
	
	public List<IntrusionRecord> getAllIntrusionRecords() {
		List<IntrusionRecord> allRecords = new ArrayList<IntrusionRecord>();
		try {
			PreparedStatement ps = con.prepareStatement(
					"SELECT USER_ID FROM APPSENSOR_INTRUSION_RECORDS");
			ResultSet rs = ps.executeQuery();
			while (rs.next()) {
				IntrusionRecord intrusionRecord = new HsqldbIntrusionRecord(rs.getString("USER_ID"));
				allRecords.add(intrusionRecord);
			}
		} catch (SQLException e) {
			throw new RuntimeException(e);
		}
		return allRecords;
	}
	
	////////////////////////////////////////////////////////////////////////
	
	// use to load the HSQLdb driver use by both connection type
	private void loadDriver() {
		try {
			Class.forName("org.hsqldb.jdbcDriver"); //.newInstance();
			System.out.println("HSQLdb driver correctly loaded.");
		}
		catch (Exception e) {
			System.out.println("Problem loading JDBC driver: " + e);
			throw new IllegalStateException("HSQLDB driver couldn't be loadded.");
		}
	}

	private synchronized static void shutdown() {
        Statement st;
        try {
            st = con.createStatement();
            // db writes out to files and performs clean shuts down
            // otherwise there will be an unclean shutdown when program ends
            st.execute("SHUTDOWN");
            con.close(); // if there are no other open connection
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        System.out.println("Shutdown successful.");
    }
	
	private static void createSchemaAndLoadData() {
	    PreparedStatement ps;
	    try {
	    	//DROP TABLES IF THEY EXIST
	    	ps = con.prepareStatement("DROP TABLE SAMPLE_TABLE IF EXISTS");  ps.executeUpdate();
	    	ps = con.prepareStatement("DROP TABLE APPSENSOR_INTRUSION_RECORD_INSTRUSIONS IF EXISTS");  ps.executeUpdate();
	    	ps = con.prepareStatement("DROP TABLE APPSENSOR_INTRUSION_RECORDS IF EXISTS");  ps.executeUpdate();
	    	ps = con.prepareStatement("DROP TABLE APPSENSOR_INTRUSIONS IF EXISTS");  ps.executeUpdate();
	    	
	    	ps.executeUpdate();
	    	ps = con.prepareStatement("CREATE TABLE APPSENSOR_INTRUSION_RECORDS (" +
	    			"ID identity PRIMARY KEY, " +
	    			"USER_ID VARCHAR(50), " +
	    			"LAST_VIOLATION VARCHAR(200), " +
	    			"LAST_RESPONSE_ACTION_MAP OBJECT" +
	    			")");  
	    	ps.executeUpdate();
	    	ps = con.prepareStatement("CREATE TABLE APPSENSOR_INTRUSIONS (" +
	    			"ID identity PRIMARY KEY, " +
	    			"SECURITY_EXCEPTION OBJECT, " +
	    			"EVENT_CODE VARCHAR(100)," +
	    			"USER_OBJ OBJECT, " +
	    			"TIME_COMMITTED TIMESTAMP, " +
	    			"LOCATION VARCHAR(200)" +
	    			")");  
	    	ps.executeUpdate();
	    	ps = con.prepareStatement("CREATE TABLE APPSENSOR_INTRUSION_RECORD_INSTRUSIONS (" +
	    			"INT_REC_ID INTEGER, " +
	    			"INT_ID INTEGER, " +
	    			"FOREIGN KEY (INT_REC_ID) REFERENCES APPSENSOR_INTRUSION_RECORDS(ID), " +
	    			"FOREIGN KEY (INT_ID) REFERENCES APPSENSOR_INTRUSIONS(ID)" +
	    			")");  
	    	ps.executeUpdate();
	    } catch (SQLException e) {
	        e.printStackTrace();
	    }
	}
	
	private static void runAndPrintBasicQuery() {
	    PreparedStatement ps;
	    try {
	    	//SAMPLE_TABLE
	    	System.out.println("-------------------------");
	    	System.out.println("SAMPLE_TABLE");
	        ps = con.prepareStatement("SELECT * FROM SAMPLE_TABLE");
	        ResultSet resultset = ps.executeQuery();
	        
	        int count = 0;
			while (resultset.next()) {
				System.out.println(resultset.getInt(1) + " : " + resultset.getString(2));
				count++;
			}
			System.out.println("total rows returned: " + count);
			
			//APPSENSOR_INTRUSION_RECORDS
			System.out.println("-------------------------");
			System.out.println("APPSENSOR_INTRUSION_RECORDS");
			ps = con.prepareStatement("SELECT * FROM APPSENSOR_INTRUSION_RECORDS");
	        resultset = ps.executeQuery();
	        
	        count = 0;
			while (resultset.next()) {
				System.out.println(resultset.getInt(1) + " : " + resultset.getString(2) + " : " + resultset.getString(3));
				count++;
			}
			System.out.println("total rows returned: " + count);
			
			//APPSENSOR_INTRUSIONS
			System.out.println("-------------------------");
			System.out.println("APPSENSOR_INTRUSIONS");
			ps = con.prepareStatement("SELECT * FROM APPSENSOR_INTRUSIONS");
	        resultset = ps.executeQuery();
	        
	        count = 0;
			while (resultset.next()) {
				System.out.println(resultset.getInt(1) + " : " + resultset.getObject(2) + " : " + resultset.getString(3) + " : " + resultset.getObject(4) + " : " + resultset.getTimestamp(5) + " : " + resultset.getString(6));
				count++;
			}
			System.out.println("total rows returned: " + count);
			
			//APPSENSOR_INTRUSION_RECORD_INSTRUSIONS
			System.out.println("-------------------------");
			System.out.println("APPSENSOR_INTRUSION_RECORD_INSTRUSIONS");
			ps = con.prepareStatement("SELECT * FROM APPSENSOR_INTRUSION_RECORD_INSTRUSIONS");
	        resultset = ps.executeQuery();
	        
	        count = 0;
			while (resultset.next()) {
				System.out.println(resultset.getInt(1) + " : " + resultset.getInt(2));
				count++;
			}
			System.out.println("total rows returned: " + count);
			System.out.println("-------------------------");
	    } catch (SQLException e) {
	        e.printStackTrace();
	    }
	}
	
	private static void closeConnection() {
		try {
			if (con != null) {
				con.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			con = null;
		}
	}


	//just for testing
	public static void main(String[] args) {
		@SuppressWarnings("unused")
		HsqldbManager hm = new HsqldbManager("appsensordb", "localhost");
		
		runAndPrintBasicQuery();
		shutdown();
		closeConnection();
	}
}
