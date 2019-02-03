package org.owasp.appsensor.demoapp.trend;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.owasp.appsensor.demoapp.trend.InMemoryTrendMonitor;

public class InMemoryTrendMonitoringContextListener implements ServletContextListener {

	@Override
	public void contextDestroyed(ServletContextEvent arg0) {
		// don't do anything
	}

	@Override
	public void contextInitialized(ServletContextEvent arg0) {
		new TrendMonitoringThread().start();	//will get launched once
	}

	class TrendMonitoringThread extends Thread {
		public void run() {
			while (true) {
				InMemoryTrendMonitor.checkUT1();
				InMemoryTrendMonitor.checkUT2();
				InMemoryTrendMonitor.checkUT3();
				InMemoryTrendMonitor.checkUT4();
				InMemoryTrendMonitor.checkSTE1();
				InMemoryTrendMonitor.checkSTE2();
				InMemoryTrendMonitor.checkSTE3();

				try {
					Thread.sleep(1000 * 60 * 5); // run checks every 5 minutes
				} catch (InterruptedException e) {
					// ignore
				}
			}
		}
	}

}
