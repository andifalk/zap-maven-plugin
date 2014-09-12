package org.zaproxy.maven.plugin;

/*
 * Copyright 2014 Andreas Falk.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.jdom.JDOMException;
import org.zaproxy.clientapi.core.Alert;
import org.zaproxy.clientapi.core.AlertsFile;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

/**
 * Goal to actually execute the security tests.
 * <p>
 * Dependent on the configuration it is possible to execute
 * <ul>
 * 	<li>Spidering of given url</li>
 * 	<li>Active Scan</li>
 * 	<li>Report Alerts</li>
 * </ul>
 * </p>
 */
@Mojo( name = "scan",
       defaultPhase = LifecyclePhase.POST_INTEGRATION_TEST, 
       threadSafe = true )
public class ExecuteScan extends AbstractMojo {

    private ClientApi clientApi;

    /**
     * The host of the ZAP proxy.
     */
    @Parameter( property = "zap.proxy.host", defaultValue = "localhost", 
    		    required = true)
    private String zapProxyHost;

    /**
     * The port of the ZAP proxy.
     */
    @Parameter( property = "zap.proxy.port", defaultValue = "8080", 
		        required = true)
    private int zapProxyPort;

    /**
     * The target URL.
     */
    @Parameter( property = "target.url", required=true )
    private String targetUrl;

    /**
     * Flag if spidering is active/not active.
     */
    @Parameter( property = "zap.spider.active", defaultValue="true" )
    private boolean spider;

    /**
     * Flag if scan is active/not active.
     */
    @Parameter( property = "zap.scan.active", defaultValue="true" )
    private boolean scan;

    /**
     * Save session of scan
     */
    @Parameter( property = "save.zap.session", defaultValue="true" )
    private boolean saveSession;

    /**
     * Switch to shutdown ZAP
     */
    @Parameter( property = "zap.shutdown", defaultValue="true" )
    private boolean shutdownZAP;

    /**
     * Location to store the ZAP reports
     */
    @Parameter( property = "report.directory", defaultValue="${project.build.directory}/zap-reports" )
    private String reportDirectory;
    
    /**
     * Unique key for Zap API.
     */
    @Parameter ( property = "zap.api.key", defaultValue="none", required=true )
    private String apiKey;

    /**
     * Save session of scan
     */
    @Parameter( property = "report.zap.alerts", defaultValue="true" )
    private boolean reportAlerts;

    /**
     * Fail build when alerts have occurred.
     */
    @Parameter( property = "fail.on.alerts", defaultValue="false" )
    private boolean failOnAlerts;

    /**
     * Alerts to ignore for check.
     */
    @Parameter
    private List<String> ignoredAlerts;

    /**
     * Create a timestamp for name of zap session file.
     * 
     * @return formatted date-time 
     */
    private String dateTimeString() {
        Calendar cal = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        return sdf.format(cal.getTime());
    }

    /**
     * Change the ZAP API status response to an integer
     *
     * @param response the ZAP APIresponse code
     * @return
     */
    private int statusToInt(ApiResponse response) {
        return Integer.parseInt(((ApiResponseElement)response).getValue());
    }

    /**
     * Search for all links and pages on the URL
     *
     * @param url the to investigate URL
     * @throws ClientApiException
     */
    private void spider(String url) throws ClientApiException {
        clientApi.spider.scan(apiKey, url);

        while ( statusToInt(clientApi.spider.status()) < 100) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                getLog().error(e.toString());
            }
        }
    }
    
    /**
     * Active scan of all pages found at given url.
     *
     * @param url the url for active scan
     * @throws ClientApiException
     */
    private void activeScan(String url) throws ClientApiException {
        clientApi.ascan.scan(apiKey, url, "true", "false");

        while ( statusToInt(clientApi.ascan.status()) < 100) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                getLog().error(e.toString());
            }
        }
    }
    
    public void checkAlerts(String url) throws ClientApiException, ZapAlertsReportedException {
    	// Retrieve all relevant alerts from API
    	List<Alert> reportedAlerts = clientApi.getAlerts(url, -1, -1);
    	List<Alert> ignoredAlerts = new ArrayList<Alert>();
    	List<Alert> requireAlerts = new ArrayList<Alert>();
    	
    	for (Alert alert : reportedAlerts) {
			if (alertIsIgnored(alert)) {
				ignoredAlerts.add(alert);
			} else {
				requireAlerts.add(alert);
			}
		}
    	
    	// Write alerts to output file
    	if (reportAlerts) {
    		File outputFile;
			try {
				outputFile = Files.createTempFile(Paths.get(reportDirectory), "ZAP", "xml").toFile();
	    		AlertsFile.saveAlertsToFile(requireAlerts, reportedAlerts, ignoredAlerts, outputFile);
			} catch (IOException | JDOMException e) {
				getLog().error("Error creating alerts report file", e);
			}
    	}
    	
    	// Fail build on required alerts if enabled
    	if (failOnAlerts && !requireAlerts.isEmpty()) {
    		throw new ZapAlertsReportedException("There are security alerts!");
    	}
    }

	private boolean alertIsIgnored(Alert alert) {
		for (String alertToIgnore : ignoredAlerts) {
			if (alert.getAlert().equalsIgnoreCase(alertToIgnore)) {
				return true;
			}
		}
		return false;
	}

    /**
     * Execute security testing.
     * <ol>
     * <li>Perform spidering of target url</li>
     * <li>Active scan of target url</li>
     * <li>Save zap session</li>
     * <li>Analyze and report security alerts found</li>
     * </ol>
     *
     * @throws MojoExecutionException if an unexpected error occurred in zap client api
     * @throws MojoFailureException if build should fail because of security alerts
     */
    public void execute() throws MojoExecutionException, MojoFailureException {

        try {

            clientApi = new ClientApi(zapProxyHost, zapProxyPort);

            if (spider) {
                getLog().info(String.format("Perform spidering of site '%s'", targetUrl));
                spider(targetUrl);
            } else {
                getLog().info("Skipping spidering");
            }

            if (scan) {
                getLog().info(String.format("Perform active scan of site '%s'", targetUrl));
                activeScan(targetUrl);
            } else {
                getLog().info("Skipping active scan");
            }

            // Store zap session, if enabled
            String fileName = "";
            if (saveSession) {
                fileName = "ZAP_" + dateTimeString();
                clientApi.core.saveSession(apiKey, fileName, "true");
                getLog().info(String.format("Saved session into '%s'", fileName));
            } else {
                getLog().info("Skipping session saving");
            }
            
            getLog().info("Analyzing reported alerts...");
            checkAlerts(targetUrl);

            getLog().info("Zap maven plugin finished");

        } catch (ClientApiException e) {
            getLog().error(e.toString());
            throw new MojoExecutionException("Processing with ZAP failed");
        } finally {
            if (shutdownZAP && (clientApi != null)) {
                try {
                    getLog().info("Shutting down zap proxy");
                    clientApi.core.shutdown(apiKey);
                } catch (Exception e) {
                    getLog().error(e.toString());
                    e.printStackTrace();
                }
            } else {
                getLog().info("Skipping shutdown of zap proxy");
            }
        }
    }

}
