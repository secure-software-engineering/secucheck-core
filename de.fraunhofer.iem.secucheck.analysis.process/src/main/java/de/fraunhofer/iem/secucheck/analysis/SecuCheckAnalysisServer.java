package de.fraunhofer.iem.secucheck.analysis;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.core.JsonProcessingException;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.ReportType;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessageSerializer;
import de.fraunhofer.iem.secucheck.analysis.serializable.query.CompleteQuery;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.CompleteResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.ListenerResult;

public class SecuCheckAnalysisServer {
	
	private final ByteArrayOutputStream baos = new ByteArrayOutputStream();
	private final PrintStream systemOut = System.out;
	private final Logger logger;
	
	public SecuCheckAnalysisServer() {
		System.setOut(new PrintStream(baos));
		logger = LogManager.getLogger();
		logger.debug("X");	
	}

	public static void main(String[] args) {
		try {
			new SecuCheckAnalysisServer().run();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void run() throws Exception {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		
		CompleteQuery queryDetails = 
				(CompleteQuery) ProcessMessageSerializer.deserializeFromJsonString(br.readLine());
		
		AnalysisResultListener resultListener = queryDetails.hasResultListener() ? 
				new SimpleResultListener() : null;
				
		SecucheckAnalysis analysis = new SecucheckTaintAnalysis(
				queryDetails.getSootClassPath(), 
				queryDetails.getCanonicalClasses(), resultListener);	
		
		SecucheckTaintAnalysisResult result = analysis.run(queryDetails.getFlowQueries());
		CompleteResult completeResult = new CompleteResult(result);
		systemOut.println(ProcessMessageSerializer.serializeToJsonString(completeResult));
		System.err.print(baos.toString());
		
		if (logger.isInfoEnabled()) {
			logger.log(Level.INFO, "Successfully analyzed a query.");
		}
	}
	

	class SimpleResultListener implements AnalysisResultListener {
		
		public void reportFlowResult(AnalysisResult result) {
			sendResult(ReportType.SingleResult, result);
		}
		
		public void reportCompositeFlowResult(AnalysisResult result) {
			sendResult(ReportType.CompositeResult, result);
		}
		
		public void reportCompleteResult(AnalysisResult result) {
			sendResult(ReportType.CompleteResult, result);
		}
		
		public boolean isCancelled() {
			return false;
		}
		
		private void sendResult(ReportType reportType, AnalysisResult result) {
			ListenerResult listenResult = new ListenerResult();
			listenResult.setReportType(reportType);
			listenResult.setResult(result);
			
			try {
				SecuCheckAnalysisServer.this.systemOut.println(ProcessMessageSerializer.serializeToJsonString(listenResult));
			} catch (Exception e) { e.printStackTrace();}
			
			// TEMP CHANGE
			
			System.err.print(SecuCheckAnalysisServer.this.baos.toString());
			
			if (logger.isInfoEnabled()) {
				logger.log(Level.INFO, "Successfully sent a result report.");
			}
		}
	};
	
}
