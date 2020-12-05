package de.fraunhofer.iem.secucheck.analysis;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.ReportType;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessageSerializer;
import de.fraunhofer.iem.secucheck.analysis.serializable.query.CompleteQuery;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.CompleteResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.ListenerResult;

public class SecuCheckAnalysisServer {
	
	private final ByteArrayOutputStream baos = new ByteArrayOutputStream();
	private final PrintStream systemOut = System.out;
	private final Logger logger;
	
	private SimpleResultListener resultListener;
	
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
		//while(true) {	
			ProcessMessage message = ProcessMessageSerializer.deserializeFromJsonString(br.readLine());
			switch (message.getMessageType()) {
				case CompleteQuery:
					CompleteQuery queryDetails = (CompleteQuery)message;
					this.resultListener = queryDetails.hasResultListener() ? 
							new SimpleResultListener() : null;
					
					SecucheckAnalysis analysis = new SecucheckTaintAnalysis(
							queryDetails.getOs(),
							queryDetails.getSolver(),
							queryDetails.getAppClassPath(),
							queryDetails.getSootClassPath(), 
							queryDetails.getAnalysisEntryPoints(), resultListener);	
					
					SecucheckTaintAnalysisResult result = analysis.run(queryDetails.getFlowQueries());
					CompleteResult completeResult = new CompleteResult(result);
					systemOut.println(ProcessMessageSerializer.serializeToJsonString(completeResult));
					System.err.print(baos.toString());
					if (logger.isInfoEnabled()) {
						logger.log(Level.INFO, "Successfully analyzed a query.");
					}
					break;			
				case Cancellation:
					resultListener.setCancelled();
					break;
				default: break;
			}
		//}
	}

	class SimpleResultListener implements AnalysisResultListener {
		
		private boolean isCancelled = false;
		
		public void reportFlowResult(TaintFlowQueryResult result) {
			ListenerResult listenerResult = new ListenerResult();
			listenerResult.setSingleResult(result);
			listenerResult.setReportType(ReportType.SingleResult);
			sendResult(listenerResult);
		}
		
		public void reportCompositeFlowResult(CompositeTaintFlowQueryResult result) {
			ListenerResult listenerResult = new ListenerResult();
			listenerResult.setCompositeResult(result);
			listenerResult.setReportType(ReportType.CompositeResult);
			sendResult(listenerResult);
		}
		
		public void reportCompleteResult(SecucheckTaintAnalysisResult result) {
			ListenerResult listenerResult = new ListenerResult();
			listenerResult.setCompleteResult(result);
			listenerResult.setReportType(ReportType.CompleteResult);
			sendResult(listenerResult);
		}
		
		public boolean isCancelled() {
			return isCancelled;
		}
		
		public boolean setCancelled() {
			return isCancelled = true;
		}
		
		private void sendResult(ListenerResult listenerResult) {
			try {
				SecuCheckAnalysisServer.this.systemOut.println(
						ProcessMessageSerializer.serializeToJsonString(listenerResult));
			} catch (Exception e) { e.printStackTrace();}
			System.err.print(SecuCheckAnalysisServer.this.baos.toString());
			if (logger.isInfoEnabled()) {
				logger.log(Level.INFO, "Successfully sent a result report.");
			}
		}
	};
}
