package de.fraunhofer.iem.secucheck.analysis;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.ProcessBuilder.Redirect;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.io.FileUtils;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessageSerializer;
import de.fraunhofer.iem.secucheck.analysis.serializable.query.CompleteQuery;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.CompleteResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.ListenerResult;

public final class SecuCheckTaintAnalysisInProcess implements SecucheckAnalysis {
	
	private final ReentrantLock lock;
	
	private String sootClassPath;
	private List<String> canonicalClasses;
	private AnalysisResultListener resultListener;
	private SecucheckTaintAnalysisResult result;
	
	private static File analysisJarFile;

	public SecuCheckTaintAnalysisInProcess(String sootClassPath, List<String> canonicalClassNames,
				AnalysisResultListener resultListener) {
		this.sootClassPath = sootClassPath;
		this.canonicalClasses = canonicalClassNames;
		this.resultListener = resultListener;
		this.lock = new ReentrantLock();
	}
	
	public void setSootClassPath(String sootClassPath) {
		this.sootClassPath = sootClassPath;
	}
	
	public void setAnalysisClasses(List<String> canonicalClassNames) {
		this.canonicalClasses = canonicalClassNames;
	}
	
	public void setListener(AnalysisResultListener resultListener) {
		this.resultListener = resultListener;
	}
	
	public SecucheckTaintAnalysisResult run(List<? super CompositeTaintFlowQueryImpl> flowQueries) {
		lock.lock();
		try {
					
			File javaFile = getJavaBinaryFile();
			File analysisJarFile = getAnalysisJarFile();
	
			if (javaFile == null || analysisJarFile == null) {
				return result;
			}
			
			ProcessBuilder builder = new ProcessBuilder().command(//
							javaFile.toString(), // "-Xdebug",
							//"-Xrunjdwp:transport=dt_socket,address=127.0.0.1:9000,suspend=y",
							"-jar", analysisJarFile.toString()).redirectError(Redirect.INHERIT);
			
			Process process = builder.start();
			// PrintStream pw = System.out;
			PrintWriter pw = new PrintWriter(process.getOutputStream());
			
			List<CompositeTaintFlowQuery> flowsClone = cloneList(flowQueries);
			CompleteQuery analysisQuery = new CompleteQuery(sootClassPath, canonicalClasses,
					flowsClone, resultListener == null);

			pw.println(ProcessMessageSerializer.serializeToJsonString(analysisQuery));
			pw.flush();

			BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));

			while (!process.waitFor(50, TimeUnit.MILLISECONDS)) {
				if (resultListener.isCancelled())
					process.destroyForcibly();
				readInput(br);
			}
			
			readInput(br);
			return this.result;
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			lock.unlock();
		}
		return result;
	}
	
	private void readInput(BufferedReader br) throws IOException {
		while (br.ready()) {
			String line = null;
			try {
				line = br.readLine();
				if (line == null) break;
			} catch (IOException e) {
				e.printStackTrace();
				break;
			}
			handleProccessMessage(ProcessMessageSerializer.deserializeFromJsonString(line));
		}
	}

	private void handleProccessMessage(ProcessMessage message) {
		switch(message.getMessageType()) {
			case ListenerResult:
				ListenerResult interResult = (ListenerResult) message;
				switch(interResult.getReportType()) {
					case SingleResult:
						this.resultListener.reportFlowResult(interResult.getResult());
						break;
					case CompositeResult:
						this.resultListener.reportCompositeFlowResult(interResult.getResult());
						break;
				case CompleteResult:
					this.resultListener.reportCompleteResult(interResult.getResult());
					break;
				}
				break;
			case AnalysisResult:
				CompleteResult completeResult = (CompleteResult) message;
				this.result = completeResult.getResult();
				break;
			default: break;
		}
	}

	private static File getAnalysisJarFile() throws IOException {
		if (SecuCheckTaintAnalysisInProcess.analysisJarFile == null 
				|| !SecuCheckTaintAnalysisInProcess.analysisJarFile.exists()) {
			SecuCheckTaintAnalysisInProcess.analysisJarFile = provideResource("/analysis.jar");
		}
		return SecuCheckTaintAnalysisInProcess.analysisJarFile;
	}

	private static File provideResource(String resourcePath) throws IOException {
		InputStream is = SecuCheckTaintAnalysisInProcess.class.getResourceAsStream(resourcePath);
		File file = File.createTempFile("SecuCheck", resourcePath.replace('/', '-'));
		FileUtils.copyInputStreamToFile(is, file);
		file.deleteOnExit();
		return file;
	}

	private static File getJavaBinaryFile() {
		File javaHome = new File(System.getProperty("java.home"));
		File javaFiles[] = new File[] { 
				new File(javaHome, "/bin/java.exe"), new File(javaHome, "/bin/java") };
		for (File javaFile : javaFiles) {
			if (javaFile.exists()) {
				return javaFile;
			}
		}
		return null;
	}
	
	private static List<CompositeTaintFlowQuery> cloneList(List<? super CompositeTaintFlowQueryImpl> list){
		final List<CompositeTaintFlowQuery> flowsClone = 
				new ArrayList<CompositeTaintFlowQuery>();
		CompositeTaintFlowQueryImpl copyQuery;
		for (Object query : list) {			
			copyQuery = new CompositeTaintFlowQueryImpl();
			((CompositeTaintFlowQuery)query).copyTo(copyQuery);			
			flowsClone.add(copyQuery);
		}
		return flowsClone;
	}
}
