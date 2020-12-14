package de.fraunhofer.iem.secucheck.analysis.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.ProcessBuilder.Redirect;
import java.net.URISyntaxException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.io.FileUtils;

import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.query.Solver;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysis;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.Utility;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessage;
import de.fraunhofer.iem.secucheck.analysis.serializable.ProcessMessageSerializer;
import de.fraunhofer.iem.secucheck.analysis.serializable.query.CompleteQuery;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.CompleteResult;
import de.fraunhofer.iem.secucheck.analysis.serializable.result.ListenerResult;

public final class SecuCheckTaintAnalysisOutOfProcess implements SecucheckAnalysis {
	
	private final ReentrantLock lock;
	
	private SecucheckAnalysisConfiguration config;
	private SecucheckTaintAnalysisResult result;
	
	private static File analysisJarFile;
	
	public SecuCheckTaintAnalysisOutOfProcess() {
		this.lock = new ReentrantLock();
	}
	
	public SecuCheckTaintAnalysisOutOfProcess(SecucheckAnalysisConfiguration config) {
		this();
	}
	
	public SecucheckTaintAnalysisResult run(List<CompositeTaintFlowQueryImpl> flowQueries)
			throws Exception {
		Utility.ValidateCompositeFlowQueries(flowQueries);
		lock.lock();
		try {
			
			File javaFile = getJavaBinaryFile();
			File analysisJarFile = getAnalysisJarFile();
	
			if (javaFile == null || analysisJarFile == null) {
				return result;
			}
			
			ProcessBuilder builder = new ProcessBuilder().command(//
							javaFile.toString(),  //"-Xdebug",
							//"-Xrunjdwp:transport=dt_socket,address=127.0.0.1:9000,suspend=y",
							"-jar", analysisJarFile.toString()).redirectError(Redirect.INHERIT);
			
			Process process = builder.start();
			// PrintStream pw = System.out;
			PrintWriter pw = new PrintWriter(process.getOutputStream());
			
			CompleteQuery analysisQuery = new CompleteQuery(config.getOs(), config.getSolver(), 
					config.getSootClassPathJars(), config.getApplicationClassPath(),
					config.getAnalysisEntryPoints(), flowQueries, config.getListener() != null);

			pw.println(ProcessMessageSerializer.serializeToJsonString(analysisQuery));
			pw.flush();

			BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));

			while (!process.waitFor(50, TimeUnit.MILLISECONDS)) {
				if (config.getListener() != null && config.getListener().isCancelled())
					process.destroyForcibly();
				readInput(br);
			}
			
			readInput(br);
			return this.result;
		} finally {
			lock.unlock();
		}
	}
	
	private void readInput(BufferedReader br) throws Exception {
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
						this.config.getListener().reportFlowResult(interResult.getSingleResult());
						break;
					case CompositeResult:
						this.config.getListener().reportCompositeFlowResult(interResult.getCompositeResult());
						break;
				case CompleteResult:
					this.config.getListener().reportCompleteResult(interResult.getCompleteResult());
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

	private static File getAnalysisJarFile() throws IOException, URISyntaxException {
		if (SecuCheckTaintAnalysisOutOfProcess.analysisJarFile == null 
				|| !SecuCheckTaintAnalysisOutOfProcess.analysisJarFile.exists()) {
			 SecuCheckTaintAnalysisOutOfProcess.analysisJarFile = provideResource("/analysis.jar");
		}
		return SecuCheckTaintAnalysisOutOfProcess.analysisJarFile;
	}

	private static File provideResource(String resourcePath) throws IOException {
		InputStream is = SecuCheckTaintAnalysisOutOfProcess.class.getResourceAsStream(resourcePath);
		if (is == null || is.available() == 0) {
			throw new IOException("Could not find the analysis process jar");
		}
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

	@Override
	public void setConfiguration(SecucheckAnalysisConfiguration configuration) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public SecucheckAnalysisConfiguration getConfiguration() {
		// TODO Auto-generated method stub
		return null;
	}
}