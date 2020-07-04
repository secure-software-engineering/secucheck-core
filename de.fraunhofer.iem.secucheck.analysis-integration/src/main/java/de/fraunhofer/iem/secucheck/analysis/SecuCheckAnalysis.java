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

import org.apache.commons.io.FileUtils;
import org.eclipse.emf.ecore.EObject;

import de.fraunhofer.iem.secucheck.custom.ProgressReporter;
import de.fraunhofer.iem.secucheck.custom.XMLHelper;
import de.fraunhofer.iem.secucheck.marker.AnalysisResult;
import de.fraunhofer.iem.secucheck.marker.ProgressReport;
import de.fraunhofer.iem.secucheck.query.Flow;
import de.fraunhofer.iem.secucheck.query.TaintFlow;

public class SecuCheckAnalysis {
	private ProgressReporter progressReporter;
	private AnalysisResult analysisResult;
	private static File analysisJarFile;

	public SecuCheckAnalysis(ProgressReporter progressReporter) {
		this.progressReporter = progressReporter;
	}

	public AnalysisResult runThrows(String sootClassPath, List<String> canonicalClassNames, List<TaintFlow> flowQueries, List<Flow> flows)
			throws InterruptedException, IOException {

		List<EObject> elements = new ArrayList<EObject>();
		elements.addAll(flowQueries);
		elements.addAll(flows);
		
		File javaFile = getJavaBinaryFile();
		File analysisJarFile = getAnalysisJarFile();

		if (javaFile != null && analysisJarFile != null) {
			ProcessBuilder builder = new ProcessBuilder() //
					.command(//
							javaFile.toString(), //
							// "-Xdebug", "-Xrunjdwp:transport=dt_socket,address=127.0.0.1:9000,suspend=y",
							// //
							"-jar", //
							analysisJarFile.toString())
					.redirectError(Redirect.INHERIT);
			Process process = builder.start();
			PrintWriter pw = new PrintWriter(process.getOutputStream());
			//PrintStream pw = System.out;
			pw.println(sootClassPath);
			pw.println(String.join(";", canonicalClassNames));
			pw.println(XMLHelper.serialize(elements).replace("\n", " "));
			pw.flush();

			BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));

			while (!process.waitFor(50, TimeUnit.MILLISECONDS)) {
				if (progressReporter.isCanceled()) {
					process.destroyForcibly();
				}
				readInput(br);
			}
			readInput(br);
		}
		return this.analysisResult;
	}

	private void readInput(BufferedReader br) throws IOException {
		while (br.ready()) {
			String line = null;
			try {
				line = br.readLine();
				if (line == null) {
					break;
				}
			} catch (IOException e) {
				e.printStackTrace();
				break;
			}

			try {
				handleReceived((EObject) XMLHelper.deserializeList(line).get(0));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void handleReceived(EObject element) {
		if (element instanceof AnalysisResult) {
			this.analysisResult = (AnalysisResult) element;
		} else if (element instanceof ProgressReport) {
			this.progressReporter.reportProgress((ProgressReport) element);
		}
	}

	public AnalysisResult run(String sootClassPath, List<String> canonicalClassNames, List<TaintFlow> flowQueries, List<Flow> flows) {
		try {
			return runThrows(sootClassPath, canonicalClassNames, flowQueries, flows);
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
		return null;
	}

	private static File getAnalysisJarFile() throws IOException {
		if (SecuCheckAnalysis.analysisJarFile == null || !SecuCheckAnalysis.analysisJarFile.exists()) {
			SecuCheckAnalysis.analysisJarFile = provideResource("/analysis.jar");
		}
		return SecuCheckAnalysis.analysisJarFile;
	}

	private static File provideResource(String resourcePath) throws IOException {
		InputStream is = SecuCheckAnalysis.class.getResourceAsStream(resourcePath);
		File file = File.createTempFile("SecuCheck", resourcePath.replace('/', '-'));
		FileUtils.copyInputStreamToFile(is, file);
		file.deleteOnExit();
		return file;
	}

	private File getJavaBinaryFile() {
		File javaHome = new File(System.getProperty("java.home"));
		File javaFiles[] = new File[] { new File(javaHome, "/bin/java.exe"), new File(javaHome, "/bin/java") };
		for (File javaFile : javaFiles) {
			if (javaFile.exists()) {
				return javaFile;
			}
		}
		return null;
	}
}
