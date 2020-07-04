package de.fraunhofer.iem.secucheck.analysis;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.emf.common.util.BasicEList;
import org.eclipse.emf.common.util.EList;
import org.eclipse.emf.ecore.EObject;

import de.fraunhofer.iem.secucheck.custom.ProgressReporter;
import de.fraunhofer.iem.secucheck.custom.XMLHelper;
import de.fraunhofer.iem.secucheck.marker.AnalysisResult;
import de.fraunhofer.iem.secucheck.marker.ProgressReport;
import de.fraunhofer.iem.secucheck.query.Flow;
import de.fraunhofer.iem.secucheck.query.TaintFlow;

public class Server implements ProgressReporter {
	private ByteArrayOutputStream baos = new ByteArrayOutputStream();
	private PrintStream systemOut = System.out;

	private SecuCheckAnalysis analysis = new SecuCheckAnalysis();

	public Server() {
		System.setOut(new PrintStream(baos));
		final Logger logger = LogManager.getLogger();
		logger.debug("X");
	}

	public static void main(String[] args) {
		try {
			new Server().run();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void run() throws IOException {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

		String sootClassPath = br.readLine();
		List<String> canonicalClassNames = Arrays.asList(br.readLine().split(";"));
		EList<? extends EObject> elements = XMLHelper.deserializeList(br.readLine());
		List<TaintFlow> flowQueries = filterType(elements, TaintFlow.class);
		List<Flow> flows = filterType(elements, Flow.class);

		AnalysisResult result = analysis.run(sootClassPath, canonicalClassNames, flowQueries, flows);
		systemOut.println(XMLHelper.serialize(result));

		System.err.print(baos.toString());
	}

	@SuppressWarnings("unchecked")
	private <T> EList<T> filterType(EList<? extends EObject> list, Class<T> type) {
		EList<T> result = new BasicEList<T>();
		for (EObject element : list) {
			if (type.isInstance(element)) {
				result.add((T) element);
			}
		}
		return result;
		
	}


	@Override
	public void reportProgress(ProgressReport report) {
		systemOut.println(XMLHelper.serialize(report));
	}

	@Override
	public boolean isCanceled() {
		return false;
	}
}
