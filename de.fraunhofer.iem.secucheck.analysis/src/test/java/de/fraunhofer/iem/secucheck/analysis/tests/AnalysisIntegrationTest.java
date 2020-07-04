package de.fraunhofer.iem.secucheck.analysis.tests;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;

import de.fraunhofer.iem.secucheck.analysis.SecuCheckAnalysis;
import de.fraunhofer.iem.secucheck.custom.ProgressReporter;
import de.fraunhofer.iem.secucheck.marker.AnalysisResult;
import de.fraunhofer.iem.secucheck.marker.Marker;
import de.fraunhofer.iem.secucheck.marker.ProgressReport;
import de.fraunhofer.iem.secucheck.query.Flow;
import de.fraunhofer.iem.secucheck.query.InputDeclaration;
import de.fraunhofer.iem.secucheck.query.Method;
import de.fraunhofer.iem.secucheck.query.OutputDeclaration;
import de.fraunhofer.iem.secucheck.query.Parameter;
import de.fraunhofer.iem.secucheck.query.PartialTaintFlow;
import de.fraunhofer.iem.secucheck.query.QueryFactory;
import de.fraunhofer.iem.secucheck.query.TaintFlow;

public class AnalysisIntegrationTest {

	@Test
	public void blackboxTest() {
	    final Logger logger = LogManager.getLogger();
	    logger.debug("X");
	    
		Method m1 = QueryFactory.eINSTANCE.createMethod();
		m1.setSignature("Test: int getSecret()");
		Method m2 = QueryFactory.eINSTANCE.createMethod();
		
		
		OutputDeclaration outDecl = QueryFactory.eINSTANCE.createOutputDeclaration();
		outDecl.getOutputs().add(QueryFactory.eINSTANCE.createReturnValue());
		m1.setOutputDeclaration(outDecl);
		
		InputDeclaration inDecl = QueryFactory.eINSTANCE.createInputDeclaration();
		Parameter param = QueryFactory.eINSTANCE.createParameter();
		param.setNumber(0);
		inDecl.getInputs().add(param);
		m2.setInputDeclaration(inDecl);
		
		
		m2.setSignature("Test: void publish(int)");
		TaintFlow flow = QueryFactory.eINSTANCE.createTaintFlow();
		PartialTaintFlow partialFlow = QueryFactory.eINSTANCE.createPartialTaintFlow();
		flow.getPartialTaintFlows().add(partialFlow);

		partialFlow.getFrom().add(m1);
		partialFlow.getTo().add(m2);
		
		flow.setReportMessage("Invalid Information Flow");
		flow.setReportLocation(3);
		
		List<TaintFlow> taintFlows = new ArrayList<TaintFlow>();
		taintFlows.add(flow);

		

		SecuCheckAnalysis analysis = new SecuCheckAnalysis(new ProgressReporter() {
			@Override
			public void reportProgress(ProgressReport report) {
				// do nothing
			}
			
			@Override
			public boolean isCanceled() {
				return false;
			}
		});
		
		List<String> entryPoints = new ArrayList<String>();
		entryPoints.add("Test");
		AnalysisResult result = analysis.run("src/test/resources", entryPoints, taintFlows, new ArrayList<Flow>());
		
		org.junit.Assert.assertTrue(result.getIssues().size() == 1 && result.getIssues().get(0).getMarkers().size() >= 2);
	}
}
