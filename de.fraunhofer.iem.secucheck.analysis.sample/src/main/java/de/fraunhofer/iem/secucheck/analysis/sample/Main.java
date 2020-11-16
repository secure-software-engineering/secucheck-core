package de.fraunhofer.iem.secucheck.analysis.sample;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.client.SecuCheckTaintAnalysisOutOfProcess;
import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysis;
import de.fraunhofer.iem.secucheck.analysis.SecucheckTaintAnalysis;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.ReportSite;
import de.fraunhofer.iem.secucheck.analysis.query.ReturnValue;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;

public class Main {
	
	public static void main(String[] args) {
		try {
			// Run the in-process hosted instance of the SecucheckTaintAnalysis.
			runSecucheckAnalysis(new SecucheckTaintAnalysis());
			
			// Run the out-of-process hosted instance of the SecucheckTaintAnalysis.
			runSecucheckAnalysis(new SecuCheckTaintAnalysisOutOfProcess());
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
	}
	
	private static void runSecucheckAnalysis(SecucheckAnalysis secucheckAnalysis) 
			throws Exception {
		
		AnalysisResultListener resultListener = new ConsoleResultListener();
		
		secucheckAnalysis.setOs(OS.Linux);
		secucheckAnalysis.setAnalysisEntryPoints(getEntryPoints());
		secucheckAnalysis.setApplicationClassPath(getAppClassPath());
		secucheckAnalysis.setSootClassPathJars(getSootClassPath());
				
		runDemoSet1(secucheckAnalysis, resultListener);
		runDemoSet2(secucheckAnalysis, resultListener);
		runDemoSet3(secucheckAnalysis, resultListener);
		
	}
	
	/** Demo-set 1: 
	 *  - Demonstrates basic intra-type's:
	 * 	 - Source
	 * 	 - Sink
	 * 	 - Sanitizer
	 * 	 - Propogator
	 *   By using using paramterized and non-paramterized usages.
	 *  - Demonstrates use of result-listener
	 */
	private static void runDemoSet1(SecucheckAnalysis secucheckAnalysis, 
			AnalysisResultListener resultListener) throws Exception {
		
		List<CompositeTaintFlowQueryImpl> compositeOfFirst = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "1", getTaintFlowQuery1()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfSecond = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "2", getTaintFlowQuery2()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfThird = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "3", getTaintFlowQuery3()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfFourth = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "4", getTaintFlowQuery4()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfFifth = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "5", getTaintFlowQuery5()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfSixth = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "6", getTaintFlowQuery6()));
		
		// For demonstration purposes the listener is set to null in run 1.
		runAnalysisQuery(secucheckAnalysis, compositeOfFirst, 1, resultListener);
		runAnalysisQuery(secucheckAnalysis, compositeOfSecond, 2, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfThird, 3, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfFourth, 4, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfFifth, 5, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfSixth, 6, null);
	}

	/** Demo-set 2: 
	 *  - Demonstrates 2 level inter-type taint-flow's:
	 * 	 - Source
	 * 	 - Sink
	 * 	 - Sanitizer
	 * 	 - Propogator
	 */
	private static void runDemoSet2(SecucheckAnalysis secucheckAnalysis, 
			AnalysisResultListener resultListener) throws Exception {
		
		List<CompositeTaintFlowQueryImpl> compositeOfSeventh = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "7", getTaintFlowQuery7()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfEighth = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "8", getTaintFlowQuery8()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfNinth = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "9", getTaintFlowQuery9()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfTenth = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "10", getTaintFlowQuery10()));
		
		runAnalysisQuery(secucheckAnalysis, compositeOfSeventh, 7, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfEighth, 8, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfNinth, 9, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfTenth, 10, null);
	}
	
	/** Demo-set 3: 
	 *  - Demonstrates multiple composites
	 */
	private static void runDemoSet3(SecucheckAnalysis secucheckAnalysis, 
			AnalysisResultListener resultListener) throws Exception {
		
		List<CompositeTaintFlowQueryImpl> compositeOfFirst = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "1", getTaintFlowQuery1()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfFirstTwo = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "1 & 2", getTaintFlowQuery1(),
						getTaintFlowQuery2()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfFirstThree = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "1,2 & 3", getTaintFlowQuery1(),
						getTaintFlowQuery2(), getTaintFlowQuery3()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfAll = Utility.getInList(
				Utility.getCompositeOf(ReportSite.SourceAndSink, "1,2,3 & 4", getTaintFlowQuery1(),
						getTaintFlowQuery2(), getTaintFlowQuery3(),
						getTaintFlowQuery4()));
		
		runAnalysisQuery(secucheckAnalysis, compositeOfFirst, 1, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfFirstTwo, 12, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfFirstThree, 13, null);
		runAnalysisQuery(secucheckAnalysis, compositeOfAll, 14, null);
	}
	
	private static void runAnalysisQuery(SecucheckAnalysis secucheckAnalysis, 
			List<CompositeTaintFlowQueryImpl> composites, int queryNumber, 
			AnalysisResultListener resultListener) throws Exception {
		secucheckAnalysis.setListener(resultListener);
		SecucheckTaintAnalysisResult result = secucheckAnalysis.run(composites);
		System.out.println();
		System.out.println("Result-" + queryNumber + " size: " + result.size());
	}

	/// Start: Definitions of taint-flows for intra-type ones.
	
	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workWithIssue()} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery1() {		
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL1SourceMethod());
		taintFlowQuery.addTo(Utility.getL1SinkMethod());		
		return taintFlowQuery;
	}
	
	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workNoIssueSanitizer()} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery2() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL1SourceMethod());
		taintFlowQuery.addNotThrough(Utility.getL1SanitizerMethod());
		taintFlowQuery.addTo(Utility.getL1SinkMethod());
		return taintFlowQuery;
	}
	
	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workWithIssueProgator()} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery3() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL1SourceMethod());
		taintFlowQuery.addThrough(Utility.getL1PropogatorMethod());
		taintFlowQuery.addTo(Utility.getL1SinkMethod());
		return taintFlowQuery;
	}
	
	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workNoIssueSanitizerProgator()} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery4() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL1SourceMethod());
		taintFlowQuery.addNotThrough(Utility.getL1SanitizerMethod());
		taintFlowQuery.addThrough(Utility.getL1PropogatorMethod());
		taintFlowQuery.addTo(Utility.getL1SinkMethod());
		return taintFlowQuery;
	}
	
	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workWithIssueParam()} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery5() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL1SourceParamMethod());
		taintFlowQuery.addTo(Utility.getL1SinkMethod());
		return taintFlowQuery;
	}
	
	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workWithIssueProgatorParam(int)} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery6() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL1SourcePropogratorParamMethod());
		taintFlowQuery.addThrough(Utility.getL1PropogatorMethod());
		taintFlowQuery.addTo(Utility.getL1SinkMethod());
		return taintFlowQuery;
	}
	
	/// End: Definitions of taint-flows for intra-type ones.
	
	/// Start: Definitions of taint-flows for inter-type ones.
	
	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workWithOtherTypeIssue()} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery7() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL2SourceMethod());
		taintFlowQuery.addTo(Utility.getL2SinkMethod());
		return taintFlowQuery;
	}
	
	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workWithOtherTypeIssueParam(int)} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery8() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL1SourceOtherTypeParamMethod());
		taintFlowQuery.addTo(Utility.getL2SinkMethod());
		return taintFlowQuery;
	}
	
	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workWithOtherTypeIssueProgator()} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery9() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL2SourceMethod());
		taintFlowQuery.addThrough(Utility.getL2PropogatorMethod());
		taintFlowQuery.addTo(Utility.getL2SinkMethod());
		return taintFlowQuery;
	}

	/**
	 *  Describing flow of: {@link #AnalyzeMeLevel1#workWithOtherTypeIssueProgator()} method. 
	 */
	private static TaintFlowQueryImpl getTaintFlowQuery10() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(Utility.getL1SourceOtherTypeIssuePropParamMethod());
		taintFlowQuery.addThrough(Utility.getL2PropogatorMethod());
		taintFlowQuery.addTo(Utility.getL2SinkMethod());
		return taintFlowQuery;
	}
	
	/// End: Definitions of taint-flows for inter-type ones.
	
	private static String getAppClassPath() {
		return System.getProperty("user.dir") + File.separator + "target" + File.separator + "classes";
	}
	
	private static String getSootClassPath() {		
		return 	System.getProperty("java.home") + File.separator + "lib" + File.separator +"rt.jar" ;
				
	}
	
	private static List<EntryPoint> getEntryPoints(){
		List<EntryPoint> entryPoints = new ArrayList<EntryPoint>();
	
		EntryPoint entryPoint = new EntryPoint();
		entryPoint.setCanonicalClassName("AnalyzeMeLevel1");
		entryPoint.setAllMethods(true);
		entryPoints.add(entryPoint);
		
		entryPoint = new EntryPoint();
		entryPoint.setCanonicalClassName("AnalyzeMeLevel2");
		entryPoint.setAllMethods(true);
		entryPoints.add(entryPoint);
		
		return entryPoints;
	}
}
