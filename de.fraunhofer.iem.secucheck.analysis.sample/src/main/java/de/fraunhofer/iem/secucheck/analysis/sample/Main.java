package de.fraunhofer.iem.secucheck.analysis.sample;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.client.SecuCheckTaintAnalysisOutOfProcess;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysis;
import de.fraunhofer.iem.secucheck.analysis.SecucheckTaintAnalysis;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.ReturnValue;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.CompositeTaintFlowQueryResult;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.TaintFlowQueryResult;

public class Main {

	enum OS { Windows, LinuxOrMac }
	
	public static void main(String[] args) {
		try {
			// Run the in-process hosted instance of the SecucheckTaintAnalysis.
			runSecucheckAnalysis(new SecucheckTaintAnalysis());
			
			// Run the out-of-process hosted instance of the SecucheckTaintAnalysis.
			runSecucheckAnalysis(new SecuCheckTaintAnalysisOutOfProcess());
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void runSecucheckAnalysis(SecucheckAnalysis secucheckAnalysis) 
			throws Exception {
	
		List<CompositeTaintFlowQueryImpl> compositeOfFirst = getInList(
				getCompositeOf(0, "1", getTaintFlowQuery1()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfFirstTwo = getInList(
				getCompositeOf(0, "1 & 2", getTaintFlowQuery1(),
						getTaintFlowQuery2()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfFirstThree = getInList(
				getCompositeOf(0, "1,2 & 3", getTaintFlowQuery1(),
						getTaintFlowQuery2(), getTaintFlowQuery3()));
		
		List<CompositeTaintFlowQueryImpl> compositeOfAll = getInList(
				getCompositeOf(0, "1,2,3 & 4", getTaintFlowQuery1(),
						getTaintFlowQuery2(), getTaintFlowQuery3(),
						getTaintFlowQuery4()));
		
		List<String> classesToAnalyse = Arrays.asList(getClassesToAnalyze().split(";"));
		String sootClassPath = getSootClassPath(OS.LinuxOrMac);
		AnalysisResultListener resultListener = getConsoleResultListener();
		
		secucheckAnalysis.setAnalysisClasses(classesToAnalyse);
		secucheckAnalysis.setSootClassPath(sootClassPath);
		secucheckAnalysis.setListener(resultListener);
		
		SecucheckTaintAnalysisResult result1 = secucheckAnalysis.run(compositeOfFirst);
		System.out.println();
		System.out.println("Result-1 size: " + result1.size());
		
		// For demonstration purposes the listener is set to null.
		secucheckAnalysis.setListener(null);
		SecucheckTaintAnalysisResult result2 = secucheckAnalysis.run(compositeOfFirstTwo);
		System.out.println();
		System.out.println("Result-2 size: " + result2.size());
		
		secucheckAnalysis.setListener(resultListener);
		SecucheckTaintAnalysisResult result3 = secucheckAnalysis.run(compositeOfFirstThree);
		System.out.println();
		System.out.println("Result-3 size: " + result3.size());
		
		// For demonstration purposes the listener is set to null.
		secucheckAnalysis.setListener(null);
		SecucheckTaintAnalysisResult result4 = secucheckAnalysis.run(compositeOfAll);
		System.out.println();
		System.out.println("Result-4 size: " + result4.size());
	}
		
	private static MethodImpl getSourceMethod() {
		List<InputParameter> inputs = new ArrayList<InputParameter>();
		List<OutputParameter> outputs = new ArrayList<OutputParameter>();
		ReturnValue returnValue = new ReturnValue();
		
		MethodImpl method = new MethodImpl();
		method.setName("getSecret");
		method.setSignature("AnalyzeMe: int getSecret()");
		method.setInputParameters(inputs);
		method.setOutputParameters(outputs);
		method.setReturnValue(returnValue);
		return method;
	}
	
	private static MethodImpl getSanitizerMethod() {
		InputParameter input = new InputParameter();
		input.setNumber(0);
		
		List<InputParameter> inputs = new ArrayList<InputParameter>();
		inputs.add(input);
		
		List<OutputParameter> outputs = null;
		ReturnValue returnValue = null;
		
		MethodImpl method = new MethodImpl();
		method.setName("sanatizer");
		method.setSignature("AnalyzeMe: int sanatizer(int)");
		method.setInputParameters(inputs);
		method.setOutputParameters(outputs);
		method.setReturnValue(returnValue);
		return method;
	}
	
	private static MethodImpl getPropogatorMethod() {
		InputParameter input = new InputParameter();
		input.setNumber(0);
		
		List<InputParameter> inputs = new ArrayList<InputParameter>();
		inputs.add(input);
		
		List<OutputParameter> outputs = null;
		ReturnValue returnValue = null;
		
		MethodImpl method = new MethodImpl();
		method.setName("propogator");
		method.setSignature("AnalyzeMe: int propogator(int)");
		method.setInputParameters(inputs);
		method.setOutputParameters(outputs);
		method.setReturnValue(returnValue);
		return method;
	}
	
	private static MethodImpl getSinkMethod() {
		InputParameter input = new InputParameter();
		input.setNumber(0);
		
		List<InputParameter> inputs = new ArrayList<InputParameter>();
		inputs.add(input);
		
		List<OutputParameter> outputs = null;
		ReturnValue returnValue = null;
		
		MethodImpl method = new MethodImpl();
		method.setName("publish");
		method.setSignature("AnalyzeMe: void publish(int)");
		method.setInputParameters(inputs);
		method.setOutputParameters(outputs);
		method.setReturnValue(returnValue);
		return method;
	}
	
	private static TaintFlowQueryImpl getTaintFlowQuery1() {		
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(getSourceMethod());
		taintFlowQuery.addTo(getSinkMethod());		
		return taintFlowQuery;
	}
	
	private static TaintFlowQueryImpl getTaintFlowQuery2() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(getSourceMethod());
		taintFlowQuery.addNotThrough(getSanitizerMethod());
		taintFlowQuery.addTo(getSinkMethod());
		return taintFlowQuery;
	}
	
	private static TaintFlowQueryImpl getTaintFlowQuery3() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(getSourceMethod());
		taintFlowQuery.addThrough(getPropogatorMethod());
		taintFlowQuery.addTo(getSinkMethod());
		return taintFlowQuery;
	}
	
	private static TaintFlowQueryImpl getTaintFlowQuery4() {
		TaintFlowQueryImpl taintFlowQuery = new TaintFlowQueryImpl();
		taintFlowQuery.addFrom(getSourceMethod());
		taintFlowQuery.addNotThrough(getSanitizerMethod());
		taintFlowQuery.addThrough(getPropogatorMethod());
		taintFlowQuery.addTo(getSinkMethod());
		return taintFlowQuery;
	}
	
	private static CompositeTaintFlowQueryImpl getCompositeOf(int reportLoc, 
			String message, TaintFlowQueryImpl ...flowQueryImpls) {
		CompositeTaintFlowQueryImpl compositeQuery = new CompositeTaintFlowQueryImpl();
		compositeQuery.setReportLocation(reportLoc);
		compositeQuery.setReportMessage(message);		
		for (TaintFlowQueryImpl flowQuery : flowQueryImpls) {
			compositeQuery.addQuery(flowQuery);
		}		
		return compositeQuery;
	}
	
	private static <T> List<T> getInList(T ... ts){
		List<T> list = new ArrayList<T>();
		for (T t:ts) {
			list.add(t);
		}
		return list;
	}
		
	private static String getSootClassPath(OS os) {		
		// Use ';' for Windows and ':' for Linux or Mac.
		String pathSeparator= os == OS.Windows ? ";" : ":";
		return 	System.getProperty("java.home") + File.separator + "lib" + File.separator +"rt.jar" + 
				pathSeparator +
				System.getProperty("user.dir") + File.separator + "target" + File.separator + "classes";
	}
			
	private static String getClassesToAnalyze() {
		return "AnalyzeMe";
	}
	
	private static AnalysisResultListener getConsoleResultListener() {
		return new AnalysisResultListener() {
			
			public void reportFlowResult(TaintFlowQueryResult result) {
				System.out.println();
				System.out.println("Recieved single flow result, size:" + result.size());
			}
			
			public void reportCompositeFlowResult(CompositeTaintFlowQueryResult result) {
				System.out.println();
				System.out.println("Recieved composite flow result, size:" + result.size());
			}
			
			public void reportCompleteResult(SecucheckTaintAnalysisResult result) {
				System.out.println();
				System.out.println("Recieved complete result, size:" + result.size());
			}
			
			public boolean isCancelled() {
				return false;
			}
		};
	}
	
}
