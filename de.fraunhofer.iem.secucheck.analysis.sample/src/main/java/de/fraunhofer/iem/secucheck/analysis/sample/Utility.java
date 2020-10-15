package de.fraunhofer.iem.secucheck.analysis.sample;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.ReportSite;
import de.fraunhofer.iem.secucheck.analysis.query.ReturnValue;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;

public class Utility {
	
	public static <T> List<T> getInList(T ... ts){
		List<T> list = new ArrayList<T>();
		for (T t:ts) {
			list.add(t);
		}
		return list;
	}
	
	
	public static CompositeTaintFlowQueryImpl getCompositeOf(ReportSite reportLoc, 
			String message, TaintFlowQueryImpl ...flowQueryImpls) {
		CompositeTaintFlowQueryImpl compositeQuery = new CompositeTaintFlowQueryImpl();
		compositeQuery.setReportLocation(reportLoc);
		compositeQuery.setReportMessage(message);		
		for (TaintFlowQueryImpl flowQuery : flowQueryImpls) {
			compositeQuery.addQuery(flowQuery);
		}		
		return compositeQuery;
	}
	
	
	/// Start: Generic taint-flow elements definition.
	
	private static MethodImpl getSourceMethod(String canonicalClassName) {
		List<InputParameter> inputs = new ArrayList<InputParameter>();
		List<OutputParameter> outputs = new ArrayList<OutputParameter>();
		ReturnValue returnValue = new ReturnValue();
		
		MethodImpl method = new MethodImpl();
		method.setName("getSecret");
		method.setSignature(canonicalClassName + ": int getSecret()");
		method.setInputParameters(inputs);
		method.setOutputParameters(outputs);
		method.setReturnValue(returnValue);
		return method;
	}
	
	private static MethodImpl getSanitizerMethod(String canonicalClassName) {
		InputParameter input = new InputParameter();
		input.setNumber(0);
		
		List<InputParameter> inputs = new ArrayList<InputParameter>();
		inputs.add(input);
		
		List<OutputParameter> outputs = new ArrayList<OutputParameter>();
		ReturnValue returnValue = null;
		
		MethodImpl method = new MethodImpl();
		method.setName("sanatizer");
		method.setSignature(canonicalClassName + ": int sanatizer(int)");
		method.setInputParameters(inputs);
		method.setOutputParameters(outputs);
		method.setReturnValue(returnValue);
		return method;
	}
	
	private static MethodImpl getPropogatorMethod(String canonicalClassName) {
		InputParameter input = new InputParameter();
		input.setNumber(0);
		
		List<InputParameter> inputs = new ArrayList<InputParameter>();
		inputs.add(input);
		
		List<OutputParameter> outputs = new ArrayList<OutputParameter>();
		ReturnValue returnValue = new ReturnValue();
		
		MethodImpl method = new MethodImpl();
		method.setName("propogator");
		method.setSignature(canonicalClassName + ": int propogator(int)");
		method.setInputParameters(inputs);
		method.setOutputParameters(outputs);
		method.setReturnValue(returnValue);
		return method;
	}
	
	private static MethodImpl getSinkMethod(String canonicalClassName) {
		InputParameter input = new InputParameter();
		input.setNumber(0);
		
		List<InputParameter> inputs = new ArrayList<InputParameter>();
		inputs.add(input);
		
		List<OutputParameter> outputs = new ArrayList<OutputParameter>();
		ReturnValue returnValue = null;
		
		MethodImpl method = new MethodImpl();
		method.setName("publish");
		method.setSignature(canonicalClassName + ": void publish(int)");
		method.setInputParameters(inputs);
		method.setOutputParameters(outputs);
		method.setReturnValue(returnValue);
		return method;
	}
	
	public static MethodImpl getUsageSourceParameMethod(String canonicalClassName,
			String methodName) {
		
		List<InputParameter> inputs = new ArrayList<InputParameter>();
		List<OutputParameter> outputs = new ArrayList<OutputParameter>();
		ReturnValue returnValue = null;
		
		// For the first input parameter.
		OutputParameter outputParam = new OutputParameter();
		outputParam.setNumber(0);
		outputs.add(outputParam);
		
		MethodImpl method = new MethodImpl();
		method.setName("getSecret");
		method.setSignature(canonicalClassName+": "+methodName);
		method.setInputParameters(inputs);
		method.setOutputParameters(outputs);
		method.setReturnValue(returnValue);
		return method;
	}
	
	/// End: Generic tTaint-flow elements definition.
	
	/// Start: Taint-flow elements level: 1 definition.
	
	public static MethodImpl getL1SourceMethod() {
		return getSourceMethod("AnalyzeMeLevel1");
	}
	
	public static MethodImpl getL1SanitizerMethod() {
		return getSanitizerMethod("AnalyzeMeLevel1");
	}
	
	public static MethodImpl getL1PropogatorMethod() {
		return getPropogatorMethod("AnalyzeMeLevel1");
	}
	
	public static MethodImpl getL1SinkMethod() {
		return getSinkMethod("AnalyzeMeLevel1");
	}
	
	public static MethodImpl getL1SourceParamMethod() {
		return getUsageSourceParameMethod("AnalyzeMeLevel1",
				"void workWithIssueParam(int)");
	}
	
	public static MethodImpl getL1SourcePropogratorParamMethod() {
		return getUsageSourceParameMethod("AnalyzeMeLevel1",
				"void workWithIssueProgatorParam(int)");
	}
	
	
	public static MethodImpl getL1SourceOtherTypeParamMethod() {
		return getUsageSourceParameMethod("AnalyzeMeLevel1",
				"void workWithOtherTypeIssueParam(int)");
	}
	
	public static MethodImpl getL1SourceOtherTypeIssuePropParamMethod() {
		return getUsageSourceParameMethod("AnalyzeMeLevel1",
				"void workWithOtherTypeIssueProgatorParam(int)");
	}
	
	/// End: Taint-flow elements level: 1 definition.
	
	/// Start: Taint-flow elements level: 2 definition.
	
	public static MethodImpl getL2SourceMethod() {
		return getSourceMethod("AnalyzeMeLevel2");
	}
	
	public static MethodImpl getL2SanitizerMethod() {
		return getSanitizerMethod("AnalyzeMeLevel2");
	}
	
	public static MethodImpl getL2PropogatorMethod() {
		return getPropogatorMethod("AnalyzeMeLevel2");
	}
	
	public static MethodImpl getL2SinkMethod() {
		return getSinkMethod("AnalyzeMeLevel2");
	}
	
	/// End: Taint-flow elements level: 2 definition.
	
	/// Start: Taint-flow elements level: 3 definition.
	
	public static MethodImpl getL3SourceMethod(String canonicalClassName) {
		return getSourceMethod("AnalyzeMeLevel3");
	}
	
	public static MethodImpl getL3SanitizerMethod() {
		return getSanitizerMethod("AnalyzeMeLevel3");
	}
	
	public static MethodImpl getL3PropogatorMethod() {
		return getPropogatorMethod("AnalyzeMeLevel3");
	}
	
	public static MethodImpl getL3SinkMethod() {
		return getSinkMethod("AnalyzeMeLevel3");
	}
	
	/// End: Taint-flow elements level: 3 definition.
	
}
