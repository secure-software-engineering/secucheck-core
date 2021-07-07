package de.fraunhofer.iem.secucheck.analysis.parser.methodsignature;

import java.util.ArrayList;
import java.util.List;

public class ParsedMethodSignature {
	
	private String className;
	private String returnType;
	private String methodName;
	private List<String> methodArguments;
	
	public ParsedMethodSignature() {
		this.className = null;
		this.returnType = null;
		this.methodName = null;
		this.methodArguments = new ArrayList<>();
	}
	
	public String getClassName() {
		return className;
	}
	public void setClassName(String className) {
		this.className = className;
	}
	public String getReturnType() {
		return returnType;
	}
	public void setReturnType(String returnType) {
		this.returnType = returnType;
	}
	public String getMethodName() {
		return methodName;
	}
	public void setMethodName(String methodName) {
		this.methodName = methodName;
	}
	public List<String> getMethodArguments() {
		return methodArguments;
	}
	public void setMethodArguments(List<String> methodArguments) {
		this.methodArguments = methodArguments;
	}
	
}
