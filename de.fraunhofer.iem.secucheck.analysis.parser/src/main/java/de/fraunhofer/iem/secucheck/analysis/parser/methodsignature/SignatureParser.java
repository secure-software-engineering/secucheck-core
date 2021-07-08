package de.fraunhofer.iem.secucheck.analysis.parser.methodsignature;

import java.util.ArrayList;
import java.util.List;

public class SignatureParser {

	public static boolean matches(Object sootSignature, Object dslSignature) {
		
		ParsedMethodSignature parsedSootSignature = parseSootSignature(sootSignature);
		ParsedMethodSignature parsedDSLSignature = parseDSLSignature(dslSignature);
		if(parsedDSLSignature.getMethodArguments().size()==1 && 
				parsedDSLSignature.getMethodArguments().get(0) == "ANY") {
			
			if( parsedDSLSignature.getClassName().equals(parsedSootSignature.getClassName()) 
				&& parsedDSLSignature.getReturnType().equals(parsedSootSignature.getReturnType()) 
				&& parsedDSLSignature.getMethodName().equals(parsedSootSignature.getMethodName()) ) {
				return true;
			}
			else {
				return false;
			}
			
		}
		
		if( parsedDSLSignature.getClassName().equals(parsedSootSignature.getClassName()) 
				&& parsedDSLSignature.getReturnType().equals(parsedSootSignature.getReturnType()) 
				&& parsedDSLSignature.getMethodName().equals(parsedSootSignature.getMethodName())
				&& parsedDSLSignature.getMethodArguments().equals(parsedSootSignature.getMethodArguments()) ) {
				return true;
			}
		
		return false;
		
	}
	
	
	private static ParsedMethodSignature parseDSLSignature(Object signature) {
		
		String strSignature = signature.toString();
		ParsedMethodSignature parsedSignature = new ParsedMethodSignature();
		String methodFullyQualifiedName;
		
		if(strSignature.isBlank()) {
			return parsedSignature;
		}
		
		if(strSignature.contains(":")) {
			String[] subSignatures = strSignature.split(":");
			if(subSignatures.length == 2) {
				parsedSignature.setClassName(subSignatures[0].replace("\\s+", ""));
				methodFullyQualifiedName = subSignatures[1].trim();
			}
			else {
				throw new RuntimeException("Error during method signature parsing process.");
			}
		}
		else {
			parsedSignature.setClassName("");
			methodFullyQualifiedName = strSignature;
		}
		
		String[] splittedMethodFullyQualifiedName = methodFullyQualifiedName.split("\\s+", 2);
		parsedSignature.setReturnType(splittedMethodFullyQualifiedName[0].trim());
		
		String methodNameAndParam = splittedMethodFullyQualifiedName[1].trim();
		parsedSignature.setMethodName(methodNameAndParam.substring(0, methodNameAndParam.indexOf("(")));
		
		String methodParam = methodNameAndParam.substring(methodNameAndParam.indexOf("(")+1, methodNameAndParam.indexOf(")"));
		List<String> methodArgs = new ArrayList<>();
		if(methodParam.isBlank()){
			methodArgs.add("");
			parsedSignature.setMethodArguments(methodArgs);
		} 
		else {
			String[] methodParamArray = methodParam.split(",");
			for(String param : methodParamArray) {
				methodArgs.add(param.replace("\\s+", ""));
			}
			parsedSignature.setMethodArguments(methodArgs);
		}
		
		return parsedSignature;
		
	}
	
	
	private static ParsedMethodSignature parseSootSignature(Object signature) {
		
		String strSignature = signature.toString();
		return parseDSLSignature(strSignature.substring(1, strSignature.length() - 1));
		
	}
	
}
