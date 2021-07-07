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
		
		String[] subSignatures = strSignature.split(":");
		if(subSignatures.length == 2) {
			parsedSignature.setClassName(subSignatures[0].replace("\\s+", ""));
		}
		else {
			throw new RuntimeException("Error during method signature parsing process.");
		}
		
		String methodFullyQualifiedName = subSignatures[1].trim();
		String[] splittedMethodFullyQualifiedName = methodFullyQualifiedName.split("\\s+", 2);
		parsedSignature.setReturnType(splittedMethodFullyQualifiedName[0].trim());
		
		String methodNameAndParam = splittedMethodFullyQualifiedName[1].trim();
		parsedSignature.setMethodName(methodNameAndParam.substring(0, methodNameAndParam.indexOf("(")));
		
		String[] methodParamArray = methodNameAndParam.substring(methodNameAndParam.indexOf("(")+1, methodNameAndParam.indexOf(")")).split(",");
		List<String> methodArgs = new ArrayList<>();
		for(String param : methodParamArray) {
			methodArgs.add(param.replace("\\s+", ""));
		}
		parsedSignature.setMethodArguments(methodArgs);
		
		return parsedSignature;
		
	}
	
	
	private static ParsedMethodSignature parseSootSignature(Object signature) {
		
		String strSignature = signature.toString();
		return parseDSLSignature(strSignature.substring(1, strSignature.length() - 1));
		
	}
	
}
