package de.fraunhofer.iem.secucheck.analysis.parser.methodsignature;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

public class SignatureParser {

	public static boolean matches(Object sootSignature, Object dslSignature) {
		
		ParsedMethodSignature parsedSootSignature = parseSootSignature(sootSignature);
		ParsedMethodSignature parsedDSLSignature = parseDSLMethodSignature(dslSignature);
		
		if( parsedDSLSignature.getMethodArguments().size()==1 && 
				parsedDSLSignature.getMethodArguments().get(0).equals("ANY") ) {
			
			if( areEqualBesidesArgs(parsedSootSignature, parsedDSLSignature) ) {
				return true;
			}
			return false;
		}
		
		if( parsedDSLSignature.getMethodArguments().contains("_") ) {
			
			if( parsedDSLSignature.getMethodArguments().size() == parsedSootSignature.getMethodArguments().size()
				&& areEqualBesidesArgs(parsedSootSignature, parsedDSLSignature) ) {
				
				for(int i=0; i<parsedDSLSignature.getMethodArguments().size(); i++) {
					if( !parsedDSLSignature.getMethodArguments().get(i).equals("_")
						&& !parsedDSLSignature.getMethodArguments().get(i).equals(parsedSootSignature.getMethodArguments().get(i)) ) {
						return false;
					}
				}
				return true;
				
			}
			
		}
		
		if( areEqualBesidesArgs(parsedSootSignature, parsedDSLSignature)
			&& parsedDSLSignature.getMethodArguments().equals(parsedSootSignature.getMethodArguments()) ) {
				return true;
			}
		return false;
	}
	
	
	public static ParsedMethodSignature parseDSLMethodSignature(Object signature) {
		ParsedMethodSignature parsedSignature = new ParsedMethodSignature();
		String strSignature = signature.toString();
		
		try {
			String methodPartialQualifiedName = "";
			
			if(StringUtils.isBlank(strSignature)) {
				return parsedSignature;
			}
			
			if(strSignature.contains(":")) {
				String[] subSignatures = strSignature.split(":");
				if(subSignatures.length == 2) {
					parsedSignature.setClassName(subSignatures[0].replace("\\s+", ""));
					methodPartialQualifiedName = subSignatures[1].trim();
				} else {
					return parsedSignature;
				}
			}
			else {
				methodPartialQualifiedName = strSignature;
			}
			
			String[] splittedMethodFullyQualifiedName = methodPartialQualifiedName.split("\\s+", 2);
			parsedSignature.setReturnType(splittedMethodFullyQualifiedName[0].trim());
			
			String methodNameAndParam = splittedMethodFullyQualifiedName[1].trim();
			parsedSignature.setMethodName(methodNameAndParam.substring(0, methodNameAndParam.indexOf("(")).trim());
			
			String methodParam = methodNameAndParam.substring(methodNameAndParam.indexOf("(")+1, methodNameAndParam.indexOf(")"));
			List<String> methodArgs = new ArrayList<>();
			if(StringUtils.isBlank(methodParam)){
				methodArgs.add("");
				parsedSignature.setMethodArguments(methodArgs);
			} 
			else {
				String[] methodParamArray = methodParam.split(",");
				for(String param : methodParamArray) {
					methodArgs.add(param.replaceAll("\\s",""));
				}
				parsedSignature.setMethodArguments(methodArgs);
			}
		} catch(Exception e) {
			throw new RuntimeException("Unable to parse method signature:\n"+strSignature);
		}
		
		return parsedSignature;
		
	}
	
	public static String parseDSLClassOrPackageSignature(Object signature) {
		String strSignature = signature.toString();
		if(StringUtils.isBlank(strSignature)) {
			return "";
		}
		return strSignature.replaceAll("\\s", "");
	}
	
	
	private static ParsedMethodSignature parseSootSignature(Object signature) {
		
		String strSignature = signature.toString();
		return parseDSLMethodSignature(strSignature.substring(1, strSignature.length() - 1));
		
	}
	
	
	private static boolean areEqualBesidesArgs(ParsedMethodSignature parsedSootSignature, ParsedMethodSignature parsedDSLSignature) {
		
		if( parsedDSLSignature.getClassName().equals(parsedSootSignature.getClassName()) 
				&& parsedDSLSignature.getReturnType().equals(parsedSootSignature.getReturnType()) 
				&& parsedDSLSignature.getMethodName().equals(parsedSootSignature.getMethodName()) ) {
			return true;
		}
		
		return false;
	}
	
}
