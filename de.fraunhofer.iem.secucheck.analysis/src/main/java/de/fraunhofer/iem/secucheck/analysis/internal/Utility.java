package de.fraunhofer.iem.secucheck.analysis.internal;


import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.Stmt;

class Utility {
	
	static List<Method> getMethods(CompositeTaintFlowQuery flowQuery) {
		List<Method> methods = new ArrayList<Method>();
		for (TaintFlowQuery singleFlow: flowQuery.getTaintFlowQueries()) {
			methods.addAll(getMethods(singleFlow));
		}
		return methods;
	}
		
	static List<Method> getMethods(TaintFlowQuery flowQuery) {
		List<Method> methods = new ArrayList<Method>();
		flowQuery.getFrom().forEach(y -> methods.add((Method)y));
		flowQuery.getTo().forEach(y -> methods.add((Method)y));
		
		if (flowQuery.getNotThrough() != null)
			flowQuery.getNotThrough().forEach(y -> methods.add((Method)y));
		
		if (flowQuery.getThrough() != null)
			flowQuery.getThrough().forEach(y -> methods.add((Method)y));
		
		return methods;
	}
	
	static SootMethod getSootMethod(Method method) {
		String[] signatures = method.getSignature().split(":");
		SootClass sootClass = Scene.v().forceResolve(signatures[0], SootClass.BODIES);
		if (sootClass != null && signatures.length >= 2) {
			return sootClass.getMethodUnsafe(signatures[1].trim());
		}
		return null;
	}
	
	static SootMethod findSourceMethodDefinition(TaintFlowQuery partialFlow, 
			SootMethod method, Stmt actualStatement) {
		for (Method sourceMethod : partialFlow.getFrom()) {
			String sourceSootSignature = "<" + sourceMethod.getSignature() + ">";
			if (method.getSignature().equals(sourceSootSignature)) {
				return method;
			} else if (actualStatement.containsInvokeExpr() && 
					actualStatement.toString().contains(sourceSootSignature)) {
				return actualStatement.getInvokeExpr().getMethodRef().tryResolve();
			}
		}
		return null;
	}
	
	static SootMethod findSinkMethodDefinition(TaintFlowQuery partialFlow,
			SootMethod method, Stmt actualStatement) {
		for (Method sinkMethod : partialFlow.getTo()) {
			String sinkSootSignature = "<" + sinkMethod.getSignature() + ">";
			if (actualStatement.containsInvokeExpr() &&
					actualStatement.toString().contains(sinkSootSignature)) {
				return actualStatement.getInvokeExpr().getMethodRef().tryResolve();
			}
		}
		return null;
	}
}
