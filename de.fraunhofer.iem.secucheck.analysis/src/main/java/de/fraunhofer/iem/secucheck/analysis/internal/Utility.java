package de.fraunhofer.iem.secucheck.analysis.internal;


import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import boomerang.seedfactory.Method;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.Stmt;

public class Utility {
	
	static List<Method> getMethods(CompositeTaintFlowQuery flowQuery) {
		List<Method> methods = new ArrayList<Method>();
		flowQuery.getTaintFlowQueries().forEach(flow -> methods.addAll(getMethods(flow)));
		return methods;
	}
		
	static List<Method> getMethods(TaintFlowQuery flowQuery) {
		List<Method> methods = new ArrayList<Method>();
		flowQuery.getFrom().forEach(p -> methods.addAll(getMethods(p)));
		flowQuery.getTo().forEach(p -> methods.addAll(getMethods(p)));
		flowQuery.getNotThrough().forEach(p -> methods.addAll(getMethods(p)));
		flowQuery.getThrough().forEach(p -> methods.addAll(getMethods(p)));
		return methods;
	}

	static List<Method> getMethods(FlowParticipant p) {
		if (p instanceof MethodSet) {
			return ((MethodSet) p).getMethods();
		} else if (p instanceof Method) {
			return Collections.singletonList((Method) p);
		}
		return Collections.emptyList();
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
		for (FlowParticipant p : partialFlow.getFrom()) {
			for (Method sourceMethod : Utility.getMethods(p)) {
				String sourceSootSignature = "<" + sourceMethod.getSignature() + ">";
				if (method.getSignature().equals(sourceSootSignature)) {
					return method;
				} else if (actualStatement.containsInvokeExpr() && 
						actualStatement.toString().contains(sourceSootSignature)) {
					return actualStatement.getInvokeExpr().getMethodRef().tryResolve();
				}
			}
		}
		return null;
	}
	

	static SootMethod findSinkMethodDefinition(TaintFlowQuery partialFlow,
			SootMethod method, Stmt actualStatement) {
		for (FlowParticipant p : partialFlow.getTo()) {
			for (Method sinkMethod : Utility.getMethods(p)) {
				String sourceSootSignature = "<" + sinkMethod.getSignature() + ">";
				if (actualStatement.containsInvokeExpr() &&
						actualStatement.toString().contains(sourceSootSignature)) {
					return actualStatement.getInvokeExpr().getMethodRef().tryResolve();
				}
			}
		}
		return null;
	}
	

}
