package de.fraunhofer.iem.secucheck.analysis.internal;


import java.util.ArrayList;
import java.util.List;

import boomerang.scene.WrappedClass;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.Stmt;

class Utility {
	
	static List<de.fraunhofer.iem.secucheck.analysis.query.Method> getMethods(CompositeTaintFlowQuery flowQuery) {
		List<de.fraunhofer.iem.secucheck.analysis.query.Method> methods = new ArrayList<>();
		for (TaintFlowQuery singleFlow: flowQuery.getTaintFlowQueries()) {
			methods.addAll(getMethods(singleFlow));
		}
		return methods;
	}
		
	static List<de.fraunhofer.iem.secucheck.analysis.query.Method> getMethods(TaintFlowQuery flowQuery) {
		List<de.fraunhofer.iem.secucheck.analysis.query.Method> methods = new ArrayList<>();
		flowQuery.getFrom().forEach(y -> methods.add((Method)y));
		flowQuery.getTo().forEach(y -> methods.add((Method)y));
		
		if (flowQuery.getNotThrough() != null)
			flowQuery.getNotThrough().forEach(y -> methods.add((Method)y));
		
		if (flowQuery.getThrough() != null)
			flowQuery.getThrough().forEach(y -> methods.add((Method)y));
		
		return methods;
	}
	
	static SootMethod getSootMethod(boomerang.scene.Method method) {
		WrappedClass wrappedClass = method.getDeclaringClass();
		SootClass clazz = (SootClass) wrappedClass.getDelegate();
		return clazz.getMethod(method.getSubSignature());
	}
	
	static SootMethod getSootMethod(de.fraunhofer.iem.secucheck.analysis.query.Method method) {
		String[] signatures = method.getSignature().split(":");
		SootClass sootClass = Scene.v().forceResolve(signatures[0], SootClass.BODIES);
		if (sootClass != null && signatures.length >= 2) {
			return sootClass.getMethodUnsafe(signatures[1].trim());
		}
		return null;
	}
	
	static SootMethod findSourceMethodDefinition(TaintFlowQuery partialFlow, 
			SootMethod method, Stmt actualStatement) {
		for (de.fraunhofer.iem.secucheck.analysis.query.Method sourceMethod : partialFlow.getFrom()) {
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
		for (de.fraunhofer.iem.secucheck.analysis.query.Method sinkMethod : partialFlow.getTo()) {
			String sinkSootSignature = "<" + sinkMethod.getSignature() + ">";
			if (actualStatement.containsInvokeExpr() &&
					actualStatement.toString().contains(sinkSootSignature)) {
				return actualStatement.getInvokeExpr().getMethodRef().tryResolve();
			}
		}
		return null;
	}
}
