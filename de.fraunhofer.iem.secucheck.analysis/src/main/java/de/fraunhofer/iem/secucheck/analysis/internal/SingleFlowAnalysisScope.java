package de.fraunhofer.iem.secucheck.analysis.internal;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.Sets;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.callgraph.ObservableICFG;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import boomerang.seedfactory.SeedFactory;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.IdentityStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.ParameterRef;
import soot.jimple.Stmt;
import wpds.impl.Weight.NoWeight;

public class SingleFlowSeedFactory extends SeedFactory<NoWeight>{

	private final TaintFlowQuery taintFlow;
	private final ObservableICFG<Unit, SootMethod> icfg;
	
	private final Set<SootMethod> sourceMethods = new HashSet<SootMethod>();
	private final Set<SootMethod> sinkMethods = new HashSet<SootMethod>();
	
	public SingleFlowSeedFactory(TaintFlowQuery taintFlow, ObservableICFG<Unit, SootMethod> icfg) {
		this.taintFlow = taintFlow;
		this.icfg = icfg;
	}
	
	@Override
	protected Collection<? extends Query> generate(SootMethod method, Stmt u) {
		Set<Query> out = Sets.newHashSet();
		
		Collection<Value> sourceVariables = generateSourceVariables(this.taintFlow, method, u);
		sourceVariables.forEach(v -> 
			out.add(new ForwardQuery(new Statement(u, method), new Val(v, method))) );
		
		Collection<Value> sinkVariables = generatedSinkVariables(this.taintFlow, method, u);
		sinkVariables.forEach(v -> 
			out.add(new BackwardQuery(new Statement(u, method), new Val(v, method))));
		
		// Find source method	
		for (Method flowMethod : this.taintFlow.getFrom()) {
			if (method.toString().equals("<" + flowMethod.getSignature() + ">")) {
				sourceMethods.add(method);
			}
		}

		// Find target method				
		for (Method flowMethod : this.taintFlow.getTo()) {
			if (method.toString().equals("<" + flowMethod.getSignature() + ">")) {
				sinkMethods.add(method);
			}
		}
		return out;
	}
	
	@Override
	public ObservableICFG<Unit, SootMethod> icfg() { return this.icfg; }
	
	private Collection<Value> generateSourceVariables(TaintFlowQuery partialFlow, 
			SootMethod method, Stmt actualStatement) {
		
		for (Object object : partialFlow.getFrom()) {
			Method sourceMethod = (Method) object;
			String sourceSootSignature = "<" + sourceMethod.getSignature() + ">";
			Collection<Value> out = Sets.newHashSet();

			if (method.getSignature().equals(sourceSootSignature) && 
					actualStatement instanceof IdentityStmt) {
				
				IdentityStmt identity = (IdentityStmt) actualStatement;
				Value right = identity.getRightOp();
				if (right instanceof ParameterRef) {
					
					ParameterRef parameterRef = (ParameterRef) right;
					if (sourceMethod.getOutputParameters() != null) {
						for (OutputParameter output : sourceMethod.getOutputParameters()) {
							int parameterIndex = output.getNumber();
							if (parameterRef.getIndex() == parameterIndex
									&& method.getParameterCount() >= parameterIndex) {
								out.add(identity.getLeftOp());
							}
						}
					}
					
				}
				return out;

			} else if (actualStatement.containsInvokeExpr()
					&& actualStatement.toString().contains(sourceSootSignature)) {

				// taint the return value
				if (sourceMethod.getReturnValue() != null && actualStatement instanceof AssignStmt) {
					out.add(((AssignStmt) actualStatement).getLeftOp());
				} 
				
				if (sourceMethod.getOutputParameters() != null) {
					for (OutputParameter output : sourceMethod.getOutputParameters()) {
						int parameterIndex =  output.getNumber();
						if (actualStatement.getInvokeExpr().getArgCount() >= parameterIndex) {
							out.add(actualStatement.getInvokeExpr().getArg(parameterIndex));
						}
					}
				}
				
				// taint this object
				if (sourceMethod.isOutputThis() && actualStatement.getInvokeExpr() instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) actualStatement.getInvokeExpr();
					out.add(instanceInvoke.getBase());
				}
				
				return out;
			}

		}
	

//		if (this.flow.getSource().getValueSource() != null) // a single value source
//		{
//			// TODO:handle this
//		} 
		return Collections.emptySet();
	}

	private Collection<Value> generatedSinkVariables(TaintFlowQuery partialFlow, 
			SootMethod method, Stmt actualStatement) {
		for (Object object : partialFlow.getTo()) {
			Method sourceMethod = (Method) object;
			String sourceSootSignature = "<" + sourceMethod.getSignature() + ">";
			Collection<Value> out = Sets.newHashSet();

			if (actualStatement.containsInvokeExpr() 
					&& actualStatement.toString().contains(sourceSootSignature)) {
				
				// taint the return value
				if (sourceMethod.getInputParameters() != null) {
					for (InputParameter input : sourceMethod.getInputParameters()) {
						int parameterIndex = input.getNumber();
						if (actualStatement.getInvokeExpr().getArgCount() >= parameterIndex) {
							out.add(actualStatement.getInvokeExpr().getArg(parameterIndex));
						}
					}
				}
				
				// taint this object
				if (sourceMethod.isInputThis() && actualStatement.getInvokeExpr() instanceof InstanceInvokeExpr) {
					InstanceInvokeExpr instanceInvoke = (InstanceInvokeExpr) actualStatement.getInvokeExpr();
					out.add(instanceInvoke.getBase());
				}
				
				return out;
			}

		}
		// TODO: re-check the sink structure!!
		return Collections.emptySet();
	}	
}
