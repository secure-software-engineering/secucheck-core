package de.fraunhofer.iem.secucheck.analysis.internal;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.Sets;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.scene.AnalysisScope;
import boomerang.scene.ControlFlowGraph.Edge;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import boomerang.scene.jimple.SootCallGraph;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;

public class SingleFlowAnalysisScope extends AnalysisScope {

	private final TaintFlowQuery taintFlow;
	private final SootCallGraph sootCallGraph;
	
	private final Set<boomerang.scene.Method> sourceMethods = new HashSet<>();
	private final Set<boomerang.scene.Method> sinkMethods = new HashSet<>();
	
	public SingleFlowAnalysisScope(TaintFlowQuery taintFlow, SootCallGraph sootCallGraph) {
		super(sootCallGraph);
		this.taintFlow = taintFlow;
		this.sootCallGraph = sootCallGraph;
	}
	
	@Override
	protected Collection<? extends Query> generate(Edge cfgEdge) {
		
		boomerang.scene.Method method = cfgEdge.getMethod();
		Statement statement = cfgEdge.getTarget();
		
		Set<Query> out = Sets.newHashSet();
		
		// Inconsistency between instantiations of Forward and Backward queries.
		Collection<Val> sourceVariables = generateSourceVariables(this.taintFlow, method, statement);
		sourceVariables.forEach(v -> out.add(new ForwardQuery(cfgEdge, v)));
		
		Collection<Val> sinkVariables = generatedSinkVariables(this.taintFlow, method, statement);
		sinkVariables.forEach(v -> out.add(BackwardQuery.make(cfgEdge, v)));
		
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
	
	private Collection<Val> generateSourceVariables(TaintFlowQuery partialFlow, 
			boomerang.scene.Method method, Statement statement) {
		for (Method sourceMethod  : partialFlow.getFrom()) {
			String sourceSootSignature = "<" + sourceMethod.getSignature() + ">";
			Collection<Val> out = Sets.newHashSet();
			
			// method.getSignature();
			if (method.getSubSignature().equals(sourceSootSignature) && 
					statement.isIdentityStmt()) {
												
//				 IdentityStmt identity = (IdentityStmt) statement;
//				 Value right = identity.getRightOp();
//				
//				 if (right instanceof ParameterRef) {		
//					ParameterRef parameterRef = (ParameterRef) right;
//					if (sourceMethod.getOutputParameters() != null) {
//						for (OutputParameter output : sourceMethod.getOutputParameters()) {
//							int parameterIndex = output.getNumber();
//							if (parameterRef.getIndex() == parameterIndex
//									&& method.getParameterCount() >= parameterIndex) {
//								out.add(identity.getLeftOp());
//							}
//						}
//					}
//					
//				}
				
				if (sourceMethod.getOutputParameters() != null) {
					for (OutputParameter output : sourceMethod.getOutputParameters()) {
						int parameterIndex = output.getNumber();
						if (statement.getRightOp().isParameterLocal(parameterIndex)){
							out.add(statement.getLeftOp());
						}
					}
				}
				return out;

			} else if (statement.containsInvokeExpr()
					&& statement.toString().contains(sourceSootSignature)) {
				// taint the return value
				if (sourceMethod.getReturnValue() != null && statement.isAssign()) {
					out.add(statement.getLeftOp());
				} 
				if (sourceMethod.getOutputParameters() != null) {
					for (OutputParameter output : sourceMethod.getOutputParameters()) {
						int parameterIndex =  output.getNumber();
						if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
							out.add(statement.getInvokeExpr().getArg(parameterIndex));
						}
					}
				}
				// taint this object
				if (sourceMethod.isOutputThis() && statement.getInvokeExpr().isInstanceInvokeExpr()) {
					out.add(statement.getInvokeExpr().getBase());
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

	private Collection<Val> generatedSinkVariables(TaintFlowQuery partialFlow, 
			boomerang.scene.Method method, Statement statement) {
		for (Method sourceMethod : partialFlow.getTo()) {
			String sourceSootSignature = "<" + sourceMethod.getSignature() + ">";
			Collection<Val> out = Sets.newHashSet();

			if (statement.containsInvokeExpr() && statement.toString()
					.contains(sourceSootSignature)) {
				
				// taint the return value
				if (sourceMethod.getInputParameters() != null) {
					for (InputParameter input : sourceMethod.getInputParameters()) {
						int parameterIndex = input.getNumber();
						if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
							out.add(statement.getInvokeExpr().getArg(parameterIndex));
						}
					}
				}
		
				// taint this object
				if (sourceMethod.isInputThis() && statement.getInvokeExpr().isInstanceInvokeExpr()) {
					out.add(statement.getInvokeExpr().getBase());
				}
				
				return out;
			}

		}
		// TODO: re-check the sink structure!!
		return Collections.emptySet();
	}	
}
