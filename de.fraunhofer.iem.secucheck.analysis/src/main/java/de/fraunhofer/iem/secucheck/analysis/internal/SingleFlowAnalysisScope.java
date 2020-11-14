package de.fraunhofer.iem.secucheck.analysis.internal;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.Sets;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.WeightedForwardQuery;
import boomerang.scene.AllocVal;
import boomerang.scene.AnalysisScope;
import boomerang.scene.ControlFlowGraph.Edge;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import boomerang.scene.jimple.SootCallGraph;
import de.fraunhofer.iem.secucheck.analysis.datastructures.SameTypedPair;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQuery;
import wpds.impl.Weight;
import wpds.impl.Weight;

public class SingleFlowAnalysisScope extends AnalysisScope {

	private final TaintFlowQuery taintFlow;
	
	private final Set<boomerang.scene.Method> sourceMethods = new HashSet<>();
	private final Set<boomerang.scene.Method> sinkMethods = new HashSet<>();
	
	public SingleFlowAnalysisScope(TaintFlowQuery taintFlow, SootCallGraph sootCallGraph) {
		super(sootCallGraph);
		this.taintFlow = taintFlow;
	}
	
	@Override
	protected Collection<? extends Query> generate(Edge cfgEdge) {
		Set<Query> out = Sets.newHashSet();
		
		// The target statement for the current edge.
		Statement statement = cfgEdge.getTarget();
		
		Collection<SameTypedPair<Val>> sourceVariables = 
				generateSourceVariables(this.taintFlow, statement);
		
		sourceVariables.forEach(v -> out.add(
				new WeightedForwardQuery<Weight.NoWeight>(cfgEdge, v.getFirst(), Weight.NO_WEIGHT_ONE)));
		
		Collection<Val> sinkVariables = generatedSinkVariables(this.taintFlow, statement);
		
		sinkVariables.forEach(v -> out.add(BackwardQuery.make(cfgEdge, v)));
		
		// Find source methods.	
		for (Method flowMethod : this.taintFlow.getFrom()) {
			if (ToStringEquals(statement.getMethod(), 
					WrapInAngularBrackets(flowMethod.getSignature()))) {
				sourceMethods.add(statement.getMethod());
			}
		}

		// Find target methods.				
		for (Method flowMethod : this.taintFlow.getTo()) {
			if (ToStringEquals(statement.getMethod(), 
					WrapInAngularBrackets(flowMethod.getSignature()))) {
				sinkMethods.add(statement.getMethod());
			}
		}
		
		return out;
	}
	
	private Collection<SameTypedPair<Val>> generateSourceVariables(TaintFlowQuery partialFlow, 
			Statement statement) {
		
		for (Method sourceMethod  : partialFlow.getFrom()) {
			
			String sourceSootSignature = WrapInAngularBrackets(sourceMethod.getSignature());
			Collection<SameTypedPair<Val>> out = Sets.newHashSet();
			
			if (ToStringEquals(statement.getMethod(), sourceSootSignature) && 
					statement.isIdentityStmt()) {
				
				if (sourceMethod.getOutputParameters() != null) {
					for (OutputParameter output : sourceMethod.getOutputParameters()) {
						int parameterIndex = output.getNumber();
						if (statement.getRightOp().isParameterLocal(parameterIndex)){							
							out.add(new SameTypedPair<Val>(statement.getLeftOp(),
									statement.getRightOp()));
						}
					}
				}
				
				return out;

			} else if (statement.containsInvokeExpr()
					&& ToStringEquals(statement.getInvokeExpr().getMethod(),
							sourceSootSignature)) {

				// Taint the return value
				if (sourceMethod.getReturnValue() != null && statement.isAssign()) {
					out.add(new SameTypedPair<Val>(statement.getLeftOp(),
							statement.getRightOp()));
				}
				
				if (sourceMethod.getOutputParameters() != null) {
					for (OutputParameter output : sourceMethod.getOutputParameters()) {
						int parameterIndex =  output.getNumber();
						if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
							out.add(new SameTypedPair<Val>(
									statement.getInvokeExpr().getArg(parameterIndex), 
									statement.getInvokeExpr().getArg(parameterIndex)));
						}
					}
				}
				
				// Taint this object
				if (sourceMethod.isOutputThis() &&
						statement.getInvokeExpr().isInstanceInvokeExpr()) {
					out.add(new SameTypedPair<Val>(statement.getInvokeExpr().getBase(),
							statement.getInvokeExpr().getBase()));
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
			Statement statement) {
		
		for (Method sinkMethod : partialFlow.getTo()) {
			
			String sinkSootSignature = WrapInAngularBrackets(sinkMethod.getSignature());
			Collection<Val> out = Sets.newHashSet();
			
			if (statement.containsInvokeExpr() && 
					ToStringEquals(statement.getInvokeExpr().getMethod(),
							sinkSootSignature)) {
				
				// Taint the return value.
				if (sinkMethod.getInputParameters() != null) {
					for (InputParameter input : sinkMethod.getInputParameters()) {
						int parameterIndex = input.getNumber();
						if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
							out.add(statement.getInvokeExpr().getArg(parameterIndex));
						}
					}
				}
		
				// Taint this object.
				if (sinkMethod.isInputThis() && 
						statement.getInvokeExpr().isInstanceInvokeExpr()) {
					out.add(statement.getInvokeExpr().getBase());
				}
				
				return out;
			}

		}
		
		// TODO: re-check the sink structure!!
		return Collections.emptySet();
	}	

	private static String WrapInAngularBrackets(String value) {
		return "<" + value + ">";
	}
	
	private static boolean ToStringEquals(Object object1, Object object2) {
		return object1.toString().equals(object2.toString());
	}

}
