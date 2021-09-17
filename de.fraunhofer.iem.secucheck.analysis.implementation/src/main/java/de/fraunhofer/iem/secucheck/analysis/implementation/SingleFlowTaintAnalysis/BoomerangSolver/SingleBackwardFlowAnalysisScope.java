package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.Sets;

import boomerang.BackwardQuery;
import boomerang.Query;
import boomerang.scene.AllocVal;
import boomerang.scene.AnalysisScope;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import boomerang.scene.ControlFlowGraph.Edge;
import boomerang.scene.jimple.SootCallGraph;
import de.fraunhofer.iem.secucheck.analysis.parser.methodsignature.SignatureParser;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlow;

/**
 * AnalysisScope for finding the seeds---ForwardQuery for each source found
 */
public class SingleBackwardFlowAnalysisScope extends AnalysisScope {

	/**
     * Current single TaintFlow specification
     */
    private final TaintFlow taintFlow;

    /**
     * List of found sources
     */
    private final Set<boomerang.scene.Method> sinkMethods = new HashSet<>();
	
    public SingleBackwardFlowAnalysisScope(TaintFlow taintFlow, SootCallGraph sootCallGraph) {
        super(sootCallGraph);
        this.taintFlow = taintFlow;
    }

    
	@Override
	protected Collection<? extends Query> generate(Edge cfgEdge) {
		Set<Query> out = Sets.newHashSet();

        // Take the start statement from the edge
        Statement statement = cfgEdge.getStart();
      
        // check and generate for sink variable
        Collection<Val> sinkVariables = generateSinkVariables(this.taintFlow, statement);

        // For each sink variable found create a BackwardQuery
        sinkVariables.forEach(v -> out.add(BackwardQuery.make(cfgEdge, v)));

        // Find sink methods. This case is, if the entry method itself is the sink
        for (Method flowMethod : this.taintFlow.getTo()) {
        	
        	if(SignatureParser.matches(statement.getMethod(), flowMethod.getSignature())) { // If the entry method is sink then create a BackwardQuery

                // Check for InFlow Parameter, If any then create query for respective parameter
                if (flowMethod.getInputParameters() != null) {
                    for (InputParameter input : flowMethod.getInputParameters()) {
                        int parameterIndex = input.getParamID();
                        if (statement.getMethod().getParameterLocals().size() >= parameterIndex) {
                            String param = statement.getMethod().getParameterLocals().get(parameterIndex).toString().replaceAll("\\(.*\\)$", "").trim();

                            if (statement.toString().contains("@parameter") && statement.toString().contains(param)) {
                                if (!sinkMethods.contains(statement.getMethod())) {
                                    out.add(BackwardQuery.make(cfgEdge,
                                            new AllocVal(
                                                    statement.getMethod().getParameterLocals().get(parameterIndex),
                                                    statement,
                                                    statement.getMethod().getParameterLocals().get(parameterIndex))));

                                    sinkMethods.add(statement.getMethod());
                                }
                            }
                        }
                    }
                }

                // ToDo: check is it necessary to check for InFlow this-object
            }
        }

        return out;
	}
	
	
	/**
     * It generates the sink variable
     *
     * @param taintFlow Current single TaintFlow
     * @param statement Current statement
     * @return List of variable based on the specification
     */
    private Collection<Val> generateSinkVariables(TaintFlow taintFlow, Statement statement) {
        Collection<Val> out = Sets.newHashSet();

        for (Method sinkMethod : taintFlow.getTo()) { // Iterate through the sinks in specification

            if (statement.containsInvokeExpr()) {
            	// If sink found, then check for InFlows
            	if(SignatureParser.matches(statement.getInvokeExpr().getMethod().getSignature(), sinkMethod.getSignature())) {
                    // Check for InFlow parameter
                    if (sinkMethod.getInputParameters() != null) {
                        for (InputParameter input : sinkMethod.getInputParameters()) {
                            int parameterIndex = input.getParamID();
                            if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                                out.add(statement.getInvokeExpr().getArg(parameterIndex));
                            }
                        }
                    }

                    // Check for InFlow this-object
                    if (sinkMethod.isInputThis() &&
                            statement.getInvokeExpr().isInstanceInvokeExpr()) {
                        out.add(new AllocVal(statement.getInvokeExpr().getBase(), statement, statement.getInvokeExpr().getBase()));
                    }
                }
            }
        }
        
        return out;
    }

}
