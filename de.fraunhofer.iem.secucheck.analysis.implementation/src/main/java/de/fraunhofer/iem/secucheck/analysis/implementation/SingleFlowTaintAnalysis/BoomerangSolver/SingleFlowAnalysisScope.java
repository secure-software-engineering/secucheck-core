package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver;

import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.scene.AllocVal;
import boomerang.scene.AnalysisScope;
import boomerang.scene.ControlFlowGraph.Edge;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import boomerang.scene.jimple.SootCallGraph;
import com.google.common.collect.Sets;

import de.fraunhofer.iem.secucheck.analysis.parser.methodsignature.SignatureParser;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlow;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * AnalysisScope for finding the seeds---ForwardQuery for each source found
 */
public class SingleFlowAnalysisScope extends AnalysisScope {
    /**
     * Current single TaintFlow specification
     */
    private final TaintFlow taintFlow;

    /**
     * List of found sources
     */
    private final Set<boomerang.scene.Method> sourceMethods = new HashSet<>();

    public SingleFlowAnalysisScope(TaintFlow taintFlow, SootCallGraph sootCallGraph) {
        super(sootCallGraph);
        this.taintFlow = taintFlow;
    }

    @Override
    protected Collection<? extends Query> generate(Edge cfgEdge) {
        Set<Query> out = Sets.newHashSet();

        // Take the start statement from the edge
        Statement statement = cfgEdge.getStart();

        // check and generate for source variable
        Collection<Val> sourceVariables = generateSourceVariables(this.taintFlow, statement);

        // For each source variable found create a ForwardQuery
        sourceVariables.forEach(v -> out.add(new ForwardQuery(cfgEdge, v)));

        // Find source methods. This case is, if the entry method itself is the source
        for (Method flowMethod : this.taintFlow.getFrom()) {
        	
        	if(SignatureParser.matches(statement.getMethod(), flowMethod.getSignature())) { // If the entry method is source then create a ForwardQuery

                // Check for OutFlow Parameter, If any then create query for respective parameter
                if (flowMethod.getOutputParameters() != null) {
                    for (OutputParameter output : flowMethod.getOutputParameters()) {
                        int parameterIndex = output.getParamID();
                        if (statement.getMethod().getParameterLocals().size() >= parameterIndex) {
                            String param = statement.getMethod().getParameterLocals().get(parameterIndex).toString().replaceAll("\\(.*\\)$", "").trim();

                            if (statement.toString().contains("@parameter") && statement.toString().contains(param)) {
                                if (!sourceMethods.contains(statement.getMethod())) {
                                    out.add(new ForwardQuery(cfgEdge,
                                            new AllocVal(
                                                    statement.getMethod().getParameterLocals().get(parameterIndex),
                                                    statement,
                                                    statement.getMethod().getParameterLocals().get(parameterIndex))));

                                    sourceMethods.add(statement.getMethod());
                                }
                            }
                        }
                    }
                }

                // Todo: check is it necessary to check for OutFlow this-object
            }
        }

        return out;
    }

    /**
     * It generated the source variable
     *
     * @param taintFlow Current single TaintFlow
     * @param statement Current statement
     * @return List of variable based on the specification
     */
    private Collection<Val> generateSourceVariables(TaintFlow taintFlow, Statement statement) {
        Collection<Val> out = Sets.newHashSet();

        for (Method sourceMethod : taintFlow.getFrom()) { // Iterate through the source in specification

            if (statement.containsInvokeExpr()) {
            	// If source found, then check for OutFlows
            	if(SignatureParser.matches(statement.getInvokeExpr().getMethod().getSignature(), sourceMethod.getSignature())) {
                    // Check for OutFlow return value
                    if (sourceMethod.getReturnValue() != null && statement.isAssign()) {
                        out.add(new AllocVal(statement.getLeftOp(), statement, statement.getLeftOp()));
                    }

                    // Check for OutFlow parameter
                    if (sourceMethod.getOutputParameters() != null) {
                        for (OutputParameter output : sourceMethod.getOutputParameters()) {
                            int parameterIndex = output.getParamID();
                            if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                                out.add(statement.getInvokeExpr().getArg(parameterIndex));
                            }
                        }
                    }

                    // Check for OutFlow this-object
                    if (sourceMethod.isOutputThis() &&
                            statement.getInvokeExpr().isInstanceInvokeExpr()) {
                        out.add(new AllocVal(statement.getInvokeExpr().getBase(), statement, statement.getInvokeExpr().getBase()));
                    }
                }
            }
        }
        return out;
    }
}
