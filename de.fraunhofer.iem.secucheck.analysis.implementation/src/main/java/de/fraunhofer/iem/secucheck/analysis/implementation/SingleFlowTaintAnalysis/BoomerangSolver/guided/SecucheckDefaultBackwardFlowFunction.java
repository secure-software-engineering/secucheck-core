package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import java.util.Collection;
import java.util.Collections;

import boomerang.BoomerangOptions;
import boomerang.flowfunction.DefaultBackwardFlowFunction;
import boomerang.scene.ControlFlowGraph;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import de.fraunhofer.iem.secucheck.analysis.parser.methodsignature.SignatureParser;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;
import wpds.interfaces.State;

/**
 * SecuCheck default backward flow function for the Boomerang DemandDriven analysis
 */
public class SecucheckDefaultBackwardFlowFunction extends DefaultBackwardFlowFunction {

	// Current single TaintFlow specification
    private final TaintFlowImpl singleFlow;

    public SecucheckDefaultBackwardFlowFunction(BoomerangOptions opts, TaintFlowImpl singleFlow) {
        super(opts);
        this.singleFlow = singleFlow;
    }
    
    /**
     * In callToReturnFlow function, we check is there a sanitizer method call. If there is a sanitizer method call,
     * Then based on the specification, we kill the fact.
     *
     * @param query Forward query
     * @param edge  data flow edge
     * @param fact  fact
     * @return List of state based on the specification of sanitizers. If no sanitizer then call the super.callToReturnFlow
     */
    @Override
    public Collection<State> callToReturnFlow(ControlFlowGraph.Edge edge, Val fact) {
        if (edge.getStart().containsInvokeExpr()) {
            if (isSanitizer(edge.getStart(), fact)) {   // If sanitizer and current fact is need to be killed by the specs then kill the fact
                return Collections.emptyList();
            }
        }

        return super.normalFlow(edge, fact);
    }

    /**
     * Checks whether the current statement contain the sanitizer method call.
     * <p>
     * Criteria for isSanitizer to return true is:
     * if there is a sanitizer method call and there is a tainted variable (fact) in the OutFlow, then check for the InFlow in specs.
     * If fact is equal to the InFlow in the specs then returns true ( in this case it kill the fact) otherwise it return false (will not kill fact).
     * <p>
     * Note: If there is sanitizer and InFlow is return value then it return true because there is nothing to kill the left op.
     *
     * @param callSite statement that contains the call site
     * @param fact     fact
     * @return True if it satisfies the criteria
     */
    private boolean isSanitizer(Statement callSite, Val fact) {
        for (MethodImpl sanitizer : singleFlow.getNotThrough()) {
            
        	if(SignatureParser.matches(callSite.getInvokeExpr().getMethod().getSignature(), sanitizer.getSignature())) {
                // UnTaint the InDeclaration since we are backward.
                if (sanitizer.getOutputParameters() != null) {      // Check for the output parameters for tainted values
                    for (OutputParameter output : sanitizer.getOutputParameters()) {   // for each output parameters
                        int parameterIndex = output.getParamID();
                        if (callSite.getInvokeExpr().getArgs().size() >= parameterIndex) {
                            if (callSite.getInvokeExpr().getArg(parameterIndex).toString().equals(fact.toString())) {   // If the parameter is tainted, then untaint the input declaration

                                if (sanitizer.getInputParameters() != null) {
                                    for (InputParameter input : sanitizer.getInputParameters()) {
                                        int inputParameterIndex = input.getParamID();

                                        if (parameterIndex == inputParameterIndex) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // UnTaint this object.
                if (sanitizer.isOutputThis() &&
                        callSite.getInvokeExpr().isInstanceInvokeExpr()) {
                    if (callSite.getInvokeExpr().getBase().toString().equals(fact.toString()))
                        if (sanitizer.isInputThis()) {
                            return true;
                        }
                }

                // UnTaint this object.
                if (sanitizer.getReturnValue() != null) {
                    return false;
                }
            }
        }
        return false;
    }

}
