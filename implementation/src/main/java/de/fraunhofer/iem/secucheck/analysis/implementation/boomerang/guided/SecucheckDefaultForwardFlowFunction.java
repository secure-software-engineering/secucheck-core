package de.fraunhofer.iem.secucheck.analysis.implementation.boomerang.guided;

import boomerang.BoomerangOptions;
import boomerang.ForwardQuery;
import boomerang.flowfunction.DefaultForwardFlowFunction;
import boomerang.scene.ControlFlowGraph;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import de.fraunhofer.iem.secucheck.analysis.implementation.boomerang.Utility;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;
import wpds.interfaces.State;

import java.util.Collection;
import java.util.Collections;

/**
 * Secucheck default forward flow function for the Boomerang DemandDriven analysis
 */
public class SecucheckDefaultForwardFlowFunction extends DefaultForwardFlowFunction {
    // Current single TaintFlow specification
    private final TaintFlowImpl singleFlow;

    public SecucheckDefaultForwardFlowFunction(BoomerangOptions opts, TaintFlowImpl singleFlow) {
        super(opts);
        this.singleFlow = singleFlow;
    }

    /**
     * In callToReturnFlow function, we check is there a sanitizer method call. If there is a sanitizer method call,
     * Then based on the specfication, we kill the fact.
     *
     * @param query Forward query
     * @param edge  dataflow edge
     * @param fact  fact
     * @return List of state based on the specification of sanitizers. If no sanitizer then call the super.callToReturnFlow
     */
    @Override
    public Collection<State> callToReturnFlow(ForwardQuery query, ControlFlowGraph.Edge edge, Val fact) {
        if (edge.getStart().containsInvokeExpr()) {
            if (isSanitizer(edge.getStart(), fact)) {   // If sanitizer and current fact is need to be killed by the specs then kill the fact
                return Collections.emptyList();
            }
        }

        return super.normalFlow(query, edge, fact);
    }

    /**
     * Checks whether the current statement contain the sanitizer method call.
     * <p>
     * Criteria for isSanitizer to return true is:
     * if there is a sanitizer method call and there is a tainted variable (fact) in the InFlow. Then check for the OutFlow in specs.
     * If fact is equal to the OutFlow in the specs then returns true ( in this case it kill the fact) otherwise it return false (will not kill fact).
     * <p>
     * Note: If there is sanitizer and OutFlow is return value then it return true because there is nothing to kill the left op.
     *
     * @param callSite statement that contains the callsite
     * @param fact     fact
     * @return True if it satisfies the criteria
     */
    private boolean isSanitizer(Statement callSite, Val fact) {
        for (MethodImpl sanitizer : singleFlow.getNotThrough()) {
            String sanitizerSootSignature = Utility.wrapInAngularBrackets(sanitizer.getSignature());

            if (Utility.toStringEquals(callSite.getInvokeExpr().getMethod().getSignature(), sanitizerSootSignature)) {
                // UnTaint the OutDeclaration.
                if (sanitizer.getInputParameters() != null) {      // Check for the iputparameters for tainted values
                    for (InputParameter input : sanitizer.getInputParameters()) {   // for each input parameters
                        int parameterIndex = input.getParamID();
                        if (callSite.getInvokeExpr().getArgs().size() >= parameterIndex) {
                            if (callSite.getInvokeExpr().getArg(parameterIndex).toString().equals(fact.toString())) {   // If the parameter is tainted, then untaint the output declaration

                                if (sanitizer.getOutputParameters() != null) {
                                    for (OutputParameter output : sanitizer.getOutputParameters()) {
                                        int outputParameterIndex = output.getParamID();

                                        if (parameterIndex == outputParameterIndex) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // UnTaint this object.
                if (sanitizer.isInputThis() &&
                        callSite.getInvokeExpr().isInstanceInvokeExpr()) {
                    if (callSite.getInvokeExpr().getBase().toString().equals(fact.toString()))
                        if (sanitizer.isOutputThis()) {
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
