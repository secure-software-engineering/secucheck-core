package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.BoomerangOptions;
import boomerang.ForwardQuery;
import boomerang.flowfunction.DefaultForwardFlowFunction;
import boomerang.scene.ControlFlowGraph;
import boomerang.scene.Method;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import wpds.interfaces.State;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

public class MyDefaultForwardFlowFunction extends DefaultForwardFlowFunction {
    private TaintFlowQueryImpl singleFlow;

    public MyDefaultForwardFlowFunction(BoomerangOptions opts, TaintFlowQueryImpl singleFlow) {
        super(opts);
        this.singleFlow = singleFlow;
    }

    @Override
    public Set<State> normalFlow(ForwardQuery query, ControlFlowGraph.Edge nextEdge, Val fact) {

        return super.normalFlow(query, nextEdge, fact);
    }

    @Override
    public Set<Val> callFlow(Statement callSite, Val fact, Method callee) {
   /*     if (isSanitizer(callSite, fact, callee)){
            System.out.println("Returning empty");
            return Collections.emptySet();
        }
*/
        Set<Val> res = super.callFlow(callSite, fact, callee);
/*
        System.out.println("Returning non empty");
        for (Val val : res) {
            System.out.println("--> " + val);
        }
*/
        return res;
    }

    @Override
    public Collection<State> callToReturnFlow(ForwardQuery query, ControlFlowGraph.Edge edge, Val fact) {

        if (edge.getStart().containsInvokeExpr()) {
            if (isSanitizer(edge.getStart(), fact)) {
                return Collections.emptyList();
            }
        }

        return super.normalFlow(query, edge, fact);
    }

    private boolean isSanitizer(Statement callSite, Val fact) {
        for (MethodImpl sanitizer : singleFlow.getNotThrough()) {
            String sanitizerSootSignature = Utility.wrapInAngularBrackets(sanitizer.getSignature());

            if (Utility.toStringEquals(callSite.getInvokeExpr().getMethod().getSignature(), sanitizerSootSignature)) {
                // UnTaint the OutDeclaration.
                if (sanitizer.getInputParameters() != null) {      // Check for the iputparameters for tainted values
                    for (InputParameter input : sanitizer.getInputParameters()) {   // for each input parameters
                        int parameterIndex = input.getNumber();
                        if (callSite.getInvokeExpr().getArgs().size() >= parameterIndex) {
                            if (callSite.getInvokeExpr().getArg(parameterIndex).toString().equals(fact.toString())) {   // If the parameter is tainted, then untaint the output declaration

                                if (sanitizer.getOutputParameters() != null) {
                                    for (OutputParameter output : sanitizer.getOutputParameters()) {
                                        int outputParameterIndex = output.getNumber();

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
