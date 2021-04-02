package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.BoomerangOptions;
import boomerang.ForwardQuery;
import boomerang.flowfunction.DefaultForwardFlowFunction;
import boomerang.scene.ControlFlowGraph;
import boomerang.scene.Method;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import wpds.interfaces.State;

import java.util.Collection;
import java.util.Set;

public class MyDefaultForwardFlowFunction extends DefaultForwardFlowFunction {

    public MyDefaultForwardFlowFunction(BoomerangOptions opts) {
        super(opts);
    }

    @Override
    public Set<State> normalFlow(ForwardQuery query, ControlFlowGraph.Edge nextEdge, Val fact) {

        return super.normalFlow(query, nextEdge, fact);
    }

    @Override
    public Set<Val> callFlow(Statement callSite, Val fact, Method callee) {


        Set<Val> res = super.callFlow(callSite, fact, callee);

        if (callee.getSubSignature().contains("injectableQuery")) {
            System.out.println("CALL_FLOW");
            System.out.println(callSite);
            System.out.println(fact);
            System.out.println(callee);

            for (Val val : res)
                System.out.println(val);
        }
        return res;
    }

    @Override
    public Collection<State> callToReturnFlow(ForwardQuery query, ControlFlowGraph.Edge edge, Val fact) {


        Set<State> res = super.normalFlow(query, edge, fact);

        if (edge.getMethod().getSubSignature().contains("injectableQuery")) {
            System.out.println("CALL_TO_RETURN_FLOW");
            System.out.println(edge);
            System.out.println(fact);

            for (State state : res)
                System.out.println(state);
        }
        return res;
    }
}
