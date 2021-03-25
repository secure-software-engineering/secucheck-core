package de.fraunhofer.iem.secucheck.analysis.internal;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.guided.IDemandDrivenGuidedManager;
import boomerang.scene.ControlFlowGraph;
import boomerang.scene.Statement;
import boomerang.scene.Val;

import java.util.Collection;

public class BoomerangGPHandler implements IDemandDrivenGuidedManager {
    @Override
    public Collection<Query> onForwardFlow(ForwardQuery query, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        Statement stmt = dataFlowEdge.getStart();

        if (stmt.containsInvokeExpr()) {
            if (stmt.getInvokeExpr().getMethod().getSignature().contains("append"))
                System.out.println("Critical = " + stmt.getInvokeExpr().getMethod().getSignature());

            if (stmt.getInvokeExpr().getMethod().getSignature().contains("concat"))
                System.out.println("Critical = " + stmt.getInvokeExpr().getMethod().getSignature());
        }
        return null;
    }

    @Override
    public Collection<Query> onBackwardFlow(BackwardQuery query, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        System.out.println("Error = ");
        return null;
    }
}
