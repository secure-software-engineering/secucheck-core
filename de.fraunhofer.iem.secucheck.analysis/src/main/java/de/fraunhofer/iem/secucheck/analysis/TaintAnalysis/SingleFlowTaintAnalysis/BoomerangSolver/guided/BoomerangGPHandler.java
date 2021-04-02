package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.guided.IDemandDrivenGuidedManager;
import boomerang.scene.AllocVal;
import boomerang.scene.ControlFlowGraph;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import boomerang.scene.jimple.JimpleStatement;
import boomerang.scene.jimple.JimpleVal;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;

import java.util.*;

public class BoomerangGPHandler implements IDemandDrivenGuidedManager {
    public static final String S_VALUE_OF = "<java.lang.String: java.lang.String valueOf(java.lang.Object)>";
    public static final String SB_TO_STRING = "<java.lang.StringBuilder: java.lang.String toString()>";
    public static final String SB_APPEND = "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>";
    public static final String SB_INIT = "<java.lang.StringBuilder: void <init>(java.lang.String)>";

    private Collection<Query> processStatement(Statement statement, Val dataFlowVal, ControlFlowGraph.Edge dataFlowEdge) {
        ArrayList<Query> out = new ArrayList<Query>();

        // JimpleStatements
        if (statement instanceof JimpleStatement) {
            JimpleStatement jimpleStatement = (JimpleStatement) statement;

            // JInvokeStmt
            if (jimpleStatement.getDelegate() instanceof JInvokeStmt) {
                JInvokeStmt jInvokeStmt = (JInvokeStmt) jimpleStatement.getDelegate();

                // This condition is for StringBuilder <init>. If first arg or base is tainted, then taint the base.
                if (statement.getInvokeExpr().getMethod().getSignature().equals(SB_INIT)) {
 /*                   if (dataFlowVal.toString().equals(statement.getInvokeExpr().getBase().toString())) {
                        out.add(
                                new ForwardQuery(
                                        dataFlowEdge,
                                        new AllocVal(
                                                statement.getInvokeExpr().getBase(),
                                                statement,
                                                statement.getInvokeExpr().getBase()
                                        )
                                )
                        );
                    }
*/
                    if (dataFlowVal.toString().equals(statement.getInvokeExpr().getArg(0).toString())) {
                        out.add(
                                new ForwardQuery(
                                        dataFlowEdge,
                                        new AllocVal(
                                                statement.getInvokeExpr().getBase(),
                                                statement,
                                                statement.getInvokeExpr().getBase()
                                        )
                                )
                        );
                    }
                } // End of SB_INIT
            } // End of JInvokeStmt

            // JAssignStmt
            if (jimpleStatement.getDelegate() instanceof JAssignStmt) {
                JAssignStmt jAssignStmt = (JAssignStmt) jimpleStatement.getDelegate();

                // This condition is for String valueOf. If first arg is tainted, then taint the base.
                if (statement.getInvokeExpr().getMethod().getSignature().equals(S_VALUE_OF)) {
                    if (statement.getInvokeExpr().getArg(0).toString().equals(dataFlowVal.toString())) {
                        out.add(
                                new ForwardQuery(
                                        dataFlowEdge,
                                        new AllocVal(
                                                new JimpleVal(jAssignStmt.getLeftOp(), statement.getMethod()),
                                                statement,
                                                new JimpleVal(jAssignStmt.getLeftOp(), statement.getMethod())
                                        )
                                )
                        );
                    }
                } // End of S_VALUE_OF

                // This condition is for StringBuilder toString. If first arg is tainted, then taint the base.
                if (statement.getInvokeExpr().getMethod().getSignature().equals(SB_TO_STRING)) {
                    if (statement.getInvokeExpr().getBase().toString().equals(dataFlowVal.toString())) {
                        out.add(
                                new ForwardQuery(
                                        dataFlowEdge,
                                        new AllocVal(
                                                new JimpleVal(jAssignStmt.getLeftOp(), statement.getMethod()),
                                                statement,
                                                new JimpleVal(jAssignStmt.getLeftOp(), statement.getMethod())
                                        )
                                )
                        );
                    }
                } // End of SB_TO_STRING

                // This condition is for StringBuilder append. If first arg is tainted, then taint the base.
                if (statement.getInvokeExpr().getMethod().getSignature().equals(SB_APPEND)) {
                    if (statement.getInvokeExpr().getBase().toString().equals(dataFlowVal.toString())) {
                        out.add(
                                new ForwardQuery(
                                        dataFlowEdge,
                                        new AllocVal(
                                                new JimpleVal(jAssignStmt.getLeftOp(), statement.getMethod()),
                                                statement,
                                                new JimpleVal(jAssignStmt.getLeftOp(), statement.getMethod())
                                        )
                                )
                        );
                    }

                    if (statement.getInvokeExpr().getArg(0).toString().equals(dataFlowVal.toString())) {
                        out.add(
                                new ForwardQuery(
                                        dataFlowEdge,
                                        new AllocVal(
                                                new JimpleVal(jAssignStmt.getLeftOp(), statement.getMethod()),
                                                statement,
                                                new JimpleVal(jAssignStmt.getLeftOp(), statement.getMethod())
                                        )
                                )
                        );
                    }
                } // End of SB_APPEND
            } // End of JAssignStmt
        } // End of JimpleStatements

        return out;
    }


    @Override
    public Collection<Query> onForwardFlow(ForwardQuery query, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        Statement stmt = dataFlowEdge.getStart();
        ArrayList<Query> out = new ArrayList<Query>();

        //   System.out.println("Check = " + stmt + "\n" + stmt.getClass().getCanonicalName());
        if (stmt.containsInvokeExpr()) {
            if (stmt.getInvokeExpr().getMethod().getSignature().contains("executeQuery")) {
                System.out.println("\n\n\n\n\n\n\nHalf Hooorrrrrayyyyy\n\n\n\n\n\n\n\n");
                if (dataFlowVal.toString().equals(stmt.getInvokeExpr().getArg(0).toString())) {
                    System.out.println("\n\n\n\n\n\n\n\nHooorrrrayyyyy found taintflow!!!\n\n\n\n\n\n\n\n");

                }
            }

            out.addAll(processStatement(stmt, dataFlowVal, dataFlowEdge));

            if (stmt.getInvokeExpr().getMethod().getSignature().contains("concat"))
                System.out.println("ConcatCritical = " + stmt.getInvokeExpr().getMethod().getSignature());
        }

        //     System.out.println("Size = " + arrayList.size() + " Query " + query);
        return out;
    }

    @Override
    public Collection<Query> onBackwardFlow(BackwardQuery query, ControlFlowGraph.Edge dataFlowEdge, Val
            dataFlowVal) {
        System.out.println("Error = ");
        return Collections.emptyList();
    }
}