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
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

public class BoomerangGPHandler implements IDemandDrivenGuidedManager {
    private final ArrayList<BackwardQuery> foundSinks = new ArrayList<>();
    private TaintFlowQueryImpl singleFlow;

    public static final String S_VALUE_OF = "<java.lang.String: java.lang.String valueOf(java.lang.Object)>";
    public static final String SB_TO_STRING = "<java.lang.StringBuilder: java.lang.String toString()>";
    public static final String SB_APPEND = "<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>";
    public static final String SB_INIT = "<java.lang.StringBuilder: void <init>(java.lang.String)>";

    public BoomerangGPHandler(TaintFlowQueryImpl singleFlow) {
        this.singleFlow = singleFlow;
    }

    public ArrayList<BackwardQuery> getFoundSinks() {
        return foundSinks;
    }

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

    private boolean isSink(Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        boolean isSinkFound = false;

        for (Method sinkMethod : singleFlow.getTo()) {

            //System.out.print("Sink ===--->>> " + sinkMethod.getSignature() + " ----- ");
            String sinkSootSignature = Utility.wrapInAngularBrackets(sinkMethod.getSignature());

            if (statement.containsInvokeExpr() &&
                    Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(),
                            sinkSootSignature)) {

                // Taint the return value.
                if (sinkMethod.getInputParameters() != null) {
                    for (InputParameter input : sinkMethod.getInputParameters()) {
                        int parameterIndex = input.getNumber();
                        if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                            if (statement.getInvokeExpr().getArg(parameterIndex).toString().equals(dataFlowVal.toString())) {
                                foundSinks.add(BackwardQuery.make(dataFlowEdge, statement.getInvokeExpr().getArg(parameterIndex)));
                                isSinkFound = true;
                            }
                        }
                    }
                }

                // Taint this object.
                if (sinkMethod.isInputThis() &&
                        statement.getInvokeExpr().isInstanceInvokeExpr()) {
                    if (statement.getInvokeExpr().getBase().toString().equals(dataFlowVal.toString())) {
                        foundSinks.add(BackwardQuery.make(dataFlowEdge, statement.getInvokeExpr().getBase()));
                        isSinkFound = true;
                    }
                }
            }

        }

        // TODO: re-check the sink structure!!
        return isSinkFound;
    }

    private Collection<Query> getOutForRequiredPropogator(Method requiredPropogatorMethod, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        List<Query> queryList = new ArrayList<>();

        if (requiredPropogatorMethod.getOutputParameters() != null) {
            for (OutputParameter outputParameter : requiredPropogatorMethod.getOutputParameters()) {
                int parameterIndex = outputParameter.getNumber();
                if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                    System.out.println("Ok Entered here");
                    queryList.add(new ForwardQuery(dataFlowEdge,
                            new AllocVal(
                                    statement.getInvokeExpr().getArg(parameterIndex),
                                    statement,
                                    statement.getInvokeExpr().getArg(parameterIndex)
                            )
                    ));
                }
            }
        }

        if (requiredPropogatorMethod.isOutputThis() &&
                statement.getInvokeExpr().isInstanceInvokeExpr()) {
            queryList.add(new ForwardQuery(dataFlowEdge,
                    new AllocVal(
                            statement.getInvokeExpr().getBase(),
                            statement,
                            statement.getInvokeExpr().getBase()
                    )
            ));
        }

        if (requiredPropogatorMethod.getReturnValue() != null &&
                statement.isAssign()) {
            queryList.add(new ForwardQuery(dataFlowEdge,
                    new AllocVal(
                            statement.getLeftOp(),
                            statement,
                            statement.getLeftOp()
                    )
            ));
        }

        return queryList;
    }

    private Collection<Query> isRequiredPropogator(Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        List<Query> queryList = new ArrayList<>();

        for (Method requiredPropogatorMethod : singleFlow.getThrough()) {

            String requiredPropogatorSootSignature = Utility.wrapInAngularBrackets(requiredPropogatorMethod.getSignature());

            if (statement.containsInvokeExpr() &&
                    Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(),
                            requiredPropogatorSootSignature)) {

                // Taint the return value.
                if (requiredPropogatorMethod.getInputParameters() != null) {
                    for (InputParameter input : requiredPropogatorMethod.getInputParameters()) {
                        int parameterIndex = input.getNumber();
                        if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                            if (statement.getInvokeExpr().getArg(parameterIndex).toString().equals(dataFlowVal.toString())) {
                                queryList.addAll(getOutForRequiredPropogator(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));
                                return queryList;
                            }
                        }
                    }
                }

                // Taint this object.
                if (requiredPropogatorMethod.isInputThis() &&
                        statement.getInvokeExpr().isInstanceInvokeExpr()) {
                    if (statement.getInvokeExpr().getBase().toString().equals(dataFlowVal.toString())) {
                        queryList.addAll(getOutForRequiredPropogator(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));
                        return queryList;
                    }
                }
            }

        }

        return queryList;
    }

    @Override
    public Collection<Query> onForwardFlow(ForwardQuery query, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        Statement stmt = dataFlowEdge.getStart();
        ArrayList<Query> out = new ArrayList<Query>();

        //   System.out.println("Check = " + stmt + "\n" + stmt.getClass().getCanonicalName());
        if (stmt.containsInvokeExpr()) {
            if (isSink(stmt, dataFlowEdge, dataFlowVal)) {
                return Collections.emptyList();
            }

            out.addAll(isRequiredPropogator(stmt, dataFlowEdge, dataFlowVal));

            if (out.size() > 0)
                return out;

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
