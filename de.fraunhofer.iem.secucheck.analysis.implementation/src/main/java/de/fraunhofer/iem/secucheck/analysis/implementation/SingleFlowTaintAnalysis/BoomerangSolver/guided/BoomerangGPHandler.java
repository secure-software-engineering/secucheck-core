package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.guided.IDemandDrivenGuidedManager;
import boomerang.scene.AllocVal;
import boomerang.scene.ControlFlowGraph;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import de.fraunhofer.iem.secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.query.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * This is the Secucheck DemandDriven Manager for Boomerang
 *
 * @author Ranjith Krishnamurthy
 */
public class BoomerangGPHandler implements IDemandDrivenGuidedManager {
    private final ArrayList<BackwardQuery> foundSinks = new ArrayList<>();
    private final TaintFlowImpl singleFlow;
    private final SecucheckAnalysisConfiguration secucheckAnalysisConfiguration;

    public BoomerangGPHandler(TaintFlowImpl singleFlow, SecucheckAnalysisConfiguration secucheckAnalysisConfiguration) {
        this.singleFlow = singleFlow;
        this.secucheckAnalysisConfiguration = secucheckAnalysisConfiguration;
    }

    public ArrayList<BackwardQuery> getFoundSinks() {
        return foundSinks;
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
                        int parameterIndex = input.getParamID();
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

    private Collection<Query> getOutForPropogator(Method requiredPropogatorMethod, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        List<Query> queryList = new ArrayList<>();

        if (requiredPropogatorMethod.getOutputParameters() != null) {
            for (OutputParameter outputParameter : requiredPropogatorMethod.getOutputParameters()) {
                int parameterIndex = outputParameter.getParamID();
                if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
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

    private Collection<Query> isPropogator(List<MethodImpl> propogators, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        List<Query> queryList = new ArrayList<>();

        for (Method requiredPropogatorMethod : propogators) {

            String requiredPropogatorSootSignature = Utility.wrapInAngularBrackets(requiredPropogatorMethod.getSignature());

            if (statement.containsInvokeExpr() &&
                    Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(),
                            requiredPropogatorSootSignature)) {

                // Taint the return value.
                if (requiredPropogatorMethod.getInputParameters() != null) {
                    for (InputParameter input : requiredPropogatorMethod.getInputParameters()) {
                        int parameterIndex = input.getParamID();
                        if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                            if (statement.getInvokeExpr().getArg(parameterIndex).toString().equals(dataFlowVal.toString())) {
                                queryList.addAll(getOutForPropogator(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));
                                return queryList;
                            }
                        }
                    }
                }

                // Taint this object.
                if (requiredPropogatorMethod.isInputThis() &&
                        statement.getInvokeExpr().isInstanceInvokeExpr()) {
                    if (statement.getInvokeExpr().getBase().toString().equals(dataFlowVal.toString())) {
                        queryList.addAll(getOutForPropogator(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));
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

            out.addAll(isPropogator(singleFlow.getThrough(), stmt, dataFlowEdge, dataFlowVal));

            if (out.size() > 0)
                return out;

            out.addAll(isPropogator(secucheckAnalysisConfiguration.getAnalysisGeneralPropagators(), stmt, dataFlowEdge, dataFlowVal));
        }

        return out;
    }

    @Override
    public Collection<Query> onBackwardFlow(BackwardQuery query, ControlFlowGraph.Edge dataFlowEdge, Val
            dataFlowVal) {
        System.out.println("Error = ");
        return Collections.emptyList();
    }
}
