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
    /**
     * List of found sinks. Whenever SecucheckDemandDrivenManager finds a sink with a taintflow then it creates a
     * BackwardQuery and adds it to this list.
     */
    private final ArrayList<BackwardQuery> foundSinks = new ArrayList<>();

    /**
     * Current single TaintFlow specification, that the current analysis running for.
     */
    private final TaintFlowImpl singleFlow;

    /**
     * SecuchcekAnalysisConfiguration given by the client. This is used to get the GeneralPropagators for now.
     */
    private final SecucheckAnalysisConfiguration secucheckAnalysisConfiguration;

    /**
     * Constructor
     *
     * @param singleFlow                     Single TaintFlow specification
     * @param secucheckAnalysisConfiguration SecuchcekAnalysisConfiguration given by the client
     */
    public BoomerangGPHandler(TaintFlowImpl singleFlow, SecucheckAnalysisConfiguration secucheckAnalysisConfiguration) {
        this.singleFlow = singleFlow;
        this.secucheckAnalysisConfiguration = secucheckAnalysisConfiguration;
    }

    /**
     * Getter for the list of found sinks
     *
     * @return List of found sinks
     */
    public ArrayList<BackwardQuery> getFoundSinks() {
        return foundSinks;
    }

    /**
     * This method checks whether the current statement contains the sink method call. If yes, it return true.
     *
     * @param statement    Current Statement
     * @param dataFlowEdge Dataflow edge
     * @param dataFlowVal  Fact: dataFlowVal
     * @return True is there is a sink method call and TaintFlow exist.
     */
    private boolean isSink(Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        boolean isSinkFound = false;

        for (Method sinkMethod : singleFlow.getTo()) {
            String sinkSootSignature = Utility.wrapInAngularBrackets(sinkMethod.getSignature());

            if (statement.containsInvokeExpr() &&
                    Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(),
                            sinkSootSignature)) {   // If there is a sink method call, then check is there a taintflow present

                //For sinks there is always a InFlow, there is no OutFlow.

                // Check for the InFlow parameters
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

                // Check for InFlow this-object
                if (sinkMethod.isInputThis() &&
                        statement.getInvokeExpr().isInstanceInvokeExpr()) {
                    if (statement.getInvokeExpr().getBase().toString().equals(dataFlowVal.toString())) {
                        foundSinks.add(BackwardQuery.make(dataFlowEdge, statement.getInvokeExpr().getBase()));
                        isSinkFound = true;
                    }
                }
            }

        }

        return isSinkFound;
    }

    /**
     * This method returns the Collections of Query based on the OutFlow for the given propagator.
     *
     * @param propogatorMethod propagator method that is found
     * @param statement        Current statement
     * @param dataFlowEdge     Dataflow edge
     * @param dataFlowVal      Fact
     * @return List of Query based on the OutFlow of the required propagator
     */
    private Collection<Query> getOutForPropogator(Method propogatorMethod, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        List<Query> queryList = new ArrayList<>();

        // Check for the OutFlow
        if (propogatorMethod.getOutputParameters() != null) {
            for (OutputParameter outputParameter : propogatorMethod.getOutputParameters()) {
                int parameterIndex = outputParameter.getParamID();
                if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) { // If OutFlow present, then create a query
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

        // Check for OutFlow this-object
        if (propogatorMethod.isOutputThis() &&
                statement.getInvokeExpr().isInstanceInvokeExpr()) { // If present, then create a query for this-object
            queryList.add(new ForwardQuery(dataFlowEdge,
                    new AllocVal(
                            statement.getInvokeExpr().getBase(),
                            statement,
                            statement.getInvokeExpr().getBase()
                    )
            ));
        }

        // Check for the OutFlow return value
        if (propogatorMethod.getReturnValue() != null &&
                statement.isAssign()) { // If yes, create a query for left-op
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

    /**
     * This method check whether the current statement contains a propagator.
     *
     * @param propogators  List of propagators from the specification
     * @param statement    current statement
     * @param dataFlowEdge Dataflow edge
     * @param dataFlowVal  Fact
     * @return Returns the List of query if there is a taintflow present in the propagators.
     */
    private Collection<Query> isPropogator(List<MethodImpl> propogators, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        List<Query> queryList = new ArrayList<>();

        for (Method requiredPropogatorMethod : propogators) {

            String requiredPropogatorSootSignature = Utility.wrapInAngularBrackets(requiredPropogatorMethod.getSignature());

            if (statement.containsInvokeExpr() &&
                    Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(),
                            requiredPropogatorSootSignature)) { // If there is a propagator, then check is there a tainted variable going into the method

                // Check for InFlow parameter
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

                // Check for InFlow this-object
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

    /**
     * For forward Query. Out implementation uses only ForwardQuery.
     *
     * @param query        Forward query
     * @param dataFlowEdge Dataflow edge
     * @param dataFlowVal  Fact
     * @return List of queries based on the current dataFlowVal---fact
     */
    @Override
    public Collection<Query> onForwardFlow(ForwardQuery query, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        Statement stmt = dataFlowEdge.getStart();
        ArrayList<Query> out = new ArrayList<Query>();

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

    /**
     * Our Implementation does not use BackwardQuery. Therefore no implementation for onBackwardFlow
     *
     * @param query        BackwardQuery
     * @param dataFlowEdge Dataflow edge
     * @param dataFlowVal  fact
     * @return Always empty list for our implementation.
     */
    @Override
    public Collection<Query> onBackwardFlow(BackwardQuery query, ControlFlowGraph.Edge dataFlowEdge, Val
            dataFlowVal) {
        return Collections.emptyList();
    }
}
