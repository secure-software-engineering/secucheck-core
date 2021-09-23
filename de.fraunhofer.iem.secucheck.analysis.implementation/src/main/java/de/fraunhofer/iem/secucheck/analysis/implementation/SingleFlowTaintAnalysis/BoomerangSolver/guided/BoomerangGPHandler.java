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
import de.fraunhofer.iem.secucheck.analysis.datastructures.DifferentTypedPair;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.TaintFlowPathUtility;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.datastructure.BoomerangTaintFlowPath;
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
    private final ArrayList<DifferentTypedPair<BackwardQuery, BoomerangTaintFlowPath>> foundSinks = new ArrayList<>();

    /**
     * Current single TaintFlow specification, that the current analysis running for.
     */
    private final TaintFlowImpl singleFlow;

    /**
     * SecuchcekAnalysisConfiguration given by the client. This is used to get the GeneralPropagators for now.
     */
    private final SecucheckAnalysisConfiguration secucheckAnalysisConfiguration;

    private final BoomerangTaintFlowPath tempPath;

    /**
     * Constructor
     *
     * @param singleFlow                     Single TaintFlow specification
     * @param secucheckAnalysisConfiguration SecuchcekAnalysisConfiguration given by the client
     */
    public BoomerangGPHandler(TaintFlowImpl singleFlow, SecucheckAnalysisConfiguration secucheckAnalysisConfiguration, BoomerangTaintFlowPath initialPath) {
        this.singleFlow = singleFlow;
        this.secucheckAnalysisConfiguration = secucheckAnalysisConfiguration;
        this.tempPath = initialPath;

    }

    /**
     * Getter for the list of found sinks
     *
     * @return List of found sinks
     */
    public ArrayList<DifferentTypedPair<BackwardQuery, BoomerangTaintFlowPath>> getFoundSinks() {
        return foundSinks;
    }

    /**
     * Returns the backward query for the given Method and the statement
     *
     * @param sinkMethod   Sink Method from the specifications
     * @param statement    Current Statement
     * @param dataFlowEdge Dataflow edge
     * @param dataFlowVal  Fact: dataFlowVal
     * @return Backward query for given sink method
     */
    private BackwardQuery getBackWardQueriesBasedOnRules(Method sinkMethod, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        //For sinks there is always a InFlow, there is no OutFlow.

        // Check for the InFlow parameters
        if (sinkMethod.getInputParameters() != null) {
            for (InputParameter input : sinkMethod.getInputParameters()) {
                int parameterIndex = input.getParamID();
                if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                    if (statement.getInvokeExpr().getArg(parameterIndex).toString().equals(dataFlowVal.toString())) {
                        return BackwardQuery.make(dataFlowEdge, statement.getInvokeExpr().getArg(parameterIndex));
                    }
                }
            }
        }

        // Check for InFlow this-object
        if (sinkMethod.isInputThis() &&
                statement.getInvokeExpr().isInstanceInvokeExpr()) {
            if (statement.getInvokeExpr().getBase().toString().equals(dataFlowVal.toString())) {
                return BackwardQuery.make(dataFlowEdge, statement.getInvokeExpr().getBase());
            }
        }

        return null;
    }

    /**
     * This method checks whether the current statement contains the sink method call. If yes, it return true.
     *
     * @param statement    Current Statement
     * @param dataFlowEdge Dataflow edge
     * @param dataFlowVal  Fact: dataFlowVal
     * @return True is there is a sink method call and TaintFlow exist.
     */
    private BackwardQuery isSink(Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        if (statement.containsInvokeExpr()) {
            for (Method sinkMethod : singleFlow.getTo()) {
                String sinkSootSignature = Utility.wrapInAngularBrackets(sinkMethod.getSignature());

                // Normal check
                if (Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(), sinkSootSignature)) {
                    // If there is a sink method call, then check is there a taintflow present

                    return getBackWardQueriesBasedOnRules(sinkMethod, statement, dataFlowEdge, dataFlowVal);
                }

                // Default value constructor check
                if (isDefaultConstructor(sinkSootSignature, statement.getInvokeExpr().getMethod().getSignature())) {
                    return getBackWardQueriesBasedOnRules(sinkMethod, statement, dataFlowEdge, dataFlowVal);
                }

                // Top level Default value function check
                if (isTopLevelDefaultFunction(sinkSootSignature, statement.getInvokeExpr().getMethod().getSignature())) {
                    return getBackWardQueriesBasedOnRules(sinkMethod, statement, dataFlowEdge, dataFlowVal);
                }

                // Class level Default value function check
                Method modifiedSinkMethod = isClassLevelDefaultFunction(sinkMethod, statement.getInvokeExpr().getMethod().getSignature());

                if (modifiedSinkMethod != null) {
                    return getBackWardQueriesBasedOnRules(modifiedSinkMethod, statement, dataFlowEdge, dataFlowVal);
                }

            }
        }

        return null;
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
     * This method checks whether the statement inflow is tainted based on the fluentTQL specification given.
     *
     * @param requiredPropogatorMethod FluentTQL method that contains the specification
     * @param statement                Statement
     * @param dataFlowEdge             Dataflow edge
     * @param dataFlowVal              Fact
     * @return List of Query based on the OutFlow of the required propagator
     */
    private Collection<Query> getQueriesBasedOnTheRules(Method requiredPropogatorMethod, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
        List<Query> queryList = new ArrayList<>();

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

        return queryList;
    }

    /**
     * This method checks whether the method signature is a default value constructor in Kotlin
     *
     * @param originalMethod Original method signature given in the fluentTQL specification
     * @param sootSignature  Soot method signature obtained by the Statement
     * @return Returns true if sootSignature method signature is the default value constructor version of originalMethod
     */
    private static boolean isDefaultConstructor(String originalMethod, String sootSignature) {
        if (!sootSignature.contains("<init>(")) {
            return false;
        }

        if (!originalMethod.contains("<init>(")) {
            return false;
        }

        String[] temp = originalMethod.split("\\)");

        if (temp.length != 2)
            return false;

        String processedOriginalMethod = temp[0] + ",int,kotlin.jvm.internal.DefaultConstructorMarker)>";

        return Utility.toStringEquals(processedOriginalMethod, sootSignature);
    }

    /**
     * This method checks whether the method signature is a top level default value function in Kotlin
     *
     * @param originalMethod Original method signature given in the fluentTQL specification
     * @param sootSignature  Soot method signature obtained by the Statement
     * @return Returns true if sootSignature method signature is the top level default value function version of originalMethod
     */
    private static boolean isTopLevelDefaultFunction(String originalMethod, String sootSignature) {
        String[] temp1 = originalMethod.split("\\(");

        if (temp1.length != 2)
            return false;

        String[] temp2 = temp1[1].split("\\)");

        if (temp2.length != 2)
            return false;

        String processedOriginalMethod = temp1[0] + "$default(" + temp2[0] + ",int,java.lang.Object)>";

        return Utility.toStringEquals(processedOriginalMethod, sootSignature);
    }

    /**
     * This method checks whether the method signature is a class level default value function in Kotlin
     *
     * @param originalMethod Original method signature given in the fluentTQL specification
     * @param sootSignature  Soot method signature obtained by the Statement
     * @return Returns the modified Method if it is class level default value function, if not it returns null
     */
    private static Method isClassLevelDefaultFunction(Method originalMethod, String sootSignature) {
        String[] temp1 = originalMethod.getSignature().split("\\(");

        if (temp1.length != 2)
            return null;

        String[] temp3 = temp1[0].split(":");

        if (temp3.length != 2)
            return null;

        String className = temp3[0].substring(1);

        String[] temp2 = temp1[1].split("\\)");

        if (temp2.length != 2)
            return null;

        String processedOriginalMethod = temp1[0] + "$default(" + className + "," + temp2[0] + ",int,java.lang.Object)>";

        if (Utility.toStringEquals(processedOriginalMethod, sootSignature)) {
            MethodImpl method = new MethodImpl();

            // Signature
            method.setSignature(processedOriginalMethod);

            // Output return value
            method.setReturnValue(originalMethod.getReturnValue());

            List<InputParameter> inputParameters = new ArrayList<>();
            List<OutputParameter> outputParameters = new ArrayList<>();

            // this object
            method.setInputThis(false);
            method.setOutputThis(false);

            if (originalMethod.isInputThis()) {
                InputParameter inputParameter = new InputParameter();
                inputParameter.setParamID(0);

                inputParameters.add(inputParameter);
            }

            if (originalMethod.isOutputThis()) {
                OutputParameter outputParameter = new OutputParameter();
                outputParameter.setParamID(0);

                outputParameters.add(outputParameter);
            }

            // Parameters
            for (InputParameter inputParameter : originalMethod.getInputParameters()) {
                InputParameter temp = new InputParameter();
                temp.setParamID(inputParameter.getParamID() + 1);
                inputParameters.add(temp);
            }

            for (OutputParameter outputParameter : originalMethod.getOutputParameters()) {
                OutputParameter temp = new OutputParameter();
                temp.setParamID(outputParameter.getParamID() + 1);
                outputParameters.add(temp);
            }

            method.setOutputParameters(outputParameters);
            method.setInputParameters(inputParameters);
            method.setName(originalMethod.getName());

            return method;
        }

        return null;
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

        if (statement.containsInvokeExpr()) {
            for (Method requiredPropogatorMethod : propogators) {
                String requiredPropogatorSootSignature = Utility.wrapInAngularBrackets(requiredPropogatorMethod.getSignature());

                // Normal check
                if (Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(), requiredPropogatorSootSignature)) {
                    // If there is a propagator, then check is there a tainted variable going into the method

                    queryList.addAll(getQueriesBasedOnTheRules(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));

                    return queryList;
                }

                // Check for Java 11 concat methods
                if (statement.getInvokeExpr().getMethod().getSubSignature().equals(requiredPropogatorMethod.getSignature())) { // For Java 11
                    // Todo: Check and model it correctly to handle the Java 11 dynamic calls.
                    queryList.addAll(getQueriesBasedOnTheRules(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));

                    return queryList;
                }

                // Default value constructor check
                if (isDefaultConstructor(requiredPropogatorSootSignature, statement.getInvokeExpr().getMethod().getSignature())) {
                    queryList.addAll(getQueriesBasedOnTheRules(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));

                    return queryList;
                }

                // Top level Default value function check
                if (isTopLevelDefaultFunction(requiredPropogatorSootSignature, statement.getInvokeExpr().getMethod().getSignature())) {
                    queryList.addAll(getQueriesBasedOnTheRules(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));

                    return queryList;
                }

                // Class level Default value function check
                Method modifiedRequiredPropogatorMethod = isClassLevelDefaultFunction(requiredPropogatorMethod, statement.getInvokeExpr().getMethod().getSignature());

                if (modifiedRequiredPropogatorMethod != null) {
                    queryList.addAll(getQueriesBasedOnTheRules(modifiedRequiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));

                    return queryList;
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

        //TODO: Currently if the dataflow value is not matching with the previously created Forward Query val then
        // SecuCheck does nothing. Test this extensively or confirm this is the correct step
        //if (!query.asNode().fact().toString().equals(dataFlowVal.toString())) {
        //    return Collections.emptyList();
        //}

        BoomerangTaintFlowPath parentNode = null;
        if (secucheckAnalysisConfiguration.isPostProcessResult()) {
            parentNode = (BoomerangTaintFlowPath) TaintFlowPathUtility.findNodeUsingDFS(tempPath, query);
        }

        if (stmt.containsInvokeExpr()) {
            BackwardQuery sinkQuery = isSink(stmt, dataFlowEdge, dataFlowVal);
            if (sinkQuery != null) {
                BoomerangTaintFlowPath singleTaintFlowPath = null;
                if (secucheckAnalysisConfiguration.isPostProcessResult()) {
                    BoomerangTaintFlowPath finalSinkNode = new BoomerangTaintFlowPath(
                            sinkQuery, parentNode, false, true);
                    parentNode.addNewChild(finalSinkNode);
                    singleTaintFlowPath = TaintFlowPathUtility.createSinglePathFromRootNode(finalSinkNode);
                }

                DifferentTypedPair<BackwardQuery, BoomerangTaintFlowPath> res = new DifferentTypedPair<>(sinkQuery, singleTaintFlowPath);
                foundSinks.add(res);
                return Collections.emptyList();
            }

            Collection<Query> prop = isPropogator(singleFlow.getThrough(), stmt, dataFlowEdge, dataFlowVal);

            if (secucheckAnalysisConfiguration.isPostProcessResult()) {
                for (Query propQuery : prop) {
                    BoomerangTaintFlowPath finalSinkNode = new BoomerangTaintFlowPath(
                            propQuery, parentNode, false, false);
                    parentNode.addNewChild(finalSinkNode);
                }
            }

            out.addAll(prop);

            if (out.size() > 0)
                return out;

            Collection<Query> generalProp = isPropogator(secucheckAnalysisConfiguration.getAnalysisGeneralPropagators(), stmt, dataFlowEdge, dataFlowVal);

            if (secucheckAnalysisConfiguration.isPostProcessResult()) {
                for (Query generalPropQuery : generalProp) {
                    BoomerangTaintFlowPath finalSinkNode = new BoomerangTaintFlowPath(
                            generalPropQuery, parentNode, false, false);
                    parentNode.addNewChild(finalSinkNode);
                }
            }

            out.addAll(generalProp);
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
