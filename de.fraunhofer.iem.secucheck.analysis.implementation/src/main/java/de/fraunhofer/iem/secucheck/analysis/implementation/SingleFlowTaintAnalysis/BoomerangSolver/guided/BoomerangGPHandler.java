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
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.datastructure.BoomerangTaintFlowPath;
import de.fraunhofer.iem.secucheck.analysis.parser.methodsignature.SignatureParser;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.TaintFlowPathUtility;
import de.fraunhofer.iem.secucheck.analysis.query.*;

import java.util.*;

/**
 * This is the Secucheck DemandDriven Manager for Boomerang
 *
 * @author Ranjith Krishnamurthy
 */
public class BoomerangGPHandler implements IDemandDrivenGuidedManager {
    
	/**
     * List of found sinks. Whenever SecucheckDemandDrivenManager finds a sink with a taint flow then it creates a
     * BackwardQuery and adds it to this list.
     */
    private final ArrayList<DifferentTypedPair<BackwardQuery, BoomerangTaintFlowPath>> foundSinks = new ArrayList<>();
    
    /**
     * List of found sources. Whenever SecucheckDemandDrivenManager finds a source with a taint flow then it creates a
     * ForwardQuery and adds it to this list.
     */
    private final ArrayList<DifferentTypedPair<ForwardQuery, BoomerangTaintFlowPath>> foundSources = new ArrayList<>();

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
     * Getter for the list of found sources
     *
     * @return List of found sources
     */
    public ArrayList<DifferentTypedPair<ForwardQuery, BoomerangTaintFlowPath>> getFoundSources() {
        return foundSources;
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
        for (Method sinkMethod : singleFlow.getTo()) {
        	
        	// If there is a sink method call, then check is there a taint flow present
            if (statement.containsInvokeExpr() &&
            		SignatureParser.matches(statement.getInvokeExpr().getMethod().getSignature(), sinkMethod.getSignature())) {

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
            }
        }
        return null;
    }
    
    /**
     * This method checks whether the current statement contains the source method call. If yes, it return true.
     *
     * @param statement    Current Statement
     * @param dataFlowEdge Dataflow edge
     * @param dataFlowVal  Fact: dataFlowVal
     * @return True is there is a source method call and TaintFlow exist.
     */
    private ForwardQuery isSource(Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {    	
    	for (TaintFlowElement flowElement : singleFlow.getFrom()) {
    		
    		if(flowElement instanceof Method) {
        		Method sourceMethod = (Method) flowElement;
        		
        		// If there is a source method call, then check is there a taint flow present
                if (statement.containsInvokeExpr() &&
                	SignatureParser.matches(statement.getInvokeExpr().getMethod().getSignature(), sourceMethod.getSignature())) {

                    //For sinks there is always a OutFlow, there is no InFlow.

                    // Check for the OutFlow parameters
                    if (sourceMethod.getOutputParameters() != null) {
                        for (OutputParameter output : sourceMethod.getOutputParameters()) {
                            int parameterIndex = output.getParamID();
                            if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                                if (statement.getInvokeExpr().getArg(parameterIndex).toString().equals(dataFlowVal.toString())) {
                                    return new ForwardQuery(dataFlowEdge, statement.getInvokeExpr().getArg(parameterIndex));
                                }
                            }
                        }
                    }

                    // Check for OutFlow this-object
                    if (sourceMethod.isOutputThis() &&
                            statement.getInvokeExpr().isInstanceInvokeExpr()) {
                        if (statement.getInvokeExpr().getBase().toString().equals(dataFlowVal.toString())) {
                            return new ForwardQuery(dataFlowEdge, statement.getInvokeExpr().getBase());
                        }
                    }
                    
                    // Check for return value
                    if (sourceMethod.getReturnValue() != null && statement.isAssign()) {
                    	return new ForwardQuery(dataFlowEdge, statement.getLeftOp());
                    }
                }
                
                // If the entry method is source then create a ForwardQuery
                if (SignatureParser.matches(statement.getMethod(), sourceMethod.getSignature())) {
                	// Check for OutFlow Parameter, If any then create query for respective parameter
                    if (sourceMethod.getOutputParameters() != null) {
                        for (OutputParameter output : sourceMethod.getOutputParameters()) {
                            int parameterIndex = output.getParamID();
                            if (statement.getMethod().getParameterLocals().size() >= parameterIndex) {
                                String param = statement.getMethod().getParameterLocals().get(parameterIndex).toString().replaceAll("\\(.*\\)$", "").trim();
                                if (statement.toString().contains("@parameter") && statement.toString().contains(param)) {
                                	return new ForwardQuery(dataFlowEdge,
                                			new AllocVal(
                                					statement.getMethod().getParameterLocals().get(parameterIndex),
                                					statement, 
                                					statement.getMethod().getParameterLocals().get(parameterIndex)));
                                }
                            }
                        }
                    }
                    
                    // ToDo: check is it necessary to check for OutFlow this-object
                }
    		}
    		
    		else if(flowElement instanceof Variable && statement.isAssign()) {
    			Variable sourceVariable = (Variable) flowElement;
    			if(sourceVariable.equals(Variable.HARDCODED) && statement.getRightOp().isStringConstant()) {
    				return new ForwardQuery(dataFlowEdge, statement.getLeftOp());
    			}
    			else if(sourceVariable.equals(Variable.NULL) && statement.getRightOp().isNull()) {
    				return new ForwardQuery(dataFlowEdge, statement.getLeftOp());
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

        // Check for return value
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
     * This method returns the Collections of Query based on the InFlow for the given propagator.
     *
     * @param propogatorMethod propagator method that is found
     * @param statement        Current statement
     * @param dataFlowEdge     Dataflow edge
     * @param dataFlowVal      Fact
     * @return List of Query based on the InFlow of the required propagator
     */
    private Collection<Query> getInForPropagator(Method propogatorMethod, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
    	List<Query> queryList = new ArrayList<>();
    	
    	// Check for the OutFlow
        if (propogatorMethod.getInputParameters() != null) {
            for (InputParameter inputParameter : propogatorMethod.getInputParameters()) {
                int parameterIndex = inputParameter.getParamID();
                if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) { // If InFlow present, then create a query
                    queryList.add(BackwardQuery.make(dataFlowEdge,
                            new AllocVal(
                                    statement.getInvokeExpr().getArg(parameterIndex),
                                    statement,
                                    statement.getInvokeExpr().getArg(parameterIndex)
                            )
                    ));
                }
            }
        }

        // Check for InFlow this-object
        if (propogatorMethod.isInputThis() &&
                statement.getInvokeExpr().isInstanceInvokeExpr()) { // If present, then create a query for this-object
            queryList.add(BackwardQuery.make(dataFlowEdge,
                    new AllocVal(
                            statement.getInvokeExpr().getBase(),
                            statement,
                            statement.getInvokeExpr().getBase()
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
    private Collection<Query> getQueriesBasedOnTheForwardFlowRules(Method requiredPropogatorMethod, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
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
     * This method checks whether the statement outflow is tainted based on the fluentTQL specification given.
     *
     * @param requiredPropogatorMethod FluentTQL method that contains the specification
     * @param statement                Statement
     * @param dataFlowEdge             Dataflow edge
     * @param dataFlowVal              Fact
     * @return List of Query based on the InFlow of the required propagator
     */
    private Collection<Query> getQueriesBasedOnTheBackwardFlowRules(Method requiredPropogatorMethod, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
    	List<Query> queryList = new ArrayList<>();
    	
    	// Check for OutFlow parameter
        if (requiredPropogatorMethod.getOutputParameters() != null) {
            for (OutputParameter output : requiredPropogatorMethod.getOutputParameters()) {
                int parameterIndex = output.getParamID();
                if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                    if (statement.getInvokeExpr().getArg(parameterIndex).toString().equals(dataFlowVal.toString())) {
                        queryList.addAll(getInForPropagator(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));
                        return queryList;
                    }
                }
            }
        }

        // Check for OutFlow this-object
        if (requiredPropogatorMethod.isOutputThis() &&
                statement.getInvokeExpr().isInstanceInvokeExpr()) {
            if (statement.getInvokeExpr().getBase().toString().equals(dataFlowVal.toString())) {
                queryList.addAll(getInForPropagator(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));
                return queryList;
            }
        }
        
        //Check for return value
        if (requiredPropogatorMethod.getReturnValue() != null && 
        		statement.isAssign()) { // If yes, create a query for left-op
        	queryList.addAll(getInForPropagator(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));
            return queryList;
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
     * @param direction The direction of flow, which is either "forward" or "backward"
     * @return Returns the List of query if there is a taintflow present in the propagators.
     */
    private Collection<Query> isPropogator(List<MethodImpl> propogators, Statement statement, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal, String direction) {
        List<Query> queryList = new ArrayList<>();

        if (direction.equals("forward")) {
        	for (Method requiredPropogatorMethod : propogators) {
            	
            	// If there is a propagator, then check is there a tainted variable going into the method
                if (statement.containsInvokeExpr() &&
                		SignatureParser.matches(statement.getInvokeExpr().getMethod().getSignature(), requiredPropogatorMethod.getSignature())) {

                    queryList.addAll(getQueriesBasedOnTheForwardFlowRules(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));

                } else if (statement.getInvokeExpr().getMethod().getSubSignature().equals(requiredPropogatorMethod.getSignature())) { // For Java 11
                    // Todo: Check and model it correctly to handle the Java 11 dynamic calls.
                    queryList.addAll(getQueriesBasedOnTheForwardFlowRules(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));
                }

            }
        }
        
        if (direction.equals("backward")) {
        	for (Method requiredPropogatorMethod : propogators) {
            	
            	// If there is a propagator, then check is there a tainted variable going out of the method
                if (statement.containsInvokeExpr() &&
                		SignatureParser.matches(statement.getInvokeExpr().getMethod().getSignature(), requiredPropogatorMethod.getSignature())) {

                    queryList.addAll(getQueriesBasedOnTheBackwardFlowRules(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));

                } else if (statement.getInvokeExpr().getMethod().getSubSignature().equals(requiredPropogatorMethod.getSignature())) { // For Java 11
                    // Todo: Check and model it correctly to handle the Java 11 dynamic calls.
                    queryList.addAll(getQueriesBasedOnTheBackwardFlowRules(requiredPropogatorMethod, statement, dataFlowEdge, dataFlowVal));
                }

            }
        }

        return queryList;
    }

    /**
     * For forward Query.
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

            Collection<Query> prop = isPropogator(singleFlow.getThrough(), stmt, dataFlowEdge, dataFlowVal, "forward");

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

            Collection<Query> generalProp = isPropogator(secucheckAnalysisConfiguration.getAnalysisGeneralPropagators(), stmt, dataFlowEdge, dataFlowVal, "forward");

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
     * For backward Query.
     *
     * @param query        BackwardQuery
     * @param dataFlowEdge Dataflow edge
     * @param dataFlowVal  fact
     * @return List of queries based on the current dataFlowVal---fact
     */
    @Override
    public Collection<Query> onBackwardFlow(BackwardQuery query, ControlFlowGraph.Edge dataFlowEdge, Val dataFlowVal) {
    	Statement stmt = dataFlowEdge.getStart();
        ArrayList<Query> out = new ArrayList<Query>();

        BoomerangTaintFlowPath parentNode = null;
        if (secucheckAnalysisConfiguration.isPostProcessResult()) {
            parentNode = (BoomerangTaintFlowPath) TaintFlowPathUtility.findNodeUsingDFS(tempPath, query);
        }

        ForwardQuery sourceQuery = isSource(stmt, dataFlowEdge, dataFlowVal);
        if (sourceQuery != null) {
            BoomerangTaintFlowPath singleTaintFlowPath = null;
            if (secucheckAnalysisConfiguration.isPostProcessResult()) {
                BoomerangTaintFlowPath finalSourceNode = new BoomerangTaintFlowPath(
                        sourceQuery, parentNode, false, true);
                parentNode.addNewChild(finalSourceNode);
                singleTaintFlowPath = TaintFlowPathUtility.createSinglePathFromRootNode(finalSourceNode);
            }

            DifferentTypedPair<ForwardQuery, BoomerangTaintFlowPath> res = new DifferentTypedPair<>(sourceQuery, singleTaintFlowPath);
            foundSources.add(res);
            return Collections.emptyList();
        }
        
        if (stmt.containsInvokeExpr()) {
            Collection<Query> prop = isPropogator(singleFlow.getThrough(), stmt, dataFlowEdge, dataFlowVal, "backward");

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

            Collection<Query> generalProp = isPropogator(secucheckAnalysisConfiguration.getAnalysisGeneralPropagators(), stmt, dataFlowEdge, dataFlowVal, "backward");

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
}
