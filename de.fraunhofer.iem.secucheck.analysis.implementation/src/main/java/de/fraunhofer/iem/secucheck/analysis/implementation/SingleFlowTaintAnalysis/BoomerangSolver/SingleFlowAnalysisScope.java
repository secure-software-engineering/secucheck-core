package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver;

import boomerang.BackwardQuery;
import boomerang.ForwardQuery;
import boomerang.Query;
import boomerang.scene.AllocVal;
import boomerang.scene.AnalysisScope;
import boomerang.scene.ControlFlowGraph.Edge;
import boomerang.scene.Statement;
import boomerang.scene.Val;
import boomerang.scene.jimple.SootCallGraph;
import com.google.common.collect.Sets;
import de.fraunhofer.iem.secucheck.analysis.query.InputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.Method;
import de.fraunhofer.iem.secucheck.analysis.query.OutputParameter;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlow;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class SingleFlowAnalysisScope extends AnalysisScope {

    private final TaintFlow taintFlow;

    private final Set<boomerang.scene.Method> sourceMethods = new HashSet<>();
    private final Set<boomerang.scene.Method> sinkMethods = new HashSet<>();

    public SingleFlowAnalysisScope(TaintFlow taintFlow, SootCallGraph sootCallGraph) {
        super(sootCallGraph);
        this.taintFlow = taintFlow;
    }

    @Override
    protected Collection<? extends Query> generate(Edge cfgEdge) {
        Set<Query> out = Sets.newHashSet();

        Statement statement = cfgEdge.getStart();
/*
        System.out.println("----> " + statement);
*/
        Collection<Val> sourceVariables =
                generateSourceVariables(this.taintFlow, statement);

        sourceVariables.forEach(v -> out.add(new ForwardQuery(cfgEdge, v)));

        Collection<Val> sinkVariables = generatedSinkVariables(this.taintFlow, statement);

        sinkVariables.forEach(v -> out.add(BackwardQuery.make(cfgEdge, v)));

        // Find source methods.
        for (Method flowMethod : this.taintFlow.getFrom()) {

            if (Utility.toStringEquals(statement.getMethod(),
                    Utility.wrapInAngularBrackets(flowMethod.getSignature()))) {
                //Todo: Update

                if (flowMethod.getOutputParameters() != null) {
                    for (OutputParameter output : flowMethod.getOutputParameters()) {
                        int parameterIndex = output.getParamID();
                        if (statement.getMethod().getParameterLocals().size() >= parameterIndex) {

                            String param = statement.getMethod().getParameterLocals().get(parameterIndex).toString().replaceAll("\\(.*\\)$", "").trim();

                            if (statement.toString().contains("@parameter") && statement.toString().contains(param)) {

                                if (!sourceMethods.contains(statement.getMethod())) {
                                    out.add(new ForwardQuery(cfgEdge,
                                            new AllocVal(
                                                    statement.getMethod().getParameterLocals().get(parameterIndex),
                                                    statement,
                                                    statement.getMethod().getParameterLocals().get(parameterIndex))));

                                    sourceMethods.add(statement.getMethod());

                                 //   System.out.println("Added = " + statement.toString() + " § " + statement.getMethod()
                                 //           + " § " + cfgEdge.getY().getStartLineNumber());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Find target methods.
        for (Method flowMethod : this.taintFlow.getTo()) {
            //System.out.print(flowMethod.getSignature() + " ====== " + statement.getMethod());
            if (Utility.toStringEquals(statement.getMethod(),
                    Utility.wrapInAngularBrackets(flowMethod.getSignature()))) {
                //System.out.print("<<< Added >>>");
                sinkMethods.add(statement.getMethod());
            }
            //System.out.println();
        }

        return out;
    }

    private Collection<Val> generateSourceVariables(TaintFlow partialFlow,
                                                    Statement statement) {

        Collection<Val> out = Sets.newHashSet();

        for (Method sourceMethod : partialFlow.getFrom()) {

            String sourceSootSignature = Utility.wrapInAngularBrackets(sourceMethod.getSignature());

            if (statement.containsInvokeExpr()) {
           //     System.out.println("TaintFlow source = " + sourceSootSignature);
           //     System.out.println("Statement source = " + statement.getInvokeExpr().getMethod().getSignature());
                if (Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(), sourceSootSignature)) {
                    // Taint the return value
            //        System.out.println("EEntered");
                    if (sourceMethod.getReturnValue() != null && statement.isAssign()) {

                        out.add(new AllocVal(statement.getLeftOp(), statement, statement.getLeftOp()));
                    }

                    if (sourceMethod.getOutputParameters() != null) {
                        for (OutputParameter output : sourceMethod.getOutputParameters()) {
                            int parameterIndex = output.getParamID();
                            if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                                out.add(statement.getInvokeExpr().getArg(parameterIndex));
                            }
                        }
                    }

                    // Taint this object
                    if (sourceMethod.isOutputThis() &&
                            statement.getInvokeExpr().isInstanceInvokeExpr()) {
                        out.add(new AllocVal(statement.getInvokeExpr().getBase(), statement, statement.getInvokeExpr().getBase()));
                    }
                }
            }
        }

        return out;
/*



            if (Utility.toStringEquals(statement.getMethod(), sourceSootSignature) &&
                    statement.isIdentityStmt()) {

                // Left and Right Op() methods don't work for IdentityStmt inside JimpleStatement.
                if (statement instanceof JimpleStatement) {

                    JimpleStatement jimpleStament = (JimpleStatement) statement;
                    IdentityStmt identityStmt = (IdentityStmt) jimpleStament.getDelegate();

                    if (identityStmt.getRightOp() instanceof ParameterRef) {
                        ParameterRef parameterRef = (ParameterRef) identityStmt.getRightOp();

                        if (sourceMethod.getOutputParameters() != null) {
                            for (OutputParameter output : sourceMethod.getOutputParameters()) {

                                int parameterIndex = output.getNumber();
                                if (statement.getMethod().getParameterLocals().size() >= parameterIndex
                                        && parameterRef.getIndex() == parameterIndex) {

                                    out.add(new AllocVal(
                                            new JimpleVal(identityStmt.getLeftOp(), statement.getMethod()),
                                            statement,
                                            new JimpleVal(identityStmt.getRightOp(), statement.getMethod())
                                    ));

                                }
                            }
                        }
                    }
                }

                return out;

            } else if (statement.containsInvokeExpr()
                    && Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(),
                    sourceSootSignature)) {

                // Taint the return value
                if (sourceMethod.getReturnValue() != null && statement.isAssign()) {
                    out.add(new AllocVal(statement.getLeftOp(), statement, statement.getRightOp()));
                }

                if (sourceMethod.getOutputParameters() != null) {
                    for (OutputParameter output : sourceMethod.getOutputParameters()) {
                        int parameterIndex = output.getNumber();
                        if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                            out.add(statement.getInvokeExpr().getArg(parameterIndex));
                        }
                    }
                }

                // Taint this object
                if (sourceMethod.isOutputThis() &&
                        statement.getInvokeExpr().isInstanceInvokeExpr()) {
                    out.add(statement.getInvokeExpr().getBase());
                }

                return out;
            }

        }
//		if (this.flow.getSource().getValueSource() != null) // a single value source
//		{
//			// TODO:handle this
//		} 
        return Collections.emptySet();*/
    }

    private Collection<Val> generatedSinkVariables(TaintFlow partialFlow,
                                                   Statement statement) {

        for (Method sinkMethod : partialFlow.getTo()) {

            //System.out.print("Sink ===--->>> " + sinkMethod.getSignature() + " ----- ");
            String sinkSootSignature = Utility.wrapInAngularBrackets(sinkMethod.getSignature());
            Collection<Val> out = Sets.newHashSet();

            if (statement.containsInvokeExpr() &&
                    Utility.toStringEquals(statement.getInvokeExpr().getMethod().getSignature(),
                            sinkSootSignature)) {

                // Taint the return value.
                if (sinkMethod.getInputParameters() != null) {
                    for (InputParameter input : sinkMethod.getInputParameters()) {
                        int parameterIndex = input.getParamID();
                        if (statement.getInvokeExpr().getArgs().size() >= parameterIndex) {
                            //System.out.println("Added");
                            out.add(statement.getInvokeExpr().getArg(parameterIndex));
                        }
                    }
                }

                // Taint this object.
                if (sinkMethod.isInputThis() &&
                        statement.getInvokeExpr().isInstanceInvokeExpr()) {
                    out.add(statement.getInvokeExpr().getBase());
                }

                return out;
            }

        }

        // TODO: re-check the sink structure!!
        return Collections.emptySet();
    }
}
