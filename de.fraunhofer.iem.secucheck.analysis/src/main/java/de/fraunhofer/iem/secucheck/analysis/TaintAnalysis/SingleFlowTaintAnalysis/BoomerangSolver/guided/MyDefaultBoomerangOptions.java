package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.flowfunction.IForwardFlowFunction;
import boomerang.scene.jimple.IntAndStringBoomerangOptions;

public class MyDefaultBoomerangOptions extends IntAndStringBoomerangOptions {

    @Override
    public StaticFieldStrategy getStaticFieldStrategy() {
        return StaticFieldStrategy.FLOW_SENSITIVE;
    }

    @Override
    public boolean onTheFlyCallGraph() {
        return false;
    }

    @Override
    public boolean trackStaticFieldAtEntryPointToClinit() {
        return true;
    }

    @Override
    public int maxCallDepth() {
        return 5;
    }

    @Override
    public int maxUnbalancedCallDepth() {
        return 5;
    }

    @Override
    public int maxFieldDepth() {
        return 5;
    }

    @Override
    public boolean allowMultipleQueries() {
        return true;
    }

    /*
    @Override
    public Optional<AllocVal> getAllocationVal(Method m, Statement stmt, Val fact) {
        System.out.println("Method = " + m);
        System.out.println("Statement = " + stmt);
        System.out.println("Fact = " + fact);
        System.out.println(super.getAllocationVal(m, stmt, fact).get());
        return super.getAllocationVal(m, stmt, fact);
    }
*/
    @Override
    public IForwardFlowFunction getForwardFlowFunctions() {
        return new MyDefaultForwardFlowFunction(this);
    }
}
