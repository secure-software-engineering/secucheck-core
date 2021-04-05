package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.scene.DataFlowScope;
import boomerang.scene.DeclaredMethod;
import boomerang.scene.Method;
import boomerang.scene.jimple.JimpleDeclaredMethod;
import boomerang.scene.jimple.JimpleMethod;
import de.fraunhofer.iem.secucheck.analysis.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowQueryImpl;
import soot.SootClass;

import java.util.List;

public class CustomDataFlowScope implements DataFlowScope {
    private final TaintFlowQueryImpl singleFlow;
    private final SecucheckAnalysisConfiguration secucheckAnalysisConfiguration;

    public CustomDataFlowScope(TaintFlowQueryImpl singleFlow, SecucheckAnalysisConfiguration secucheckAnalysisConfiguration) {
        this.singleFlow = singleFlow;
        this.secucheckAnalysisConfiguration = secucheckAnalysisConfiguration;
    }

    @Override
    public boolean isExcluded(DeclaredMethod method) {
        JimpleDeclaredMethod m = (JimpleDeclaredMethod) method;

        for (MethodImpl sanitizer : singleFlow.getNotThrough()) {
            if (method.getSignature().equals(Utility.wrapInAngularBrackets(sanitizer.getSignature())))
                return true;
        }

        for (MethodImpl gp : secucheckAnalysisConfiguration.getAnalysisGeneralPropagators()) {
            if (method.getSignature().equals(Utility.wrapInAngularBrackets(gp.getSignature())))
                return true;
        }


        return ((SootClass) m.getDeclaringClass().getDelegate()).isPhantom() || m.isNative();
    }

    private boolean findMethod(Method requestedMethod, List<MethodImpl> methods) {
        for (MethodImpl method : methods) {
            String[] arr = Utility.wrapInAngularBrackets(method.getSignature()).split(" ");
            String subSignature = arr[arr.length - 2] + " " + arr[arr.length - 1];
            subSignature = subSignature.replace(">", "");

            if (requestedMethod.getSubSignature().equals(subSignature))
                return true;
        }

        return false;
    }

    public boolean isExcluded(Method method) {
        JimpleMethod m = (JimpleMethod) method;

        if (findMethod(m, singleFlow.getNotThrough()))
            return true;

        if (findMethod(m, secucheckAnalysisConfiguration.getAnalysisGeneralPropagators()))
            return true;

        return ((SootClass) m.getDeclaringClass().getDelegate()).isPhantom() || m.isNative();
    }
}
