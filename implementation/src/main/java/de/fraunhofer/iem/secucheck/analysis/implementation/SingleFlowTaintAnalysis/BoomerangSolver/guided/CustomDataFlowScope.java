package de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.scene.DataFlowScope;
import boomerang.scene.DeclaredMethod;
import boomerang.scene.Method;
import boomerang.scene.jimple.JimpleDeclaredMethod;
import boomerang.scene.jimple.JimpleMethod;
import de.fraunhofer.iem.secucheck.analysis.configuration.SecucheckAnalysisConfiguration;
import de.fraunhofer.iem.secucheck.analysis.implementation.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.TaintFlowImpl;
import soot.SootClass;

import java.util.List;

/**
 * CustomDataFlowScope for Boomerang. This excludes sanitizer and general propagator from analyzing
 */
public class CustomDataFlowScope implements DataFlowScope {
    /**
     * Current single TaintFlow specification. To retrieve the sanitizers
     */
    private final TaintFlowImpl singleFlow;

    /**
     * SecucheckAnalysisConfiguration from the client. To retrieve the general propagators
     */
    private final SecucheckAnalysisConfiguration secucheckAnalysisConfiguration;

    public CustomDataFlowScope(TaintFlowImpl singleFlow, SecucheckAnalysisConfiguration secucheckAnalysisConfiguration) {
        this.singleFlow = singleFlow;
        this.secucheckAnalysisConfiguration = secucheckAnalysisConfiguration;
    }

    @Override
    public boolean isExcluded(DeclaredMethod method) {
        JimpleDeclaredMethod m = (JimpleDeclaredMethod) method;

        // Exclude sanitizer
        for (MethodImpl sanitizer : singleFlow.getNotThrough()) {
            if (method.getSignature().equals(Utility.wrapInAngularBrackets(sanitizer.getSignature())))
                return true;
        }

        // Exclude general propagators
        for (MethodImpl gp : secucheckAnalysisConfiguration.getAnalysisGeneralPropagators()) {
            if (method.getSignature().equals(Utility.wrapInAngularBrackets(gp.getSignature())))
                return true;
        }


        return ((SootClass) m.getDeclaringClass().getDelegate()).isPhantom() || m.isNative();
    }

    /**
     * This method process the method and get the subSignature and check is it present in the given list of Methods
     *
     * @param requestedMethod Requested methods to check is it present in the given list of methods
     * @param methods         List of methods
     * @return True if the requested method is present in the given list of methods
     */
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

        // Exclude sanitizers
        if (findMethod(m, singleFlow.getNotThrough()))
            return true;

        // Exclude general propagators
        if (findMethod(m, secucheckAnalysisConfiguration.getAnalysisGeneralPropagators()))
            return true;

        return ((SootClass) m.getDeclaringClass().getDelegate()).isPhantom() || m.isNative();
    }
}
