package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.scene.DataFlowScope;
import boomerang.scene.DeclaredMethod;
import boomerang.scene.Method;
import boomerang.scene.jimple.JimpleDeclaredMethod;
import boomerang.scene.jimple.JimpleMethod;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided.BoomerangGPHandler;
import soot.SootClass;

public class CustomDataFlowScope implements DataFlowScope {
    @Override
    public boolean isExcluded(DeclaredMethod method) {
        JimpleDeclaredMethod m = (JimpleDeclaredMethod) method;

        if (method.getSignature().equals(BoomerangGPHandler.S_VALUE_OF)) {
            return true;
        }

        if (method.getSignature().equals(BoomerangGPHandler.SB_TO_STRING)) {
            return true;
        }

        if (method.getSignature().equals(BoomerangGPHandler.SB_APPEND)) {
            return true;
        }



        return ((SootClass) m.getDeclaringClass().getDelegate()).isPhantom() || m.isNative();
    }

    public boolean isExcluded(Method method) {
        JimpleMethod m = (JimpleMethod) method;

        if (m.getSubSignature().equals("java.lang.String valueOf(java.lang.Object)")) {
            return true;
        }

        if (m.getSubSignature().equals("java.lang.String toString()")) {
            return true;
        }

        if (m.getSubSignature().equals("java.lang.StringBuilder append(java.lang.String)")) {
            return true;
        }

        return ((SootClass) m.getDeclaringClass().getDelegate()).isPhantom() || m.isNative();
    }
}