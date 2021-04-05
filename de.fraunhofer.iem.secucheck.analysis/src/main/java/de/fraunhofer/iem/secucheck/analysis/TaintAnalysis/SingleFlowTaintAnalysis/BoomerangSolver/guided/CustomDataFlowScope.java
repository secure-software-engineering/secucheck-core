package de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.guided;

import boomerang.scene.DataFlowScope;
import boomerang.scene.DeclaredMethod;
import boomerang.scene.Method;
import boomerang.scene.jimple.JimpleDeclaredMethod;
import boomerang.scene.jimple.JimpleMethod;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.SingleFlowTaintAnalysis.BoomerangSolver.Utility;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import soot.SootClass;

import java.util.ArrayList;
import java.util.List;

public class CustomDataFlowScope implements DataFlowScope {
    List<MethodImpl> sanitizers = new ArrayList<>();

    public CustomDataFlowScope(List<MethodImpl> sanitizers) {
        this.sanitizers.addAll(sanitizers);
    }
    @Override
    public boolean isExcluded(DeclaredMethod method) {
        JimpleDeclaredMethod m = (JimpleDeclaredMethod) method;

        for (MethodImpl sanitizer : sanitizers) {
            if (method.getSignature().equals(Utility.wrapInAngularBrackets(sanitizer.getSignature())))
                return true;
        }

        if (method.getSignature().equals("<org.owasp.webgoat.sql_injection.introduction.SqlInjectionLesson2: java.lang.String sanitize(java.lang.String)>")) {
            return true;
        }

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

        for (MethodImpl sanitizer : sanitizers) {
            String[] arr = Utility.wrapInAngularBrackets(sanitizer.getSignature()).split(" ");
            String subSignature = arr[arr.length - 2] + " " + arr[arr.length - 1];
            subSignature = subSignature.replace(">", "");

            if (m.getSubSignature().equals(subSignature))
                return true;
        }

        if (m.getSubSignature().equals("java.lang.String sanitize(java.lang.String)")) {
            return true;
        }

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
