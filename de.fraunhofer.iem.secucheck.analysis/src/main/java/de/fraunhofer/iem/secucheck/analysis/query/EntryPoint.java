package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

public final class EntryPoint {

    private String canonicalClassName;
    private List<String> methods;
    private boolean isAllMethods;

    public EntryPoint() {
    }

    public String getCanonicalClassName() {
        return canonicalClassName;
    }

    public List<String> getMethods() {
        return this.methods;
    }

    public boolean isAllMethods() {
        return this.isAllMethods;
    }

    public void setCanonicalClassName(String canonicalClassName) {
        this.canonicalClassName = canonicalClassName;
    }

    public void setMethods(List<String> methods) {
        this.methods = methods;
    }

    public void setAllMethods(boolean isAllMethods) {
        this.isAllMethods = isAllMethods;
    }
}
