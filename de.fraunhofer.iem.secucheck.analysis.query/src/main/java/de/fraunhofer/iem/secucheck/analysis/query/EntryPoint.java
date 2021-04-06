package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.List;

/**
 * This class contains the entry points for the analysis.
 */
public final class EntryPoint {

    /**
     * class name
     */
    private String canonicalClassName;

    /**
     * List of methods as entry points for analysis.
     */
    private List<String> methods;

    /**
     * True if all method in this class is entry points for analysis.
     */
    private boolean isAllMethods;

    public EntryPoint() {
    }

    /**
     * Getter for class name
     *
     * @return Class name
     */
    public String getCanonicalClassName() {
        return canonicalClassName;
    }

    /**
     * Getter for list of method for entry points
     *
     * @return List of methods as entry points for analysis
     */
    public List<String> getMethods() {
        return this.methods;
    }

    /**
     * This method return true, if all methods in the given class are entry points for analysis.
     *
     * @return Boolean
     */
    public boolean isAllMethods() {
        return this.isAllMethods;
    }

    /**
     * Setter for class name
     *
     * @param canonicalClassName Class name
     */
    public void setCanonicalClassName(String canonicalClassName) {
        this.canonicalClassName = canonicalClassName;
    }

    /**
     * Setter for list of method for entry points.
     *
     * @param methods List of method as entry points.
     */
    public void setMethods(List<String> methods) {
        this.methods = methods;
    }

    /**
     * Setter for isAllMethods
     *
     * @param isAllMethods Boolean
     */
    public void setAllMethods(boolean isAllMethods) {
        this.isAllMethods = isAllMethods;
    }
}
