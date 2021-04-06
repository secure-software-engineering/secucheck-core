package de.fraunhofer.iem.secucheck.analysis.configuration;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.query.Solver;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;

/**
 * Interface for Secucheck Analysis configurations.
 */
public interface SecucheckAnalysisConfiguration {

    /**
     * Set the operating system in which the analysis is running
     *
     * @param os Operating System
     */
    void setOs(OS os);

    /**
     * Sets the solver for the taint analysis. Currently supported solver are Boomerang 3 and Flowdroid
     *
     * @param solver Solver for taint analysis
     */
    void setSolver(Solver solver);

    /**
     * Sets the class path for the soot
     *
     * @param sootClassPath Soot class path
     */
    void setSootClassPathJars(String sootClassPath);

    /**
     * Sets the application class path
     *
     * @param appClassPath Application class path
     */
    void setApplicationClassPath(String appClassPath);

    /**
     * Sets the entry point for the analysis
     *
     * @param entryPoints Entrypoints for the analysis
     */
    void setAnalysisEntryPoints(List<EntryPoint> entryPoints);

    /**
     * Sets the general propagators
     *
     * @param generalPropagators General propagators
     */
    void setAnalysisGeneralPropagators(List<MethodImpl> generalPropagators);

    /**
     * Sets the analysis result listener
     *
     * @param resultListener Analysis result listener
     */
    void setListener(AnalysisResultListener resultListener);

    OS getOs();

    Solver getSolver();

    String getSootClassPathJars();

    String getApplicationClassPath();

    List<EntryPoint> getAnalysisEntryPoints();

    List<MethodImpl> getAnalysisGeneralPropagators();

    AnalysisResultListener getListener();

}
