package secucheck.analysis.configuration;

import java.util.List;

import secucheck.analysis.query.EntryPoint;
import secucheck.analysis.query.MethodImpl;
import secucheck.analysis.query.OS;
import secucheck.analysis.query.Solver;
import secucheck.analysis.result.AnalysisResultListener;

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

    /**
     * Sets the isPostProcess result. If set, then it process the result and add the taintflow path to the result.
     * For now, it PostProcess result is available only to Boomerang3 solver
     *
     * @param isPostProcessResult is Post Process result
     */
    void setIsPostProcessResult(boolean isPostProcessResult);

    OS getOs();

    Solver getSolver();

    String getSootClassPathJars();

    String getApplicationClassPath();

    List<EntryPoint> getAnalysisEntryPoints();

    List<MethodImpl> getAnalysisGeneralPropagators();

    AnalysisResultListener getListener();

    boolean isPostProcessResult();

}
