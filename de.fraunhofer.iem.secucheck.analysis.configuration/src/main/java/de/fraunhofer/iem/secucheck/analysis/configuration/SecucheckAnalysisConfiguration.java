package de.fraunhofer.iem.secucheck.analysis.configuration;

import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;
import de.fraunhofer.iem.secucheck.analysis.query.OS;
import de.fraunhofer.iem.secucheck.analysis.query.Solver;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;

/**
 * Secucheck Analysis configurations.
 */
public interface SecucheckAnalysisConfiguration {

    void setOs(OS os);

    void setSolver(Solver solver);

    void setSootClassPathJars(String sootClassPath);

    void setApplicationClassPath(String appClassPath);

    void setAnalysisEntryPoints(List<EntryPoint> entryPoints);

    void setAnalysisGeneralPropagators(List<MethodImpl> generalPropagators);

    void setListener(AnalysisResultListener resultListener);

    OS getOs();

    Solver getSolver();

    String getSootClassPathJars();

    String getApplicationClassPath();

    List<EntryPoint> getAnalysisEntryPoints();

    List<MethodImpl> getAnalysisGeneralPropagators();

    AnalysisResultListener getListener();

}
