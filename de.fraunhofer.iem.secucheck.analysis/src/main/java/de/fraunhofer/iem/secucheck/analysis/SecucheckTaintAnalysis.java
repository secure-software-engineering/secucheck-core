package de.fraunhofer.iem.secucheck.analysis;

import java.security.Permission;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.TaintAnalysis.result.SecucheckTaintAnalysisResult;

/**
 * Second level implementation of the SecucheckAnalysis. This sets the enviornment for the analysis.
 */
public final class SecucheckTaintAnalysis extends SecucheckTaintAnalysisBase {

    public SecucheckTaintAnalysis() {
        super(null);
    }

    public SecucheckTaintAnalysis(SecucheckAnalysisConfiguration config) {
        super(config);
    }

    @Override
    public SecucheckTaintAnalysisResult run(List<CompositeTaintFlowQueryImpl> flowQueries)
            throws Exception {
        super.lock.lock();
        try {
            // soot calls System.exit() in case of problems. This shuts down the process.
            // Therefore we must prevent System.exit() using Security Manager
            SecurityManager previousManager = System.getSecurityManager();
            try {
                System.setSecurityManager(new SecurityManager() {
                    public void checkPermission(Permission perm) {
                    }

                    public void checkExit(int status) {
                        super.checkExit(status);
                        throw new RuntimeException(
                                "System.exit() is not allowed during analysis.");
                    }
                });

                return super.run(flowQueries);

            } finally {
                System.setSecurityManager(previousManager);
            }
        } finally {
            super.lock.unlock();
        }
    }
}
