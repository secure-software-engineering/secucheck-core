package de.fraunhofer.iem.secucheck.analysis;

import java.security.Permission;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;

public final class ExitSafeTaintAnalysis extends TaintAnalysis {
	
	public ExitSafeTaintAnalysis(String sootClassPath, 
			List<String> canonicalClassNames, List<CompositeTaintFlowQuery> flowQueries,
			AnalysisResultListener resultListener) {
		super(sootClassPath, canonicalClassNames, flowQueries, resultListener);	
	}
	
	@Override
	public AnalysisResult run() {

		// soot calls System.exit() in case of problems. This shuts down the process.
		// Therefore we must prevent System.exit() using Security Manager
		SecurityManager previousManager = System.getSecurityManager();
		try {
			System.setSecurityManager(new SecurityManager() {
				public void checkPermission(Permission perm) {}
				public void checkExit(int status) {
					super.checkExit(status);
					throw new RuntimeException(
							"System.exit() is not allowed during analysis.");
				}
			});
			
			return super.run();
			
		} finally {
			System.setSecurityManager(previousManager);
		}

	}
}
