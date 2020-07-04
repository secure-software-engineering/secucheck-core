package de.fraunhofer.iem.secucheck.analysis;

import java.security.Permission;
import java.util.List;

import de.fraunhofer.iem.secucheck.custom.ProgressReporter;
import de.fraunhofer.iem.secucheck.marker.AnalysisResult;
import de.fraunhofer.iem.secucheck.query.Flow;
import de.fraunhofer.iem.secucheck.query.TaintFlow;
public class SecuCheckAnalysis {
		
	public AnalysisResult run(String sootClassPath, List<String> canonicalClassNames,
			List<TaintFlow> flowQueries, List<Flow> flows) {

		// soot calls System.exit() in case of problems. This shuts down the process.
		// Therefore we must prevent System.exit() using Security Manager
		SecurityManager previousManager = System.getSecurityManager();
		try {
			System.setSecurityManager(new SecurityManager() {
				public void checkPermission(Permission perm) {}
				public void checkExit(int status) {
					super.checkExit(status);
					throw new RuntimeException("System.exit() is not allowed during analysis.");
				}
			});
			return SpottyTestingFramework.run(sootClassPath, canonicalClassNames,
					flowQueries, flows);

		} finally {
			System.setSecurityManager(previousManager);
		}

	}
}
