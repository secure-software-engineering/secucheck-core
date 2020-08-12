package de.fraunhofer.iem.secucheck.analysis;

import java.security.Permission;
import java.util.List;

import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQuery;
import de.fraunhofer.iem.secucheck.analysis.query.CompositeTaintFlowQueryImpl;
import de.fraunhofer.iem.secucheck.analysis.query.EntryPoint;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResult;
import de.fraunhofer.iem.secucheck.analysis.result.AnalysisResultListener;
import de.fraunhofer.iem.secucheck.analysis.result.SecucheckTaintAnalysisResult;

public final class SecucheckTaintAnalysis extends SecucheckTaintAnalysisBase {
	
	public SecucheckTaintAnalysis() {
		super();
	}
		
	public SecucheckTaintAnalysis(OS os, String appClassPath, 
			String sootClassPath, List<EntryPoint> entryPoints,
			AnalysisResultListener resultListener) {
		super(os, appClassPath, sootClassPath, entryPoints,
				resultListener);	
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
					public void checkPermission(Permission perm) {}
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
