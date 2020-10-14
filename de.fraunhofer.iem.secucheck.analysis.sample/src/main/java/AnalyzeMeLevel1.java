/** 
 * This class will always be the base (entry-point) of synthetic 
 * taint-flow in the test logic. The level number indicates the
 * level the class belongs to in the taint-flow graph hierarchy. 
 */
public class AnalyzeMeLevel1 {
	
	/// Start: Taint-flow elements definition.

	public int getSecret() { return 42; }
	public void publish(int number) { System.out.print(number); }  	
	public int sanatizer(int number) { return number = 0; }
	public int propogator(int number) { return number; }
	
	/// End: Taint-flow elements definition.
	
	
	/// Start: Intra-type taint-flow definitions.

	/* 
	 * Simple taint-flow without any issue.
	 */
	public void workNoIssue() {
		int secret = getSecret();
		publish(10);
	}
		
	/*
	 * Taint-flow without any issue.
	 */
	public void workNoIssueSanitizer() {
		int secret = getSecret();
		secret = sanatizer(secret);
		publish(secret);
	}
	
	/* 
	 * Taint-flow without any issue.
	 */
	public void workNoIssueSanitizerProgator() {
		int secret = getSecret();
		secret = sanatizer(secret);
		secret = propogator(secret);
		publish(secret);
	}
	
	/*
	 * Simple taint-flow with issue.
	 */
	public void workWithIssue() {
		int secret = getSecret();
		publish(secret);
	}
	
	/*
	 * Simple taint-flow with issue from the parameter.
	 */
	public void workWithIssueParam(int secret) {
		publish(secret);
	}
	
	
	/*
	 * Taint-flow with issue using a Propogator.
	 */
	public void workWithIssueProgator() {
		int secret = getSecret();
		secret = propogator(secret);
		publish(secret);
	}
	
	/*
	 * Taint-flow with issue using the Propogator and 
	 * the Parameter.
	 */
	public void workWithIssueProgatorParam(int secret){
		secret = propogator(secret);
		publish(secret);
	}
	
	/// End: Intra-type taint-flow definitions.

	
	/// Start: Inter-type taint-flow definitions.
		
	/*
	 * Simple 2-level taint-flow with a direct issue.
	 */
	public void workWithOtherTypeIssue() {
		AnalyzeMeLevel2 level2Instance = new AnalyzeMeLevel2();
		int secret = level2Instance.getSecret();
		level2Instance.publish(secret);
	}
	
	/*
	 * Simple 2-level taint-flow with a direct issue 
	 * using the Parameter.
	 */
	public void workWithOtherTypeIssueParam(int secret) {
		AnalyzeMeLevel2 level2Instance = new AnalyzeMeLevel2();
		level2Instance.publish(secret);
	}
	
	/*
	 * 2-level taint-flow with a direct issue using 
	 * the Propogator.
	 */
	public void workWithOtherTypeIssueProgator() {
		AnalyzeMeLevel2 level2Instance = new AnalyzeMeLevel2();
		int secret = level2Instance.getSecret();
		secret = level2Instance.propogator(secret);
		level2Instance.publish(secret);
	}
	
	/*
	 * 2-level taint-flow with a direct issue using 
	 * the Propogator and the Parameter.
	 */
	public void workWithOtherTypeIssueProgatorParam(int secret){
		AnalyzeMeLevel2 level2Instance = new AnalyzeMeLevel2();
		secret = level2Instance.propogator(secret);
		level2Instance.publish(secret);
	}

	/* 
	 * Simple 2-level taint-flow with an indirect 
	 * call with no issue.
	 */
	public void workWithOtherTypeIndirectNoIssue() {
		AnalyzeMeLevel2 level2Instance = new AnalyzeMeLevel2();
		int secret = level2Instance.getSecret();
		level2Instance.indirectNoIssue(secret);
	}
	
	/* 
	 * 2-level taint-flow with an indirect issue.
	 */
	public void workWithOtherTypeIndirectIssue() {
		AnalyzeMeLevel2 level2Instance = new AnalyzeMeLevel2();
		int secret = level2Instance.getSecret();
		level2Instance.indirectIssue(secret);
	}
	
	/* 
	 * 2-level taint-flow with an indirect issue
	 * using the Porpogator and the Sanitizer.
	 */
	public void workWithOtherTypeIndirectSantNoIssue() {
		AnalyzeMeLevel2 level2Instance = new AnalyzeMeLevel2();
		int secret = level2Instance.getSecret();
		level2Instance.indirectSanitizerNoIssue(secret);
	}
	
	/* 
	 * 2-level taint-flow with an indirect issue
	 * using the Porpogator and the Sanitizer.
	 */
	public void workWithOtherTypeIndirectSantPropIssue() {
		AnalyzeMeLevel2 level2Instance = new AnalyzeMeLevel2();
		int secret = level2Instance.getSecret();
		level2Instance.indirectSanitizerPropogatorIssue(secret);
	}
		
	/// End: Inter-type taint-flow definitions.
}
