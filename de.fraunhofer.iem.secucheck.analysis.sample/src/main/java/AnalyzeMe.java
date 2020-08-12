public class AnalyzeMe {
	
	public void workNoIssue() {
		int secret = getSecret();
		publish(10);
	}
	
	public void workNoIssueSanitizer() {
		int secret = getSecret();
		secret = sanatizer(secret);
		publish(secret);
	}
	
	public void workNoIssueSanitizerProgator() {
		int secret = getSecret();
		secret = sanatizer(secret);
		secret = propogator(secret);
		publish(secret);
	}
	
	public void workWithIssue() {
		int secret = getSecret();
		publish(secret);
	}
	
	public void workWithIssueProgator() {
		int secret = getSecret();
		secret = propogator(secret);
		publish(secret);
	}

	public int getSecret() { return 42; }
	public void publish(int number) { System.out.print(number); }  	
	public int sanatizer(int number) { return number = 0; }
	public int propogator(int number) { return number; }
}
