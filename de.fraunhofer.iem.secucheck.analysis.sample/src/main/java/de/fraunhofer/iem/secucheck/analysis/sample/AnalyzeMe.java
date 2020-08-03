package de.fraunhofer.iem.secucheck.analysis.sample;

public class AnalyzeMe {
	public void work() {
		int secret = getSecret();
		publish(secret);
		//publish(sanatizer(secret));
	}

	public int getSecret() { return 42; }
	public void publish(int number) { }  	
	public int sanatizer(int number) { return number = 0; }
}
