
/** 
 * This class will always be at the second level of synthetic 
 * taint-flow in the test logic. In other words if in the taint-flows
 * there another type encountered this will be immediately after 
 * the base (entry-point) type. The level number indicates the
 * level the class belongs to in the taint-flow graph hierarchy. 
 */
public class AnalyzeMeLevel2 {
	
	public AnalyzeMeLevel2() { }
	
	/// Start: Taint-flow elements definition.

	public int getSecret() { return 42; }
	public void publish(int number) { System.out.print(number); }  	
	public int sanatizer(int number) { return number = 0; }
	public int propogator(int number) { return number; }
	
	/// End: Taint-flow elements definition.
	
	public void indirectNoIssue(int number) {
		number = 10;
		publish(number);
	}
	
	public void indirectIssue(int number) {
		publish(number);
	}
	
	public void indirectSanitizerNoIssue(int number) {
		number = sanatizer(number);
		publish(number);
	}
	
	public void indirectSanitizerPropogatorIssue(int number) {
		number = sanatizer(number);
		number = propogator(number);
		publish(number);
	}
}
