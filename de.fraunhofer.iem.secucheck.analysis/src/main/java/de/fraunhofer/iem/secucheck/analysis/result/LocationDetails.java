package de.fraunhofer.iem.secucheck.analysis.result;

public class LocationDetails {
	private String className;
	private String methodSignature;
	private int lineNumber;
	private LocationType type;
	
	public LocationDetails() { }
	
	public String getClassName() { return className; }
	public int getLineNumber() { return lineNumber; }
	public String getMethodSignature() { return methodSignature; }
	public LocationType getType() { return type; }
	public void setClassName(String className) { this.className = className; }
	public void setLineNumber(int lineNumber) { this.lineNumber = lineNumber; }
	public void setMethodSignature(String methodSignature) { this.methodSignature = methodSignature;	}
	public void setType(LocationType type) { this.type = type; }
}
