package de.fraunhofer.iem.secucheck.analysis.result;

public class LocationDetails {
	
	private String sourceClassName;
	private String usageClassName;
	
	private String methodSignature;
	private String usageMethodSignature;
	
	private int usageStartLineNumber;
	private int usageEndLineNumber;
	private int usageStartColNumber;
	private int usageEndColNumber;
	
	private LocationType type;
	
	public LocationDetails() { }
	
	public String getSourceClassName() { return sourceClassName; }
	public String getUsageClassName() { return usageClassName; }

	public String getMethodSignature() { return methodSignature; }
	public String getUsageMethodSignature() { return usageMethodSignature; }
	
	public LocationType getType() { return type; }
	
	public int getUsageStartLineNumber() { return usageStartLineNumber; }
	public int getUsageEndLineNumber() { return usageEndLineNumber; }
	public int getUsageStartColumnNumber() { return usageStartColNumber; }
	public int getUsageEndColumnNumber() { return usageEndColNumber; }
	
	public void setSourceClassName(String sourceClassName) { this.sourceClassName = sourceClassName; }
	public void setUsageClassName(String usageClassName) { this.usageClassName = usageClassName; }
	
	public void setMethodSignature(String methodSignature) { this.methodSignature = methodSignature; }
	public void setUsageMethodSignature(String usageMethodSignature) { this.usageMethodSignature = usageMethodSignature; }
	
	public void setType(LocationType type) { this.type = type; }
	
	public void setUsageStartLineNumber(int usageStartLineNumber) { this.usageStartLineNumber = usageStartLineNumber; }
	public void setUsageEndLineNumber(int usageEndLineNumber) { this.usageEndLineNumber = usageEndLineNumber; }
	public void setUsageStartColumnNumber(int usageStartColNumber) { this.usageStartColNumber = usageStartColNumber; }
	public void setUsageEndColumnNumber(int usageEndColNumber) { this.usageEndColNumber = usageEndColNumber; }
}