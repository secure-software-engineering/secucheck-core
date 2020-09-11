package de.fraunhofer.iem.secucheck.analysis.result;

public class LocationDetails {
	
	private String sourceClassName;
	private String usageClassName;
	
	private String methodSignature;
	private String usageMethodSignature;
	
	private int usageLineNumber;
	private int usageColNumber;
	
	private LocationType type;
	
	public LocationDetails() { }
	
	public String getSourceClassName() { return sourceClassName; }
	public String getUsageClassName() { return usageClassName; }

	public String getMethodSignature() { return methodSignature; }
	public String getUsageMethodSignature() { return usageMethodSignature; }
	
	public LocationType getType() { return type; }
	
	public int getLineNumber() { return usageLineNumber; }
	public int ColumnNumber() { return usageColNumber; }
	
	
	public void setSourceClassName(String sourceClassName) { this.sourceClassName = sourceClassName; }
	public void setUsageClassName(String usageClassName) { this.usageClassName = usageClassName; }
	
	public void setMethodSignature(String methodSignature) { this.methodSignature = methodSignature; }
	public void setUsageMethodSignature(String usageMethodSignature) { this.usageMethodSignature = usageMethodSignature; }
	
	public void setType(LocationType type) { this.type = type; }
	
	public void setUsageLineNumber(int usageLineNumber) { this.usageLineNumber = usageLineNumber; }
	public void setUsageColumnNumber(int usageColNumber) { this.usageColNumber = usageColNumber; }
}