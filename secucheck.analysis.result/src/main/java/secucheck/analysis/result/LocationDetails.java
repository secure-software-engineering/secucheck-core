package secucheck.analysis.result;

/**
 * This class represents the Location details on the IDE
 */
public class LocationDetails {

    /**
     * This is the source/sink method's class name
     */
    private String sourceClassName;

    /**
     * This is the class name in which the taintflow is found
     */
    private String usageClassName;

    /**
     * Method signature of the source/sink method
     */
    private String methodSignature;

    /**
     * Method signature of the method in which the taintflow is found
     */
    private String usageMethodSignature;

    /**
     * Start line number of the taint flow
     */
    private int usageStartLineNumber;

    /**
     * End line number of the taint flow
     */
    private int usageEndLineNumber;

    /**
     * Start column number of the taint flow
     */
    private int usageStartColNumber;

    /**
     * End column number of the taint flow
     */
    private int usageEndColNumber;

    /**
     * Type of the location. SOURCE, SINK or SOURCEANDSINK
     */
    private LocationType type;

    public LocationDetails() {
    }

    public String getSourceClassName() {
        return sourceClassName;
    }

    public String getUsageClassName() {
        return usageClassName;
    }

    public String getMethodSignature() {
        return methodSignature;
    }

    public String getUsageMethodSignature() {
        return usageMethodSignature;
    }

    public LocationType getType() {
        return type;
    }

    public int getUsageStartLineNumber() {
        return usageStartLineNumber;
    }

    public int getUsageEndLineNumber() {
        return usageEndLineNumber;
    }

    public int getUsageStartColumnNumber() {
        return usageStartColNumber;
    }

    public int getUsageEndColumnNumber() {
        return usageEndColNumber;
    }

    public void setSourceClassName(String sourceClassName) {
        this.sourceClassName = sourceClassName;
    }

    public void setUsageClassName(String usageClassName) {
        this.usageClassName = usageClassName;
    }

    public void setMethodSignature(String methodSignature) {
        this.methodSignature = methodSignature;
    }

    public void setUsageMethodSignature(String usageMethodSignature) {
        this.usageMethodSignature = usageMethodSignature;
    }

    public void setType(LocationType type) {
        this.type = type;
    }

    public void setUsageStartLineNumber(int usageStartLineNumber) {
        this.usageStartLineNumber = usageStartLineNumber;
    }

    public void setUsageEndLineNumber(int usageEndLineNumber) {
        this.usageEndLineNumber = usageEndLineNumber;
    }

    public void setUsageStartColumnNumber(int usageStartColNumber) {
        this.usageStartColNumber = usageStartColNumber;
    }

    public void setUsageEndColumnNumber(int usageEndColNumber) {
        this.usageEndColNumber = usageEndColNumber;
    }
}