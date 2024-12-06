package de.fraunhofer.iem.secucheck.analysis.query;

public class ReportMessageWithCwe {
    private final String message;
    private final String cwe;

    public ReportMessageWithCwe(String message, String cwe) {
        this.cwe = cwe;
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public String getCwe() {
        return cwe;
    }
}
