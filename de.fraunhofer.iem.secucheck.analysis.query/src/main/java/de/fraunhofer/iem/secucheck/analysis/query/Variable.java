package de.fraunhofer.iem.secucheck.analysis.query;

/**
 * Enumeration that can serve as source only for HARDCODED or NULL variables
 *
 * @author Enri Ozuni
 */
public enum Variable implements TaintFlowElement {
	HARDCODED,
	NULL
}
