package de.fraunhofer.iem.secucheck.analysis.query;

public interface Parameter extends Input, Output {
	int getNumber();
	void setNumber(int value);
}
