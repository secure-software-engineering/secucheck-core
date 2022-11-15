package de.fraunhofer.iem.secucheck.analysis.query;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of TaintFlow
 */
public final class TaintFlowImpl implements TaintFlow {

    private final List<MethodImpl> froms;
    private final List<MethodImpl> tos;
    private final List<MethodImpl> notThroughs;
    private final List<MethodImpl> throughs;

    public TaintFlowImpl() {
        this.froms = new ArrayList<MethodImpl>();
        this.tos = new ArrayList<MethodImpl>();
        this.notThroughs = new ArrayList<MethodImpl>();
        this.throughs = new ArrayList<MethodImpl>();
    }

    @Override
    public List<MethodImpl> getFrom() {
        return this.froms;
    }

    @Override
    public List<MethodImpl> getTo() {
        return this.tos;
    }

    @Override
    public List<MethodImpl> getNotThrough() {
        return this.notThroughs;
    }

    @Override
    public List<MethodImpl> getThrough() {
        return this.throughs;
    }

    public void addFrom(MethodImpl from) {
        this.froms.add(from);
    }

    public void addTo(MethodImpl to) {
        this.tos.add(to);
    }

    public void addNotThrough(MethodImpl through) {
        this.notThroughs.add(through);
    }

    public void addThrough(MethodImpl notThrough) {
        this.throughs.add(notThrough);
    }

}
