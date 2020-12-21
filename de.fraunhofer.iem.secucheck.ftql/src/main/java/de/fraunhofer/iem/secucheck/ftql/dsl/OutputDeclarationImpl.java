package de.fraunhofer.iem.secucheck.ftql.dsl;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.Output;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.OutputDeclaration;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.ThisObject;

class OutputDeclarationImpl implements OutputDeclaration {
    private final List<Output> outputs = new ArrayList<>();

    public List<Output> getOutputs() {
        return outputs;
    }

    public void addOutput(Output output) {
        if (output instanceof ThisObjectImpl) {
            for (Output itr : outputs) {
                if (itr instanceof ThisObject)
                    return;
            }

            outputs.add(new ThisObjectImpl());
        } else if (output instanceof ReturnImpl) {
            for (Output itr : outputs) {
                if (itr instanceof ReturnImpl)
                    return;
            }

            outputs.add(new ReturnImpl());
        } else {
            outputs.add(output);
        }
    }
}
