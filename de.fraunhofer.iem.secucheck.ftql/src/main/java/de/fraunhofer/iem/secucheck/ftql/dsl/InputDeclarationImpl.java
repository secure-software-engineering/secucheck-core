package de.fraunhofer.iem.secucheck.ftql.dsl;

import java.util.ArrayList;
import java.util.List;

import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.Input;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.InputDeclaration;
import de.fraunhofer.iem.secucheck.ftql.fluentInterface.io.ThisObject;

class InputDeclarationImpl implements InputDeclaration {
    private final List<Input> inputs = new ArrayList<>();

    public List<Input> getInputs() {
        return inputs;
    }

    public void addInput(Input input) {
        if (input instanceof ThisObjectImpl) {
            for (Input itr : inputs) {
                if (itr instanceof ThisObject)
                    return;
            }

            inputs.add(new ThisObjectImpl());
        } else {
            inputs.add(input);
        }
    }
}
