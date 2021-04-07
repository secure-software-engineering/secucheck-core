# What is secucheck-core?
Secucheck-core is the taint analysis. Currently, it includes two solver, 
Boomerang 3.x and Flowdroid.

Boomerang 3.x tested for WebGoat, fluentTQL catalog and it finds the TaintFlows. Flowdroid is currently 
under development.

## secucheck-core structure
| Project | Description | can use in client side? |
| ------- | ----------- | ----------------------- |
| de.fraunhofer.iem.secucheck.analysis | Core analysis API to use secucheck-core analysis | Yes |
| de.fraunhofer.iem.secucheck.analysis.configuration | Lets the client configure secucheck-core analysis | Yes |
| de.fraunhofer.iem.secucheck.analysis.datastructure | used to represent the analysis results | Yes |
| de.fraunhofer.iem.secucheck.analysis.implementation | Implements the different solver (internal to secucheck-core) | No |
| de.fraunhofer.iem.secucheck.analysis.query | TaintFlow query independent of other TaintFlowQuery language | Yes | 
| de.fraunhofer.iem.secucheck.analysis.result | Taint analysis results classes | Yes | 
| de.fraunhofer.iem.secucheck.analysis.SingleFlowAnalysis | Interface for taint analysis for single taintflow specification | No

## Required maven dependency to use secucheck-core at client side.
- de.fraunhofer.iem.secucheck.analysis
```xml
<dependency>
    <groupId>de.fraunhofer.iem.secucheck</groupId>
    <version>0.0.1-SNAPSHOT</version>
    <artifactId>de.fraunhofer.iem.secucheck.analysis</artifactId>
</dependency>
```

- de.fraunhofer.iem.secucheck.analysis.configuration
```xml
<dependency>
    <groupId>de.fraunhofer.iem.secucheck</groupId>
    <artifactId>de.fraunhofer.iem.secucheck.analysis.configuration</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

- de.fraunhofer.iem.secucheck.analysis.result
```xml
<dependency>
    <groupId>de.fraunhofer.iem.secucheck</groupId>
    <artifactId>de.fraunhofer.iem.secucheck.analysis.result</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

- de.fraunhofer.iem.secucheck.analysis.query
```xml
<dependency>
    <groupId>de.fraunhofer.iem.secucheck</groupId>
    <artifactId>de.fraunhofer.iem.secucheck.analysis.query</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

- de.fraunhofer.iem.secucheck.analysis.datastructures
```xml
<dependency>
    <groupId>de.fraunhofer.iem.secucheck</groupId>
    <artifactId>de.fraunhofer.iem.secucheck.analysis.datastructures</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```