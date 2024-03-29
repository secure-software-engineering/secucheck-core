# What is secucheck-core?
This is the core taint analysis of the SecuCheck tool which can be found in [this repository](https://github.com/secure-software-engineering/secucheck/) which also contains further documentation. SecuCheck integrates two data-solvers: Boomerang 3.x, an implementation of SPDS and FlowDroid, an implementation of IFDS.

Boomerang 3.x is the default solver. Our tests are based on Boomerang 3.x. For WebGoat, the catalog, the demo-project and spring-petclinic and it finds all the TaintFlows.

## How to build secucheck-core manually?
- secucheck-core uses Boomerang DemandDriven analysis feature which is not yet realeased. Therefore, we need to build the Boomerang manually to the local maven before building SecuCheck. 
 
- Clone the Boomernag repository using the below command
```shell script
git clone https://github.com/CodeShield-Security/SPDS.git
```

- Change the branch to develop using the below command. Recently used boomerang commit to build SecuCheck is 361a6bc33f7e8311398532a5c444c9e9cc358b0d
```shell script
git checkout develop
```

- Build Boomerang using the below command
```shell script
mvn clean install -DskipTests
```

- Clone secuchek-core
```shell script
git clone https://github.com/secure-software-engineering/secucheck-core.git
```

- change path to root directory of secucheck-core project
```shell script
cd secucheck-core
```

- change the branch to SCC-1.1.0 or SCC-1.0.0
```shell script
git checkout SCC-1.1.0
```

- build the project 
```shell script
mvn clean install
```

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
