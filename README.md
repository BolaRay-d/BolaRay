# BolaRay

BolaRay is a prototype tool for the static detection of Broken Object-Level Authorization (BOLA) vulnerabilities in PHP database-backed applications.

This tool employs a combination of SQL and static analysis to automatically infer the distinct types of object-level authorization models, and subsequently verify whether existing implementations enforce appropriate checks for these models.

## Step 1

Generate the ASTs of the PHP files in the application using the tool [php2ast](./phpjoern/php2ast). This tool will output two CSV files, `nodes.csv` and `rels.csv`, representing the nodes of the generated ASTs and their relationships, respectively. In addition, directory and file nodes are also created and connected to the individual AST root nodes to reflect a scanned directory's structure and obtain a single large tree.

```bash
./php2ast /path/to/application
```

## Step 2

Generate code property graphs and call graphs for the ASTs using the tool [TChecker](./TChecker/phpast2cpg). This tool will read the CSV files generated in the previous step, analyze the ASTs, generate code property graphs and call graphs for them, and output the calculated edges in two CSV files, `cpg_edges.csv` and `call_graphs.csv`.

```bash
./phpast2cpg /path/to/nodes.csv /path/to/rels.csv
```

## Step 3

Import the code property graphs and call graphs into a [Neo4J database](./neo4j-community-2.1.8/data/) using the tool [batch-import](./batch-import/).

```bash
./batch-import/import.sh /path/to/nodes.csv /path/to/rels.csv /path/to/cpg_edges.csv /path/to/call_graphs.csv
```

## Step 4

Start the [Neo4J server](./neo4j-community-2.1.8/bin) and run the [BolaRay](./python-joern/bolaray.py) tool to detect Broken Object-Level Authorization (BOLA) vulnerabilities in the application.

```bash
./neo4j-community-2.1.8/bin/neo4j console
python2 ./python-joern/bolarray --dal-specifications=/path/to/dal-specifications
```