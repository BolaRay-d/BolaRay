# BolaRay

BolaRay is a prototype tool developed to statically detect Broken Object-Level Authorization (BOLA) vulnerabilities in PHP database-backed applications.

The tool combines SQL analysis with static code analysis to automatically infer and classify distinct object-level authorization models within an application. It then checks whether the application’s implementation properly enforces authorization for these models, identifying any potential vulnerabilities.

•	[STUDY.csv](./STUDY.csv): Collected vulnerability data from our study.

•	[appendix-hm.pdf](./appendix-hm.pdf): Detailed appendix for hierarchical models.

•	[appendix-study.pdf](./appendix-study.pdf): Detailed appendix for methodology and discussion of
study limitations.

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
python2 ./python-joern/bolaray --dal-specifications=/path/to/dal-specifications
```

## Citation

```
@inproceedings{BolaRay,
    title       = {Detecting Broken Object-Level Authorization Vulnerabilities in Database-Backed Applications},
    author      = {Yongheng Huang, Chenghang Shi, Jie Lu, Haofeng Li, Haining Meng and Lian Li},
    booktitle   = {Proceedings of the 31st ACM Conference on Computer and Communications Security (CCS)},
    month       = oct,
    year        = 2024
}
```