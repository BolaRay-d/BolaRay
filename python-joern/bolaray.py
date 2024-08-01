import warnings
import argparse

from Analysis import Analysis


def print_result(result, set_of_type, newline=True):
    set_of_type.add(type(result))
    if list == type(result):
        for x in result:
            print_result(x, set_of_type, newline)
    elif dict == type(result):
        for k, v in result.items():
            print_result(k, set_of_type, False)
            print(":"),
            print_result(v, set_of_type, False)
            if newline:
                print("")
            else:
                print(""),
    elif str == type(result):
        if newline:
            print(result.encode('utf-8'))
        else:
            print(result.encode('utf-8')),
    elif set == type(result):
        for x in result:
            print_result(x, set_of_type, newline)
    elif str(type(result)) == "<class 'py2neo.core.Node'>":
        if newline:
            print(result)
        else:
            print(result),
    elif str(type(result)) == "<type 'unicode'>":
        if newline:
            print(result.encode('utf-8'))
        else:
            print(result.encode('utf-8')),
    else:
        if newline:
            print(result)
        else:
            print(result),


def main():
    warnings.filterwarnings("ignore", category=UserWarning)

    parser = argparse.ArgumentParser(description="BolaRay")
    parser.add_argument('--dal-specifications', required=True, help='Path to the dal specifications file')

    args = parser.parse_args()

    dal_specifications = args.dal_specifications

    with open(dal_specifications, 'r') as f:
        query_args = f.read()

    sa = Analysis(7474)

    query = query_args + """
        long startTime = System.nanoTime()
        def sql_query_funcs = ["mysql_query", "mysqli_query", "pg_query", "sqlite_query"]
        def sql_fetch_funcs = ["mysql_fetch_row", "mysql_fetch_array", "mysqli_fetch_row", "mysqli_fetch_array", "pg_fetch_array", "sqlite_fetch_array", "mysql_fetch_assoc"]
        def sql_prepare_funcs = ["prepare"]
        def sql_bind_funcs = ["bindParam"]
        def sql_execute_funcs = ["execute"]
        def sql_insert_id_funcs = ["mysql_insert_id", "mysqli_insert_id"]
        def sql_num_rows_funcs = ["mysql_num_rows", "mysql_numrows", "mysqli_num_rows", "pg_num_rows", "sqlite_num_rows"]
        def sources = ["\$_GET", "\$_POST", "\$_COOKIE", "\$_REQUEST", "\$_ENV", "\$HTTP_ENV_VARS", "\$HTTP_POST_VARS", "\$HTTP_GET_VARS"]
        def equal_funcs = ["intval", "trim", "strtoupper", "strtolower", "absint"]
        def exit_funcs = new HashSet<Vertex>()
        def header_statements = new HashSet<Vertex>()
        def exit_blocks = new HashMap<Vertex, HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>>()
        def may_exit_blocks = new HashMap<Vertex, HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>>()
        def repairs = ["md5", "0", "addslashes", "0", "mysqli_real_escape_string", "1", "mysql_escape_string", "0", "mysql_real_escape_string", "0", "htmlspecialchars", "0", "stripslashes", "0", "strip_tags", "0"]
        def table_prefix = ["\$DBPrefix", "\$wpdb->base_prefix", "\$wpdb->prefix", "\$wpdb->", "\$prefix"]
        def table_prefix_func = ["prefix"]
        def table_prefix_array = ["\$CFG_TABLE"]
        def excludeDirs = ["vendor", "install", "installation"]
        def excludeFiles = ["schema.php"]
        def dal_sql_query_funcs = ["direct_query"]
        def dal_sql_fetch_funcs = ["fetch"]
        def dal_sql_prepare_funcs = []
        def dal_sql_bind_funcs = ["query"]
        def dal_sql_execute_funcs = ["queryPrepared"]
        def dal_sql_insert_id_funcs = ["lastInsertId"]
        def dal_sql_num_rows_funcs = ["numrows"]
        def dalQueryNodes = new HashSet<Vertex>()
        def hasCodeNodes = g.V().filter{it && it.code}.toList()
        def hasTypeNodes = g.V().filter{it && it.type && (it.type == "AST_EXIT" || it.type == "AST_METHOD_CALL" || it.type == "AST_CALL" || it.type == "AST_STATIC_CALL" || it.type == "AST_ASSIGN")}.toList()
        def skip_func = new HashSet<String>()
        skip_func.addAll(sql_query_funcs)
        skip_func.addAll(sql_fetch_funcs)
        skip_func.addAll(sql_prepare_funcs)
        skip_func.addAll(sql_bind_funcs)
        skip_func.addAll(sql_execute_funcs)
        skip_func.addAll(sql_insert_id_funcs)
        skip_func.addAll(equal_funcs)
        skip_func.addAll(repairs)
        skip_func.addAll(dal_sql_query_funcs)
        skip_func.addAll(dal_sql_fetch_funcs)
        skip_func.addAll(dal_sql_bind_funcs)
        skip_func.addAll(dal_sql_execute_funcs)
        skip_func.addAll(dal_sql_insert_id_funcs)
        skip_func.addAll(dal_sql_num_rows_funcs)
        def skipWPFunc = new HashSet<String>()
        def queryIndex = new HashMap<String, Integer>()
        def fetchIndex = new HashMap<String, Integer>()
        def dalFetchColumn = new HashMap<String, Integer>()
        def sanitizations = new HashMap<String, Integer>()
        for (int i = 0; i < repairs.size(); i += 2) {
            sanitizations.put(repairs.get(i), Integer.parseInt(repairs.get(i+1)))
        }

        QueryProcessing.tables = new HashMap<String, ArrayList<ColDef>>()
        QueryProcessing.querys = new ArrayList<QueryInfo>()
        QueryProcessing.tableRelations = new HashMap<String, HashSet<String>>()

        def sensitiveColumn = new HashSet<String>()
        def sql_querys = []
        def ret = []
        def statisticRet = []
        def parseRet = []
        def exitRet = []
        def valTableRet = []
        def valDefTableRet = []
        def sessionRet = []
        def useValueRet = []
        def defPathRet = []
        def userTables = new HashMap<String, HashSet<String>>()
        def primaryKeys = new HashSet<String>()
        def PrimaryKeysMap = new HashMap<String, String>()
        def sessionTables = new HashSet<String>()
        def statusColumns = new HashSet<String>()
        def updateColumns = new HashSet<String>()
        def condTableColumnsMap = new HashMap<String, HashSet<String>>()
        def condTableColumns = new HashSet<String>()
        def selectTableColumnsView = new HashMap<String, HashSet<String>>()
        def selectCondColumns = new HashSet<String>()
        def adminCondColumns = new HashMap<String, HashSet<String>>()
        def condColumnsMap = new HashMap<Vertex, HashMap<String, HashSet<String>>>()
        def condStringsMap = new HashMap<String, String>()
        def sql_source_map = new HashMap<Vertex, ArrayList<String>>()
        def callerDTableMaps = new HashMap<Vertex, String>()
        def dynamicTableNodeMaps = new HashMap<Vertex, HashSet<String>>()
        def valTableColumnMap = new HashMap<String, AbstractMap.SimpleEntry<Vertex, ArrayList<String>>>()
        def valTableColumnQueue = new LinkedList<String>()
        def valDefTableColumnMap = new HashMap<String, AbstractMap.SimpleEntry<Vertex, HashSet<String>>>()
        def valDefTableColumnQueue = new LinkedList<String>()
        def sessionMap = new HashMap<String, AbstractMap.SimpleEntry<Vertex, HashSet<String>>>()
        def sessionQueue = new LinkedList<String>()
        def sqlNumRowsMap = new HashMap<String, HashSet<Integer>>()
        def queryCondMap = new HashMap<String, HashSet<String>>()
        def columnValUseMap = new HashMap<String, HashSet<AbstractMap.SimpleEntry<String, String>>>()
        def foreignKeyRelations = new HashMap<String, HashSet<String>>()
        def ownTables = new HashMap<String, HashSet<String>>()
        def userOwnTables = new HashMap<String, HashMap<String, HashSet<String>>>()
        def oneToOne = new HashMap<String, HashSet<String>>()
        def userOneToOne = new HashMap<String, HashMap<String, HashSet<String>>>()
        def oneToMany = new HashMap<String, HashMap<String, HashSet<String>>>()
        def userMany = new HashMap<String, ArrayList<AbstractMap.SimpleEntry<String, String>>>()
        def userUserMany = new HashMap<String, HashMap<String, ArrayList<AbstractMap.SimpleEntry<String, String>>>>()
        def manyToMany = new HashMap<String, HashSet<AbstractMap.SimpleEntry<String, String>>>()
        def potentialManyToMany = new HashMap<String, HashSet<AbstractMap.SimpleEntry<String, String>>>()
        def manyToManyTables = manyToMany.keySet()
        def manyToManyToRm = []
        def middleTables = []
        def middleTablesToRm = []
        def oneToManyRm = []
        def allTables = []
        def userTablesToRm = []
        def statusColumnsToRm = []
        def sensitive_sql_index = []
        def useValue_sql_index = []
        def combine_sql_index = []
        def combineNodeMap = new HashMap<String, HashSet<Vertex>>()
        def vulnerableResult = new ArrayList<AbstractMap.SimpleEntry<String, ArrayList<String>>>()
        def nodes = []
        def funcsOfNodes = []
        def defPaths = new HashMap<String, HashSet<AbstractMap.SimpleEntry<String,AbstractMap.SimpleEntry<Vertex,String>>>>()
        def path_records = new HashMap<AbstractMap.SimpleEntry<Vertex, Vertex>, ArrayList<Object>>()
        def valPathsMap = new HashMap<String, HashSet<ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>>>()
        def timeRecord = []
        def insertUserReltatedTables = new HashSet<String>()
        def sqlRecord = []
        def files = new HashSet<String>()
        def llineo = 0
        def tableNums = 0
        def columnNums = 0
        def selectOriginNums = 0
        def insertOriginNums = 0
        def deleteOriginNums = 0
        def updateOriginNums = 0
        def userTableNums = 0
        def foreignKeyNums = 0
        def oneToOneNums = 0
        def oneToManyNums = 0
        def manyToManyNums = 0
        def statusColumnNums = 0
        def adminCondColumnNums = 0
        def ownershipModels = new HashSet<String>()
        def membershipModels = new HashSet<String>()
        def hierarchicalModels = new HashMap<String, HashSet<String>>()
        def statusModels = new HashSet<String>()

        parseQuery(create_table_items, hasCodeNodes, hasTypeNodes, sql_prepare_funcs, sql_bind_funcs, sql_execute_funcs, queryIndex, sanitizations, nodes, funcsOfNodes, sql_querys, combine_sql_index, combineNodeMap, table_prefix, table_prefix_func, table_prefix_array, excludeDirs, excludeFiles, callerDTableMaps, dynamicTableNodeMaps, isWP, isDAL, dal_sql_query_funcs, dal_sql_fetch_funcs, dal_sql_bind_funcs, dal_sql_execute_funcs, parseRet)

        getColumnMap(nodes, funcsOfNodes, sql_querys, userTables, primaryKeys, PrimaryKeysMap, sessionTables, statusColumns, updateColumns, condTableColumnsMap, condTableColumns, sensitive_sql_index, useValue_sql_index, sql_fetch_funcs, sql_insert_id_funcs, sql_num_rows_funcs, isWP, isDAL, dal_sql_query_funcs, dal_sql_fetch_funcs, dalFetchColumn, dal_sql_insert_id_funcs, dal_sql_num_rows_funcs, dalQueryNodes, valTableColumnMap, valTableColumnQueue, valDefTableColumnMap, valDefTableColumnQueue, sqlNumRowsMap, sql_source_map, parseRet)

        ret.add("*************************************parseRet***************************")
        ret.add(parseRet)

        System.out.println("***************************************** valTableColumnQueue")
        ret.add("***************************************** valTableColumnQueue")

        transValTableColumn(valTableColumnQueue, valTableColumnMap, sessionTables, sanitizations, nodes, sql_fetch_funcs, equal_funcs, fetchIndex, queryIndex, sql_prepare_funcs, isWP, skipWPFunc, isDAL, dal_sql_query_funcs, selectCondColumns, selectTableColumnsView, condTableColumnsMap, condTableColumns, callerDTableMaps, dynamicTableNodeMaps, valTableRet)

        ret.add("*************************************valTableRet***************************")
        ret.add(valTableRet)

        System.out.println("***************************************** valDefTableColumnQueue")
        ret.add("***************************************** valDefTableColumnQueue")
        transValDefTableColumn(valDefTableColumnQueue, valDefTableColumnMap, sessionTables, sanitizations, nodes, sql_fetch_funcs, equal_funcs, fetchIndex, queryIndex, sql_prepare_funcs, isWP, skipWPFunc, isDAL, dal_sql_query_funcs, valTableColumnMap, callerDTableMaps, dynamicTableNodeMaps, valDefTableRet)

        ret.add("*************************************valDefTableRet***************************")
        ret.add(valDefTableRet)

        if (userTables.size() > 1) {
            for (userTable in userTables.keySet()) {
                if (!sessionTables.contains(userTable) && !userTable.toUpperCase().contains("USER")) {
                    userTablesToRm.add(userTable)
                }
            }
        }

        for (userTable in userTablesToRm) {
            userTables.remove(userTable)
        }

        parseSession(nodes, hasCodeNodes, sessionMap, sessionQueue, valTableColumnMap, equal_funcs, queryIndex, isWP, isDAL, dal_sql_query_funcs, sanitizations, excludeDirs, excludeFiles, sessionRet)

        ret.add("*************************************sessionRet***************************")
        ret.add(sessionRet)

        System.out.println("***************************************** useValue")
        ret.add("***************************************** useValue")
        analyzeUseValue(nodes, sql_querys, combineNodeMap, userTables, PrimaryKeysMap, useValue_sql_index, valTableColumnMap, valDefTableColumnMap, sessionMap, queryCondMap, columnValUseMap, callerDTableMaps, dynamicTableNodeMaps, insertUserReltatedTables, useValueRet)

        findExit(exit_blocks, exit_funcs, header_statements, may_exit_blocks, hasTypeNodes, exitRet)

        ret.add("*************************************exitRet***************************")
        ret.add(exitRet)

        useValueRet.add("*************************************findManyToMany***************************")
        System.out.println("*****************************************findManyToMany**********************")

        for (int index = 0; index < nodes.size(); ++index) {
            if (useValue_sql_index[index]) {
                def query_info = QueryProcessing.querys.get(index)
                def node = nodes[index]
                System.out.println(sql_querys[index])
                if (query_info instanceof SelectInfo) {
                    SelectInfo selectInfo = (SelectInfo)query_info
                    def conditionCols = selectInfo.getConditionCols()
                    def conditionVals = selectInfo.getConditionVals()
                    def defNodes = []

                    def combineNodes = new HashSet<Vertex>()
                    if (combineNodeMap.containsKey(node.id)) {
                        combineNodes.addAll(combineNodeMap.get(node.id))
                    }
                    combineNodes.add(node)
                    for (combineNode in combineNodes) {
                        for (v in combineNode.in("REACHES")) {
                            defNodes.add(v)
                        }
                    }

                    findManyToMany(node, conditionCols, conditionVals, defNodes, valTableColumnMap, sql_querys[index], PrimaryKeysMap, queryCondMap, columnValUseMap, userTables, manyToMany, useValueRet)
                }
                else if (query_info instanceof DeleteInfo) {
                    DeleteInfo deleteInfo = (DeleteInfo) query_info
                    def table = deleteInfo.getTNames()[0]
                    if (userTables.containsKey(table)) {
                        findAdminCondColumns(node, sql_querys[index], valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, exit_funcs, header_statements, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, useValueRet)
                    }
                }
            }
        }

        useValueRet.add("*************************************findStatusColumns***************************")
        System.out.println("*****************************************findStatusColumns**********************")

        for (statusColumn in statusColumns) {
            if (!updateColumns.contains(statusColumn)) {
                statusColumnsToRm.add(statusColumn)
            }
            if (!condTableColumns.contains(statusColumn) && !selectCondColumns.contains(statusColumn)) {
                statusColumnsToRm.add(statusColumn)
            }
            if (adminCondColumns.containsKey(statusColumn)) {
                statusColumnsToRm.add(statusColumn)
            }
        }
        statusColumns.removeAll(statusColumnsToRm)

        ret.add("*************************************useValueRet***************************")
        ret.add(useValueRet)

        for (table in QueryProcessing.tables.keySet()) {
            def columns = QueryProcessing.tables.get(table)
            tableNums = tableNums + 1
            columnNums = columnNums + columns.size()
        }

        for (int index = 0; index < sql_querys.size(); ++index) {
            def isCombine = combine_sql_index[index]
            def sql_query = sql_querys[index]
            sqlRecord.add(index+" "+isCombine+" "+sql_query)
            if (!isCombine) {
                def upper = sql_query.toUpperCase()
                if (upper.startsWith("SELECT")) {
                    selectOriginNums = selectOriginNums + 1
                }
                else if (upper.startsWith("INSERT")) {
                    insertOriginNums = insertOriginNums + 1
                }
                else if (upper.startsWith("DELETE")) {
                    deleteOriginNums = deleteOriginNums + 1
                }
                else if (upper.startsWith("UPDATE")) {
                    updateOriginNums = updateOriginNums + 1
                }
            }
        }

        userTableNums = userTables.size()

        for (tableColumn in QueryProcessing.tableRelations.keySet()) {
            def table = tableColumn.substring(0, tableColumn.indexOf("."))
            def column = tableColumn.substring(tableColumn.indexOf(".")+1)
            if ((userTables.containsKey(table) && (userTables.get(table).contains(column)) ||
                (PrimaryKeysMap.containsKey(table) && (PrimaryKeysMap.get(table).equalsIgnoreCase(column) || column.endsWith("_uuid"))))
            ) {
                foreignKeyRelations.put(tableColumn, QueryProcessing.tableRelations.get(tableColumn))
                foreignKeyNums = foreignKeyNums + QueryProcessing.tableRelations.get(tableColumn).size()
            }
        }

        allTables = new ArrayList<>(QueryProcessing.tables.keySet())
        def size = allTables.size()
        for (int i = 0; i < size; ++i) {
            for (int j = i+1; j < size; ++j) {
                def table1s = []
                if (userTables.containsKey(allTables.get(i))) {
                    table1s.addAll(userTables.get(allTables.get(i)))
                }
                else {
                    table1s.addAll(PrimaryKeysMap.get(allTables.get(i)))
                }
                def table2s = []
                if (userTables.containsKey(allTables.get(j))) {
                    table2s.addAll(userTables.get(allTables.get(j)))
                }
                else {
                    table2s.addAll(PrimaryKeysMap.get(allTables.get(j)))
                }
                for (table1 in table1s) {
                    for (table2 in table2s) {
                        def tableColumn1 = allTables.get(i)+"."+table1
                        def tableColumn2 = allTables.get(j)+"."+table2
                        def table1Rels = []
                        def table2Rels = []
                        for (t in QueryProcessing.tableRelations.get(tableColumn1)) {
                            table1Rels.add(t.substring(0, t.indexOf(".")))
                        }
                        for (t in QueryProcessing.tableRelations.get(tableColumn2)) {
                            table2Rels.add(t.substring(0, t.indexOf(".")))
                        }
                        if (!table1Rels.contains(allTables.get(j)) && !table2Rels.contains(allTables.get(i))) {
                            def potentialMiddleTables = table1Rels.intersect(table2Rels)
                            if (potentialMiddleTables.size() > 0) {
                                ret.add("*****intersect*****")
                                ret.add(potentialMiddleTables)
                            }
                            for (t in potentialMiddleTables) {
                                if (t != allTables.get(i) && t != allTables.get(j)) {
                                    if (!potentialManyToMany.containsKey(allTables.get(i))) {
                                        potentialManyToMany.put(allTables.get(i), new HashSet<>())
                                    }
                                    potentialManyToMany.get(allTables.get(i)).add(new AbstractMap.SimpleEntry<String, String>(allTables.get(j), t))
                                    if (!potentialManyToMany.containsKey(allTables.get(j))) {
                                        potentialManyToMany.put(allTables.get(j), new HashSet<>())
                                    }
                                    potentialManyToMany.get(allTables.get(j)).add(new AbstractMap.SimpleEntry<String, String>(allTables.get(i), t))
                                    ret.add("*****potentialManyToMany*****")
                                    ret.add(tableColumn1+" "+t+" "+tableColumn2)
                                }
                            }
                        }
                        else {
                            if (table1Rels.contains(allTables.get(j))) {
                                ret.add("*****table1:"+tableColumn1+"*****")
                                ret.add("*****table1Rels*****")
                                ret.add(table1Rels)
                                ret.add("*****allTables.get(j)*****")
                                ret.add(allTables.get(j))
                            }
                            if (table2Rels.contains(allTables.get(i))) {
                                ret.add("*****table2:"+tableColumn2+"*****")
                                ret.add("*****table2Rels*****")
                                ret.add(table2Rels)
                                ret.add("*****allTables.get(i)*****")
                                ret.add(allTables.get(i))
                            }
                        }
                    }
                }
            }
        }

        for (table in allTables) {
            if (userTables.containsKey(table)) {
                continue
            }
            if (PrimaryKeysMap.containsKey(table) && PrimaryKeysMap.get(table).indexOf(',') == -1) {
                for (tableColumn in QueryProcessing.tableRelations.keySet()) {
                    if (tableColumn.startsWith(table + ".") && primaryKeys.contains(tableColumn)) {
                        def column = tableColumn.substring(tableColumn.indexOf(".")+1)
                        def keyManyTable = new HashMap<String, HashSet<String>>()
                        if (oneToMany.containsKey(table)) {
                            keyManyTable = oneToMany.get(table)
                        }
                        def manyTable = new HashSet<String>()
                        if (keyManyTable.containsKey(column)) {
                            manyTable = keyManyTable.get(column)
                        }
                        for (rel in QueryProcessing.tableRelations.get(tableColumn)) {
                            manyTable.add(rel)
                        }
                        keyManyTable.put(column, manyTable)
                        oneToMany.put(table, keyManyTable)
                    }
                }
            }
        }

        for (many1 in manyToManyTables) {
            def newEntrys = new HashSet<AbstractMap.SimpleEntry<String, String>>()
            def many1Table = many1.substring(0, many1.indexOf("."))
            ret.add("*****many1Table*****")
            ret.add(many1)
            for (entry in manyToMany.get(many1)) {
                def many2 = entry.getKey()
                def many2Table = many2.substring(0, many2.indexOf("."))
                def inPotentialManyToMany = false
                ret.add("*****many2Table*****")
                ret.add(many2)
                ret.add(entry.getValue())
                for (potentialEntry in potentialManyToMany.get(many1Table)) {
                    if (potentialEntry.getKey() == many2Table) {
                        inPotentialManyToMany = true
                        break
                    }
                }
                ret.add(inPotentialManyToMany)
                if (inPotentialManyToMany) {
                    def middle = entry.getValue()
                    def middleTable = middle.substring(0, middle.indexOf(" "))
                    if (!oneToMany.containsKey(middleTable) && !userTables.containsKey(middleTable)) {
                        if (middleTables.contains(middleTable) && middleTables.count(middleTable) > 1) {
                            ret.add(middleTable)
                            middleTablesToRm.add(middleTable)
                        }
                        else {
                            newEntrys.add(entry)
                            middleTables.add(middleTable)
                        }
                    }
                }
            }
            if (newEntrys.size() > 0) {
                manyToMany.put(many1, newEntrys)
            }
            else {
                manyToManyToRm.add(many1)
            }
        }

        for (middleTable in middleTablesToRm) {
            middleTables.remove(middleTable)
        }

        for (many1 in manyToMany.keySet()) {
            def newEntrys = new HashSet<AbstractMap.SimpleEntry<String, String>>()
            for (entry in manyToMany.get(many1)) {
                def middle = entry.getValue()
                def middleTable = middle.substring(0, middle.indexOf(" "))
                if (!middleTablesToRm.contains(middleTable)) {
                    newEntrys.add(entry)
                }
            }
            if (newEntrys.size() > 0) {
                manyToMany.put(many1, newEntrys)
            }
            else {
                manyToManyToRm.add(many1)
            }
        }

        for (many1 in manyToManyToRm) {
            manyToMany.remove(many1)
        }

        for (one in oneToMany.keySet()) {
            def keyManyTable = oneToMany.get(one)
            for (key in keyManyTable.keySet()) {
                def manyTables = new HashSet<String>()
                for (many in keyManyTable.get(key)) {
                    def manyTable = many.substring(0, many.indexOf("."))
                    if (!middleTables.contains(manyTable)) {
                        manyTables.add(many)
                    }
                }
                if (manyTables.size() > 0) {
                    keyManyTable.put(key, manyTables)
                    oneToMany.put(one, keyManyTable)
                }
                else {
                    oneToManyRm.add(one)
                }
            }
        }

        for (one in oneToManyRm) {
            oneToMany.remove(one)
        }

        for (userTable in userTables.keySet()) {
            for (userKey in userTables.get(userTable)) {
                def um = new ArrayList<AbstractMap.SimpleEntry<String, String>>()
                def oo = new HashSet<String>()
                def ot = new HashSet<String>()
                if (manyToMany.containsKey(userTable+"."+userKey)) {
                    for (entry in manyToMany.get(userTable+"."+userKey)) {
                        um.add(entry)
                    }
                }
                for (rel in QueryProcessing.tableRelations.get(userTable+"."+userKey)) {
                    def tableOfRel = rel.substring(0, rel.indexOf("."))
                    def columnOfRel = rel.substring(rel.indexOf(".")+1)
                    if (middleTables.contains(tableOfRel)) {
                        continue
                    }
                    if (PrimaryKeysMap.containsKey(tableOfRel) && (PrimaryKeysMap.get(tableOfRel).equalsIgnoreCase(columnOfRel) || QueryProcessing.isUniqueKey(tableOfRel, columnOfRel))
                            && PrimaryKeysMap.containsKey(userTable) && PrimaryKeysMap.get(userTable).equalsIgnoreCase(userKey)
                    ) {
                        if (oneToMany.containsKey(tableOfRel)) {
                            if (oneToMany.get(tableOfRel).containsKey(columnOfRel)) {
                                oneToMany.get(tableOfRel).get(columnOfRel).remove(userTable+"."+userKey)
                            }
                        }
                        oo.add(rel)
                    }
                    else {
                        if (!(PrimaryKeysMap.containsKey(tableOfRel) && PrimaryKeysMap.get(tableOfRel).equalsIgnoreCase(columnOfRel))) {
                            ot.add(rel)
                        }
                    }
                }
                if (um.size() > 0) {
                    userMany.put(userKey, um)
                }
                if (oo.size() > 0) {
                    oneToOne.put(userKey, oo)
                    oneToOneNums = oneToOneNums + oo.size()
                }
                if (ot.size() > 0) {
                    ownTables.put(userKey, ot)
                    oneToManyNums = oneToManyNums + ot.size()
                }
            }
            if (userMany.size() > 0) {
                userUserMany.put(userTable, userMany)
            }
            if (oneToOne.size() > 0) {
                userOneToOne.put(userTable, oneToOne)
            }
            if (ownTables.size() > 0) {
                userOwnTables.put(userTable, ownTables)
            }
            userMany = new HashMap<String, ArrayList<AbstractMap.SimpleEntry<String, String>>>()
            oneToOne = new HashMap<String, HashSet<String>>()
            ownTables = new HashMap<String, HashSet<String>>()
        }

        for (one in oneToMany.keySet()) {
            def keyManyTable = oneToMany.get(one)
            for (key in keyManyTable.keySet()) {
                oneToManyNums = oneToManyNums + keyManyTable.get(key).size()
            }
        }

        for (many1 in manyToMany.keySet()) {
            manyToManyNums = manyToManyNums + manyToMany.get(many1).size()
        }
        manyToManyNums = manyToManyNums/2

        statusColumnNums = statusColumns.size()

        adminCondColumnNums = adminCondColumns.size()

        long endTime = System.nanoTime()

        long duration = (endTime - startTime) / 1000000
        timeRecord.add("stage1: " + duration + " ms")

        collectModels(userTables, userOneToOne, userOwnTables, oneToMany, userUserMany, manyToMany, statusColumns, PrimaryKeysMap, ownershipModels, membershipModels, hierarchicalModels, statusModels)

        System.out.println("***************************************** checkPaths")
        ret.add("***************************************** checkPaths")

        for (int index = 0; index < nodes.size(); ++index) {
            if (useValue_sql_index[index]) {
                def query_info = QueryProcessing.querys.get(index)
                def node = nodes[index]
                def sql_query = sql_querys[index]
                def location = node.toFileAbs().next().name + ":" + node.lineno
                def checkSummary = new ArrayList<String>()

                if (query_info instanceof InsertInfo) {
                    defPathRet.add("***********************************")
                    defPathRet.add(sql_querys[index])
                    System.out.println("***********************************")
                    System.out.println(sql_querys[index])
                    def insertInfo = (InsertInfo) query_info
                    def table = insertInfo.getTNames()[0]
                    def colNames = insertInfo.getColNames()
                    def itemNames = insertInfo.getItemNames()

                    for (int i = 0; i < colNames.size(); ++i) {
                        if (i < itemNames.size()) {
                            def val = itemNames.get(i)
                            if (val.startsWith("\$")) {
                                if (isSensitiveSql(table, colNames.get(i), PrimaryKeysMap, userTables)) {
                                    defPathRet.add("***************************")
                                    defPathRet.add(location+" "+val)
                                    def instack = new HashSet<String>()
                                    def combineNodes = new HashSet<Vertex>()
                                    if (combineNodeMap.containsKey(node.id)) {
                                        combineNodes.addAll(combineNodeMap.get(node.id))
                                    }
                                    combineNodes.add(node)
                                    for (combineNode in combineNodes) {
                                        getDefPathsForVal(combineNode, nodes, val, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, defPathRet)
                                    }
                                    if (defPaths.containsKey(location+" "+val) && defPaths.get(location+" "+val).size() == 0) {
                                        def defVals = new HashSet<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
                                        for (combineNode in combineNodes) {
                                            if (node != combineNode) {
                                                def combineLocation = combineNode.toFileAbs().next().name + ":" + combineNode.lineno
                                                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(combineLocation+" "+val, new AbstractMap.SimpleEntry<Vertex, String>(combineNode, "equal")))
                                            }
                                        }
                                        defPaths.put(location+" "+val, defVals)
                                    }
                                    def paths = new HashSet<ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>>()
                                    def visited = new HashSet<String>()
                                    def valPath = new ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
                                    valPath.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location+" "+val, new AbstractMap.SimpleEntry<Vertex, String>(node, "sink")))
                                    constructDefPaths(location+" "+val, defPaths, valPath, paths, valPathsMap, table, callerDTableMaps, visited)
                                    for (path in paths) {
                                        def sourceDefNodeFlag = path.get(path.size()-1)
                                        def sourceDef = sourceDefNodeFlag.getKey()
                                        def sourceNodeFlag = sourceDefNodeFlag.getValue()
                                        def sourceNode = sourceNodeFlag.getKey()
                                        def sourceFlag = sourceNodeFlag.getValue()
                                        def sourceVar = sourceDef.substring(sourceDef.indexOf(" ")+1)
                                        def isSource = false
                                        for (source in sources) {
                                            if (sourceVar.startsWith(source)) {
                                                isSource = true
                                                break
                                            }
                                        }
                                        if (isSource) {
                                            defPathRet.add("#######")
                                            defPathRet.add(path)
                                            checkSummary.add("source is "+getLocation(sourceNode))
                                            def condColumns = new HashMap<String, HashSet<String>>()
                                            defPathRet.add("*************************************findCondColumns start***************************")
                                            if (condColumnsMap.containsKey(sourceNode)) {
                                                condColumns = condColumnsMap.get(sourceNode)
                                            }
                                            else {
                                                findAdminCondColumns(sourceNode, sql_querys[index], valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, condColumns, condColumnsMap, exit_funcs, header_statements, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, defPathRet)
                                                condColumnsMap.put(sourceNode, condColumns)
                                            }
                                            defPathRet.add("**************condColumns**********")
                                            defPathRet.add(condColumns)
                                            defPathRet.add("*************************************findCondColumns end***************************")
                                            if (hasAdminCheck(condColumns, adminCondColumns)) {
                                                defPathRet.add("@@@@@@@@@@@@@@@@@@@@@@@@hasAdminCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                                checkSummary.add("@@@@@@@@@@@@@@@@@@@@@@@@hasAdminCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                                continue
                                            }
                                            defPathRet.add("******************************constructFlowPaths start******************************")
                                            constructFlowPaths(path, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, defPathRet)
                                            defPathRet.add("******************************constructFlowPaths end******************************")
                                            checkMOCForCol(node, sourceNode, path, table, colNames.get(i), userTables, userOneToOne, userOwnTables, oneToMany, middleTables, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                            if (!middleTables.contains(table) && !table.endsWith("meta")) {
                                                checkMSCForCol(node, sourceNode, path, table, colNames.get(i), statusColumns, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                            }
                                            checkMMCForCol(node, sourceNode, path, table, colNames.get(i), userTables, userOneToOne, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, defPathRet)
                                            checkMHCForCol(node, sourceNode, path, table, colNames.get(i), userTables, userOneToOne, userOwnTables, oneToMany, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, defPathRet)
                                        }
                                        else {
                                            defPathRet.add("#######")
                                            defPathRet.add(getLocation(sourceNode)+" "+sourceVar+" is not source")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else if (query_info instanceof DeleteInfo) {
                    defPathRet.add("***********************************")
                    defPathRet.add(sql_querys[index])
                    System.out.println("***********************************")
                    System.out.println(sql_querys[index])
                    def deleteInfo = (DeleteInfo) query_info
                    def table = deleteInfo.getTNames()[0]
                    def conditionCols = deleteInfo.getConditionCols()
                    def conditionVals = deleteInfo.getConditionVals()

                    for (int i = 0; i < conditionCols.size(); ++i) {
                        def val = conditionVals.get(i)
                        def vals = getAllValsInCond(val)
                        table = conditionCols.get(i).substring(0, conditionCols.get(i).indexOf("."))
                        def column = conditionCols.get(i).substring(conditionCols.get(i).indexOf(".")+1)
                        for (v in vals) {
                            if (v.startsWith("\$")) {
                                if (isSensitiveSql(table, column, PrimaryKeysMap, userTables)) {
                                    defPathRet.add("***************************")
                                    defPathRet.add(location+" "+v)
                                    def instack = new HashSet<String>()
                                    def combineNodes = new HashSet<Vertex>()
                                    if (combineNodeMap.containsKey(node.id)) {
                                        combineNodes.addAll(combineNodeMap.get(node.id))
                                    }
                                    combineNodes.add(node)
                                    for (combineNode in combineNodes) {
                                        getDefPathsForVal(combineNode, nodes, v, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, defPathRet)
                                    }
                                    if (defPaths.containsKey(location+" "+v) && defPaths.get(location+" "+v).size() == 0) {
                                        def defVals = new HashSet<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
                                        for (combineNode in combineNodes) {
                                            if (node != combineNode) {
                                                def combineLocation = combineNode.toFileAbs().next().name + ":" + combineNode.lineno
                                                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(combineLocation+" "+v, new AbstractMap.SimpleEntry<Vertex, String>(combineNode, "equal")))
                                            }
                                        }
                                        defPaths.put(location+" "+v, defVals)
                                    }
                                    def paths = new HashSet<ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>>()
                                    def visited = new HashSet<String>()
                                    def valPath = new ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
                                    valPath.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location+" "+v, new AbstractMap.SimpleEntry<Vertex, String>(node, "sink")))
                                    constructDefPaths(location+" "+v, defPaths, valPath, paths, valPathsMap, table, callerDTableMaps, visited)
                                    for (path in paths) {
                                        def sourceDefNodeFlag = path.get(path.size()-1)
                                        def sourceDef = sourceDefNodeFlag.getKey()
                                        def sourceNodeFlag = sourceDefNodeFlag.getValue()
                                        def sourceNode = sourceNodeFlag.getKey()
                                        def sourceFlag = sourceNodeFlag.getValue()
                                        def sourceVar = sourceDef.substring(sourceDef.indexOf(" ")+1)
                                        def isSource = false
                                        for (source in sources) {
                                            if (sourceVar.startsWith(source)) {
                                                isSource = true
                                                break
                                            }
                                        }
                                        if (isSource) {
                                            defPathRet.add("#######")
                                            defPathRet.add(path)
                                            checkSummary.add("source is "+getLocation(sourceNode))
                                            def condColumns = new HashMap<String, HashSet<String>>()
                                            defPathRet.add("*************************************findCondColumns start***************************")
                                            if (condColumnsMap.containsKey(sourceNode)) {
                                                condColumns = condColumnsMap.get(sourceNode)
                                            }
                                            else {
                                                findAdminCondColumns(sourceNode, sql_querys[index], valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, condColumns, condColumnsMap, exit_funcs, header_statements, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, defPathRet)
                                                condColumnsMap.put(sourceNode, condColumns)
                                            }
                                            defPathRet.add("**************condColumns**********")
                                            defPathRet.add(condColumns)
                                            defPathRet.add("*************************************findCondColumns end***************************")
                                            if (hasAdminCheck(condColumns, adminCondColumns)) {
                                                defPathRet.add("@@@@@@@@@@@@@@@@@@@@@@@@hasAdminCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                                checkSummary.add("@@@@@@@@@@@@@@@@@@@@@@@@hasAdminCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                                continue
                                            }
                                            defPathRet.add("******************************constructFlowPaths start******************************")
                                            constructFlowPaths(path, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, defPathRet)
                                            defPathRet.add("******************************constructFlowPaths end******************************")
                                            checkMOCForCond(node, sourceNode, path, table, column, userTables, userOneToOne, userOwnTables, oneToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                            checkMSCForCond(node, sourceNode, path, table, column, statusColumns, PrimaryKeysMap, valTableColumnMap, adminCondColumns, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, query_info, defPathRet)
                                            checkMMCForCond(node, sourceNode, path, table, column, userTables, userOneToOne, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                            checkMHCForCond(node, sourceNode, path, table, column, userTables, userOneToOne, userOwnTables, oneToMany, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                        }
                                        else {
                                            defPathRet.add("#######")
                                            defPathRet.add(getLocation(sourceNode)+" "+sourceVar+" is not source")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else if (query_info instanceof UpdateInfo) {
                    defPathRet.add("***********************************")
                    defPathRet.add(sql_querys[index])
                    System.out.println("***********************************")
                    System.out.println(sql_querys[index])
                    UpdateInfo updateInfo = (UpdateInfo) query_info
                    def table = updateInfo.getTNames()[0]
                    def colNames = updateInfo.getColNames()
                    def itemNames = updateInfo.getItemNames()
                    def conditionCols = updateInfo.getConditionCols()
                    def conditionVals = updateInfo.getConditionVals()

                    for (int i = 0; i < colNames.size(); ++i) {
                        if (i < itemNames.size()) {
                            def val = itemNames.get(i)
                            if (val.startsWith("\$")) {
                                if (isSensitiveSql(table, colNames.get(i), PrimaryKeysMap, userTables)) {
                                    defPathRet.add("***************************")
                                    defPathRet.add(location+" "+val)
                                    def instack = new HashSet<String>()
                                    def combineNodes = new HashSet<Vertex>()
                                    if (combineNodeMap.containsKey(node.id)) {
                                        combineNodes.addAll(combineNodeMap.get(node.id))
                                    }
                                    combineNodes.add(node)
                                    for (combineNode in combineNodes) {
                                        getDefPathsForVal(combineNode, nodes, val, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, defPathRet)
                                    }
                                    if (defPaths.containsKey(location+" "+val) && defPaths.get(location+" "+val).size() == 0) {
                                        def defVals = new HashSet<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
                                        for (combineNode in combineNodes) {
                                            if (node != combineNode) {
                                                def combineLocation = combineNode.toFileAbs().next().name + ":" + combineNode.lineno
                                                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(combineLocation+" "+val, new AbstractMap.SimpleEntry<Vertex, String>(combineNode, "equal")))
                                            }
                                        }
                                        defPaths.put(location+" "+val, defVals)
                                    }
                                    def paths = new HashSet<ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>>()
                                    def visited = new HashSet<String>()
                                    def valPath = new ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
                                    valPath.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location+" "+val, new AbstractMap.SimpleEntry<Vertex, String>(node, "sink")))
                                    constructDefPaths(location+" "+val, defPaths, valPath, paths, valPathsMap, table, callerDTableMaps, visited)
                                    for (path in paths) {
                                        def sourceDefNodeFlag = path.get(path.size()-1)
                                        def sourceDef = sourceDefNodeFlag.getKey()
                                        def sourceNodeFlag = sourceDefNodeFlag.getValue()
                                        def sourceNode = sourceNodeFlag.getKey()
                                        def sourceFlag = sourceNodeFlag.getValue()
                                        def sourceVar = sourceDef.substring(sourceDef.indexOf(" ")+1)
                                        def isSource = false
                                        for (source in sources) {
                                            if (sourceVar.startsWith(source)) {
                                                isSource = true
                                                break
                                            }
                                        }
                                        if (isSource) {
                                            defPathRet.add("#######")
                                            defPathRet.add(path)
                                            checkSummary.add("source is "+getLocation(sourceNode))
                                            def condColumns = new HashMap<String, HashSet<String>>()
                                            defPathRet.add("*************************************findCondColumns start***************************")
                                            if (condColumnsMap.containsKey(sourceNode)) {
                                                condColumns = condColumnsMap.get(sourceNode)
                                            }
                                            else {
                                                findAdminCondColumns(sourceNode, sql_querys[index], valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, condColumns, condColumnsMap, exit_funcs, header_statements, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, defPathRet)
                                                condColumnsMap.put(sourceNode, condColumns)
                                            }
                                            defPathRet.add("**************condColumns**********")
                                            defPathRet.add(condColumns)
                                            defPathRet.add("*************************************findCondColumns end***************************")
                                            if (hasAdminCheck(condColumns, adminCondColumns)) {
                                                defPathRet.add("@@@@@@@@@@@@@@@@@@@@@@@@hasAdminCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                                checkSummary.add("@@@@@@@@@@@@@@@@@@@@@@@@hasAdminCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                                continue
                                            }
                                            defPathRet.add("******************************constructFlowPaths start******************************")
                                            constructFlowPaths(path, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, defPathRet)
                                            defPathRet.add("******************************constructFlowPaths end******************************")
                                            checkMOCForCol(node, sourceNode, path, table, colNames.get(i), userTables, userOneToOne, userOwnTables, oneToMany, middleTables, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                            if (!middleTables.contains(table) && !table.endsWith("meta")) {
                                                checkMSCForCol(node, sourceNode, path, table, colNames.get(i), statusColumns, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                            }
                                            checkMMCForCol(node, sourceNode, path, table, colNames.get(i), userTables, userOneToOne, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, defPathRet)
                                            checkMHCForCol(node, sourceNode, path, table, colNames.get(i), userTables, userOneToOne, userOwnTables, oneToMany, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, defPathRet)
                                        }
                                        else {
                                            defPathRet.add("#######")
                                            defPathRet.add(getLocation(sourceNode)+" "+sourceVar+" is not source")
                                        }
                                    }
                                }
                            }
                        }
                    }

                    for (int i = 0; i < conditionCols.size(); ++i) {
                        def val = conditionVals.get(i)
                        def vals = getAllValsInCond(val)
                        table = conditionCols.get(i).substring(0, conditionCols.get(i).indexOf("."))
                        def column = conditionCols.get(i).substring(conditionCols.get(i).indexOf(".")+1)
                        for (v in vals) {
                            if (v.startsWith("\$")) {
                                if (isSensitiveSql(table, column, PrimaryKeysMap, userTables)) {
                                    defPathRet.add("***************************")
                                    defPathRet.add(location+" "+v)
                                    def instack = new HashSet<String>()
                                    def combineNodes = new HashSet<Vertex>()
                                    if (combineNodeMap.containsKey(node.id)) {
                                        combineNodes.addAll(combineNodeMap.get(node.id))
                                    }
                                    combineNodes.add(node)
                                    for (combineNode in combineNodes) {
                                        getDefPathsForVal(combineNode, nodes, v, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, defPathRet)
                                    }
                                    if (defPaths.containsKey(location+" "+v) && defPaths.get(location+" "+v).size() == 0) {
                                        def defVals = new HashSet<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
                                        for (combineNode in combineNodes) {
                                            if (node != combineNode) {
                                                def combineLocation = combineNode.toFileAbs().next().name + ":" + combineNode.lineno
                                                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(combineLocation+" "+v, new AbstractMap.SimpleEntry<Vertex, String>(combineNode, "equal")))
                                            }
                                        }
                                        defPaths.put(location+" "+v, defVals)
                                    }
                                    def paths = new HashSet<ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>>()
                                    def visited = new HashSet<String>()
                                    def valPath = new ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
                                    valPath.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location+" "+v, new AbstractMap.SimpleEntry<Vertex, String>(node, "sink")))
                                    constructDefPaths(location+" "+v, defPaths, valPath, paths, valPathsMap, table, callerDTableMaps, visited)
                                    for (path in paths) {
                                        def sourceDefNodeFlag = path.get(path.size()-1)
                                        def sourceDef = sourceDefNodeFlag.getKey()
                                        def sourceNodeFlag = sourceDefNodeFlag.getValue()
                                        def sourceNode = sourceNodeFlag.getKey()
                                        def sourceFlag = sourceNodeFlag.getValue()
                                        def sourceVar = sourceDef.substring(sourceDef.indexOf(" ")+1)
                                        def isSource = false
                                        for (source in sources) {
                                            if (sourceVar.startsWith(source)) {
                                                isSource = true
                                                break
                                            }
                                        }
                                        if (isSource) {
                                            defPathRet.add("#######")
                                            defPathRet.add(path)
                                            checkSummary.add("source is "+getLocation(sourceNode))
                                            def condColumns = new HashMap<String, HashSet<String>>()
                                            defPathRet.add("*************************************findCondColumns start***************************")
                                            if (condColumnsMap.containsKey(sourceNode)) {
                                                condColumns = condColumnsMap.get(sourceNode)
                                            }
                                            else {
                                                findAdminCondColumns(sourceNode, sql_querys[index], valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, condColumns, condColumnsMap, exit_funcs, header_statements, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, defPathRet)
                                                condColumnsMap.put(sourceNode, condColumns)
                                            }
                                            defPathRet.add("**************condColumns**********")
                                            defPathRet.add(condColumns)
                                            defPathRet.add("*************************************findCondColumns end***************************")
                                            if (hasAdminCheck(condColumns, adminCondColumns)) {
                                                defPathRet.add("@@@@@@@@@@@@@@@@@@@@@@@@hasAdminCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                                checkSummary.add("@@@@@@@@@@@@@@@@@@@@@@@@hasAdminCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                                                continue
                                            }
                                            defPathRet.add("******************************constructFlowPaths start******************************")
                                            constructFlowPaths(path, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, defPathRet)
                                            defPathRet.add("******************************constructFlowPaths end******************************")
                                            checkMOCForCond(node, sourceNode, path, table, column, userTables, userOneToOne, userOwnTables, oneToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                            checkMSCForCond(node, sourceNode, path, table, column, statusColumns, PrimaryKeysMap, valTableColumnMap, adminCondColumns, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, query_info, defPathRet)
                                            checkMMCForCond(node, sourceNode, path, table, column, userTables, userOneToOne, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                            checkMHCForCond(node, sourceNode, path, table, column, userTables, userOneToOne, userOwnTables, oneToMany, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, defPathRet)
                                        }
                                        else {
                                            defPathRet.add("#######")
                                            defPathRet.add(getLocation(sourceNode)+" "+sourceVar+" is not source")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                vulnerableResult.add(new AbstractMap.SimpleEntry<String, ArrayList<String>>(index+" "+combine_sql_index[index]+" "+sql_query, checkSummary))
            }
        }

        ret.add("*************************************defPathRet***************************")
        ret.add(defPathRet)
        System.out.println("*************************************defPathRet***************************")

        def allNodes = g.V().filter{it && it.type && it.type != ''}.toList()
        for (node in allNodes) {
            def file = getFlie(node)
            if (file != "") {
                files.add(file)
                if (isStatement(node)) {
                    llineo = llineo + 1
                }
            }
        }

        long end2Time = System.nanoTime()
        duration = (end2Time - endTime) / 1000000
        timeRecord.add("stage2: " + duration + " ms")

        statisticRet.add("*************************************userTables***************************")
        statisticRet.add(userTables)
        statisticRet.add("*************************************primaryKeys***************************")
        statisticRet.add(primaryKeys)
        statisticRet.add("*************************************PrimaryKeysMap***************************")
        statisticRet.add(PrimaryKeysMap)
        statisticRet.add("*************************************sessionTables***************************")
        statisticRet.add(sessionTables)
        statisticRet.add("*************************************adminCondColumns***************************")
        statisticRet.add(adminCondColumns)
        statisticRet.add("*************************************condColumnsMap*****************************")
        statisticRet.add(condColumnsMap)
        statisticRet.add("*************************************selectCondColumns*************************")
        statisticRet.add(selectCondColumns)
        statisticRet.add("*************************************condTableColumns***************************")
        statisticRet.add(condTableColumns)
        statisticRet.add("*************************************updateColumns***************************")
        statisticRet.add(updateColumns)
        statisticRet.add("*************************************statusColumnsToRm***************************")
        statisticRet.add(statusColumnsToRm)
        statisticRet.add("*************************************statusColumns***************************")
        statisticRet.add(statusColumns)
        statisticRet.add("*************************************userOwnTables***************************")
        statisticRet.add(userOwnTables)
        statisticRet.add("*************************************userOneToOne***************************")
        statisticRet.add(userOneToOne)
        statisticRet.add("*************************************oneToMany***************************")
        statisticRet.add(oneToMany)
        statisticRet.add("*************************************userUserMany***************************")
        statisticRet.add(userUserMany)
        statisticRet.add("*************************************manyToMany***************************")
        statisticRet.add(manyToMany)
        statisticRet.add("*************************************manyToManyToRm***************************")
        statisticRet.add(manyToManyToRm)
        statisticRet.add("*************************************potentialManyToMany***************************")
        statisticRet.add(potentialManyToMany)
        statisticRet.add("*************************************middleTables***************************")
        statisticRet.add(middleTables)
        statisticRet.add("*************************************middleTablesToRm***************************")
        statisticRet.add(middleTablesToRm)
        statisticRet.add("*************************************QueryProcessing.tableRelations***************************")
        statisticRet.add(QueryProcessing.tableRelations)
        statisticRet.add("*************************************foreignKeyRelations***************************")
        statisticRet.add(foreignKeyRelations)
        statisticRet.add("*************************************queryCondMap***************************")
        statisticRet.add(queryCondMap)
        statisticRet.add("*************************************columnValUseMap***************************")
        statisticRet.add(columnValUseMap)
        statisticRet.add("*************************************sqlNumRowsMap***************************")
        statisticRet.add(sqlNumRowsMap)
        statisticRet.add("*************************************callerDTableMaps***************************")
        statisticRet.add(callerDTableMaps)
        statisticRet.add("*************************************dynamicTableNodeMaps***************************")
        statisticRet.add(dynamicTableNodeMaps)
        statisticRet.add("*************************************defPaths***************************")
        statisticRet.add(defPaths)
        statisticRet.add("*************************************QueryProcessing.tables***************************")
        statisticRet.add(QueryProcessing.tables)
        statisticRet.add("*************************************QueryProcessing.querys***************************")
        statisticRet.add(QueryProcessing.querys)
        statisticRet.add("*************************************sql_querys***************************")
        statisticRet.add(sql_querys)
        statisticRet.add("*************************************sql_source_map***************************")
        statisticRet.add(sql_source_map)
        statisticRet.add("*************************************funcsOfNodes***************************")
        statisticRet.add(funcsOfNodes)
        statisticRet.add("*************************************vulnerableResult***************************")
        printVulnerableResult(vulnerableResult, ret)
        statisticRet.add("*************************************insertUserReltatedTables***************************")
        statisticRet.add(insertUserReltatedTables)
        statisticRet.add("*************************************selectTableColumnsView***************************")
        statisticRet.add(selectTableColumnsView)
        statisticRet.add("*************************************ownershipModels**********************************")
        statisticRet.add(ownershipModels)
        statisticRet.add("*************************************membershipModels***************************")
        statisticRet.add(membershipModels)
        statisticRet.add("*************************************hierarchicalModels***************************")
        statisticRet.add(hierarchicalModels)
        statisticRet.add("*************************************statusModels***************************")
        statisticRet.add(statusModels)
        statisticRet.add("*************************************timeRecord***************************")
        statisticRet.add(timeRecord)
        statisticRet.add("*************************************fileNum***************************")
        statisticRet.add(files.size())
        statisticRet.add("*************************************llineo***************************")
        statisticRet.add(llineo)
        statisticRet.add("*************************************tableNums***************************")
        statisticRet.add(tableNums)
        statisticRet.add("*************************************columnNums***************************")
        statisticRet.add(columnNums)
        statisticRet.add("*************************************selectOriginNums***************************")
        statisticRet.add(selectOriginNums)
        statisticRet.add("*************************************insertOriginNums***************************")
        statisticRet.add(insertOriginNums)
        statisticRet.add("*************************************deleteOriginNums***************************")
        statisticRet.add(deleteOriginNums)
        statisticRet.add("*************************************updateOriginNums***************************")
        statisticRet.add(updateOriginNums)
        statisticRet.add("*************************************userTableNums***************************")
        statisticRet.add(userTableNums)
        statisticRet.add("*************************************foreignKeyNums***************************")
        statisticRet.add(foreignKeyNums)
        statisticRet.add("*************************************oneToOneNums***************************")
        statisticRet.add(oneToOneNums)
        statisticRet.add("*************************************oneToManyNums***************************")
        statisticRet.add(oneToManyNums)
        statisticRet.add("*************************************manyToManyNums***************************")
        statisticRet.add(manyToManyNums)
        statisticRet.add("*************************************statusColumnNums***************************")
        statisticRet.add(statusColumnNums)
        statisticRet.add("*************************************adminCondColumnNums***************************")
        statisticRet.add(adminCondColumnNums)
        statisticRet.add("*************************************ownershipModelNums**********************************")
        statisticRet.add(ownershipModels.size())
        statisticRet.add("*************************************membershipModelNums***************************")
        statisticRet.add(membershipModels.size())
        statisticRet.add("*************************************hierarchicalModelNums***************************")
        statisticRet.add(getHierarchialModelNums(hierarchicalModels))
        statisticRet.add("*************************************statusModelNums***************************")
        statisticRet.add(statusModels.size())
        ret.add(statisticRet)
        ret
    """

    result, elapsed_time = sa.runTimedQuery(query)

    print_result(result, set())

    print("****************************************")
    print("elapsed_time: " + str(elapsed_time))


if __name__ == "__main__":
    main()
