
Gremlin.defineStep('containsLowSource', [Vertex, Pipe], {
    def attacker_sources2 = ["_GET", "_POST", "_COOKIE", "_REQUEST", "_ENV", "HTTP_ENV_VARS", "HTTP_POST_VARS", "HTTP_GET_VARS"]
    _().ifThenElse { isAssignment(it) }
    {
        it
                .as('assign')
                .as('assign')
                .rval()
                .children()
                .loop('assign') { it.object != null } { true }
                .match { it.type == "AST_VAR" }
                .filter { attacker_sources2.contains(it.varToName().next()) }
    }

    {
        it
                .astNodes()
                .match { it.type == 'AST_VAR' }
                .filter { attacker_sources2.contains(it.varToName().next()) }
                .in('PARENT_OF')
    }
            .dedup()


});

Gremlin.defineStep('containsSession', [Vertex, Pipe], {
    def attacker_sources2 = ["_SESSION"]
    _().ifThenElse { isAssignment(it) }
    {
        it
                .as('assign')
                .as('assign')
                .rval()
                .children()
                .loop('assign') { it.object != null } { true }
                .match { it.type == "AST_VAR" }
                .filter { attacker_sources2.contains(it.varToName().next()) }
    }

    {
        it
                .astNodes()
                .match { it.type == 'AST_VAR' }
                .filter { attacker_sources2.contains(it.varToName().next()) }
                .in('PARENT_OF')
    }
            .dedup()


})


def statementToString(Vertex node, HashSet<Boolean> start, HashMap<String, Integer> queryIndex, HashSet<String> funcs, HashMap<String, Integer> sanitizations) {
    def string = "";
    if (node.type == "NULL") {
        return string
    }
    if (node.type == "AST_VAR") {
        string = '$'+node.varToName().next();
        start.add(true)
    }
    else if (node.type == 'AST_DIM') {
        def v = ""
        if (node.ithChildren(1).type.next() == 'AST_CONST') {
            v = node.ithChildren(1).out.out.code.next()
        }
        else {
            v = statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        start.add(true)
        def prefix = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
        if (v.startsWith("\$")) {
            string = prefix
        }
        else {
            string = prefix + '[' + v + ']'
        }
    }
    else if (node.type == "AST_CONST") {
        string = node.out.out.code.next()
        start.add(true)
    }
    else if (node.type == "AST_ENCAPS_LIST") {
        def count = node.numChildren().next()
        for (int i = 0; i < count; ++i) {
            string += statementToString(node.ithChildren(i).next(), start, queryIndex, funcs, sanitizations)
        }
    }
    else if (node.type == "string") {
        if (node.code) {
            string = node.code
            if (string == "%" || string == "{%") {
                string = ""
            }
            start.add(true)
        }
    }
    else if (node.type == "integer") {
        if (node.code) {
            string = node.code
            start.add(true)
        }
    }
    else if (node.type == "AST_ASSIGN") {
        string = statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
    }
    else if (node.type == "AST_CALL" || node.type == "AST_STATIC_CALL") {
        def contain = start.contains(true)
        def className = ""
        if (node.type == "AST_STATIC_CALL") {
            className = getAllValName(node.ithChildren(0).next())
        }
        def name = getFuncName(node)
        if (node.type == "AST_CALL" && node.ithChildren(0).next().type == "AST_DIM") {
            name = getAllValName(node.ithChildren(0).next())
            System.out.println("########"+name)
        }
        def count = node.numArguments().next()
        funcs.add(name)
        if (name == "sprintf") {
            string = statementToString(node.ithArguments(0).next(), start, queryIndex, funcs, sanitizations)
            def indexOfPlaceholder = -1
            for (int i = 1; i < count; ++i) {
                def arg = statementToString(node.ithArguments(i).next(), start, queryIndex, funcs, sanitizations)
                indexOfPlaceholder = string.indexOf("%")
                if (indexOfPlaceholder != -1) {
                    string = string.substring(0, indexOfPlaceholder) + arg + string.substring(indexOfPlaceholder + 2)
                }
            }
        }
        else if (name == "implode" || name == "join" || name == "explode") {
            if (count == 2 || count == 3) {
                string = statementToString(node.ithArguments(1).next(), start, queryIndex, funcs, sanitizations)
            }
            else {
                string = name
            }
        }
        else if (name == "intval" || name == "trim" || name == "issetVal") {
            string = statementToString(node.ithArguments(0).next(), start, queryIndex, funcs, sanitizations)
        }
        else {
            if (contain) {
                if (sanitizations.containsKey(name)) {
                    def index = sanitizations.get(name)
                    if (index < count) {
                        def arg = statementToString(node.ithArguments(index).next(), start, queryIndex, funcs, sanitizations)
                        string = arg
                    }
                }
                else {
                    string = name + "("
                    for (int i = 0; i < count; ++i) {
                        def arg = statementToString(node.ithArguments(i).next(), start, queryIndex, funcs, sanitizations)
                        string += arg
                        if (i < count - 1) {
                            string += ","
                        }
                    }
                    string += ")"
                }
            }
            else {
                if (queryIndex.containsKey(name)) {
                    def index = queryIndex.get(name)
                    if (index < count) {
                        def arg = statementToString(node.ithArguments(index).next(), start, queryIndex, funcs, sanitizations)
                        string = arg
                    }
                }
                else {
                    for (int i = 0; i < count; ++i) {
                        def arg = statementToString(node.ithArguments(i).next(), start, queryIndex, funcs, sanitizations)
                        string += arg
                        if (i < count - 1) {
                            string += ","
                        }
                    }
                }
            }
        }
    }
    else if (node.type == "AST_METHOD_CALL") {
        def contain = start.contains(true)
        def count = node.numArguments().next()
        def name = getFuncName(node)
        def obj = getAllValName(node.ithChildren(0).next())
        funcs.add(name)
        if (contain) {
            if (sanitizations.containsKey(name)) {
                def index = sanitizations.get(name)
                if (index < count) {
                    def arg = statementToString(node.ithArguments(index).next(), start, queryIndex, funcs, sanitizations)
                    string = arg
                }
            }
            else {
                string = name + "("
                for (int i = 0; i < count; ++i) {
                    def arg = statementToString(node.ithArguments(i).next(), start, queryIndex, funcs, sanitizations)
                    string += arg
                    if (i < count - 1) {
                        string += ","
                    }
                }
                string += ")"
            }
        }
        else {
            if (queryIndex.containsKey(name)) {
                def index = queryIndex.get(name)
                if (index < count) {
                    def arg = statementToString(node.ithArguments(index).next(), start, queryIndex, funcs, sanitizations)
                    string = arg
                }
            }
            else {
                def firstChild = node.ithChildren(0).next()
                if (firstChild.type == "AST_METHOD_CALL") {
                    string = statementToString(firstChild, start, queryIndex, funcs, sanitizations)
                    if (string == "") {
                        for (int i = 0; i < count; ++i) {
                            def arg = statementToString(node.ithArguments(i).next(), start, queryIndex, funcs, sanitizations)
                            string += arg
                            if (i < count - 1) {
                                string += ","
                            }
                        }
                    }
                }
                else {
                    for (int i = 0; i < count; ++i) {
                        def arg = statementToString(node.ithArguments(i).next(), start, queryIndex, funcs, sanitizations)
                        string += arg
                        if (i < count - 1) {
                            string += ","
                        }
                    }
                }
            }
        }
    }
    else if (node.type == "AST_RETURN") {
        string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
    }
    else if (node.type == "AST_UNARY_OP" && node.flags != null) {
        if (node.flags.contains("UNARY_SILENCE")) {
            //string = "@"
            string += statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (node.flags.contains("UNARY_BOOL_NOT")) {
            string = "!"
            string += statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
        }
        else {
            string = node.flags.toString();
        }
    }
    else if (node.type == "AST_BINARY_OP" && node.flags != null) {
        if (node.flags.contains("BINARY_CONCAT")) {
            string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
            string += statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (node.flags.contains("BINARY_BOOL_OR")) {
            string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (node.flags.contains("BINARY_IS_EQUAL")) {
            string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
            string += "=="
            string += statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (node.flags.contains("BINARY_IS_NOT_EQUAL")) {
            string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
            string += "!="
            string += statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (node.flags.contains("BINARY_IS_IDENTICAL")) {
            string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
            string += "==="
            string += statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (node.flags.contains("BINARY_IS_NOT_IDENTICAL")) {
            string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
            string += "!=="
            string += statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (node.flags.contains("BINARY_SUB")) {
            string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
            string += "-"
            string += statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (node.flags.contains("BINARY_ADD")) {
            string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
            string += "+"
            string += statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (node.flags.contains("BINARY_BOOL_AND")) {
            string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
            string += " && "
            string += statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        else {
            string = node.flags.toString().replace("[", "").replace("]", "")
        }
    }
    else if (node.type == "AST_IF") {
        string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
    }
    else if (node.type == "AST_NAME") {
        string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
    }
    else if (node.type == "AST_CONDITIONAL") {
        def trueCond = statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        def falseCond = statementToString(node.ithChildren(2).next(), start, queryIndex, funcs, sanitizations)
        if (falseCond == "" && trueCond.startsWith("\$")) {
            string = trueCond
        }
        else {
            string = falseCond
        }
    }
    else if (node.type == "AST_PROP") {
        string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
        string += "->"
        string += statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
    }
    else if (node.type == "AST_CAST") {
        string = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
    }
    else if (node.type == "AST_IF_ELEM") {
        def child = node.ithChildren(0).next()
        if (child.type == "AST_BINARY_OP" && child.flags != null && child.flags.contains("BINARY_IS_EQUAL")) {
            def left = child.ithChildren(0).next()
            def right = child.ithChildren(1).next()
            if (left.type == "AST_CALL" || left.type == "AST_METHOD_CALL" || child.type == "AST_STATIC_CALL") {
                string = statementToString(left, start, queryIndex, funcs, sanitizations)
            }
            else if (right.type == "AST_CALL" || right.type == "AST_METHOD_CALL" || child.type == "AST_STATIC_CALL") {
                string = statementToString(right, start, queryIndex, funcs, sanitizations)
            }
            else {
                string = node.type
            }
        }
        else if (child.type == "AST_UNARY_OP" && child.flags != null && (child.flags.contains("UNARY_BOOL_NOT") || child.flags.contains("UNARY_SILENCE"))) {
            string = statementToString(child.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (child.type == "AST_ASSIGN") {
            string = statementToString(child.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        }
        else if (child.type == "AST_CALL" || child.type == "AST_METHOD_CALL" || child.type == "AST_STATIC_CALL") {
            string = statementToString(child, start, queryIndex, funcs, sanitizations)
        }
        else {
            string = node.type
        }
    }
    else if (node.type == "AST_PARAM") {
        string = '$'+statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
    }
    else if (node.type == "AST_ARRAY") {
        string = "array("
        def count = node.numChildren().next()
        for (int i = 0; i < count; ++i) {
            string += statementToString(node.ithChildren(i).next(), start, queryIndex, funcs, sanitizations)
            if (i < count - 1) {
                string += ","
            }
        }
        string += ")"
    }
    else if (node.type == "AST_ARRAY_ELEM") {
        def key = statementToString(node.ithChildren(1).next(), start, queryIndex, funcs, sanitizations)
        def value = statementToString(node.ithChildren(0).next(), start, queryIndex, funcs, sanitizations)
        if (value == "") {
            value = "''"
        }
        if (key != "") {
            string = key + "=>" + value
        }
        else {
            string = value
        }
    }
    else {
        string = node.type
    }

    return string
}

def patchSql(String sql, table_prefix, table_prefix_func, table_prefix_array) {
    for (prefix in table_prefix) {
        if (sql.contains(prefix)) {
            pattern = "'"+prefix+"'"
            sql = sql.replace(pattern, "")
            pattern = '"'+prefix+'"'
            sql = sql.replace(pattern, "")
            sql = sql.replace(prefix, "")
        }
    }
    for (prefix in table_prefix_func) {
        if (sql.contains(prefix+"(")) {
            sql = sql.replace(prefix+"(", "PREFIX(")
            sql = sql.replaceAll(/((PREFIX\()([^\)]+)(\)))/, '$3')
        }
    }
    for (prefix in table_prefix_array) {
        if (sql.contains(prefix+"[")) {
            sql = sql.replace(prefix+"[", "PREFIX[")
            sql = sql.replaceAll(/((PREFIX\[)([^\]]+)(\]))/, '$3')
        }
    }
    if (sql.startsWith("\\n")) {
        sql = sql.substring(2)
    }
    sql = sql.replaceAll(/(-- .*?\\n)/, ' ')
    sql = sql.replace("\\r", " ")
    sql = sql.replace("\\n", " ")
    if (!sql.endsWith(";") && sql.indexOf(";") == -1) {
        sql = sql+";"
    }
    if (sql.startsWith("@")) {
        sql = sql.substring(1)
    }
    sql = sql.replace("\t","    ")
    sql = sql.replaceAll(/(([^\s]+)(\s*<\s*)([^\s]+)(\s*<\s*)([^\s]+)(\s*))/, '$2$3$4 AND $4$5$6$7')
    sql = sql.replaceAll(/(\sLOW_PRIORITY\s)/, ' ')
    sql = sql.replaceAll(/(\sSQL_CALC_FOUND_ROWS\s)/, ' ')
    sql = sql.replaceAll(/(([^\w])increment([^\w]))/, '$2INCREMENT_TEMP$3')
    sql = sql.replaceAll(/(([^\w])public([^\w]))/, '$2PUBLIC_TEMP$3')
    sql = sql.replaceAll(/(([^\w])default([^\w]))/, '$2DEFAULT_TEMP$3')
    sql = sql.replaceAll(/(([^\w])binary([^\w]))/, '$2BINARY_TEMP$3')
    def index = sql.toUpperCase().indexOf(" LIMIT ");
    if (index != -1) {
        sql = sql.substring(0, index);
        sql = sql+";"
    }
    index = sql.toUpperCase().lastIndexOf("ORDER BY");
    if (index != -1) {
        sql = sql.substring(0, index);
        sql = sql+";"
    }
    index = sql.toUpperCase().indexOf("GROUP BY");
    if (index != -1) {
        sql = sql.substring(0, index);
        sql = sql+";"
    }
    sql = sql.replaceAll(/((,\s+)(INDEX[^\n]+\);))/,');')
    sql = sql.replaceAll(/(([^'"\/])(\$[\w]+\[[\w-]+\])([^'"\/]))/, '$2\"$3\"$4')
    sql = sql.replaceAll(/(([^'"\/])(\$[\w]+\[[\$\w-]+\]\[[\w-]+\])([^'"\/]))/, '$2\"$3\"$4')
    sql = sql.replaceAll(/(([^'"\/])(\%\$[\w]+\%)([^'"\/]))/, '$2\"$3\"$4')
    sql = sql.replaceAll(/(([^'"\/])((\$[\w]+->[\w]+\[[\w-]+\])( )(\$[\w]+->[\w]+\[[\w-]+\]))([^'"\/]))/, '$2\"$4\"$7')
    sql = sql.replaceAll(/(([^'"\/])((\$[\w]+->[\w]+\[[\w-]+\])(\[[\w-]+\]))([^'"\/]))/, '$2\"$4\"$6')
    sql = sql.replaceAll(/(([^'"\/])(\$[\w]+->[\w]+\[[\w-]+\])([^'"\/]))/, '$2\"$3\"$4')
    sql = sql.replaceAll(/(([^'"\/])(\$[\w]+->[\w]+\[[\$\w-]+\]\[[\w-]+\])([^'"\/]))/, '$2\"$3\"$4')
    sql = sql.replaceAll(/(([^'"\/])(\$[\w]+->[\w]+)([^'"\/]))/, '$2\"$3\"$4')
    def reg = /((=\s*[:\$\w\.\[\]\'\"\)]+\s*)(\$[\w]+)(\s*;))/
    def matcher = (sql =~ reg)
    matcher.each { match ->
        def ssn = match[3]
        System.out.println("rest value")
        System.out.println(ssn)
    }
    sql = sql.replaceAll(/((=\s*[:\$\w\.\[\]\'\"\)]+\s*)(\$[\w]+)(\s*;))/,'$2$4')
    return sql
}

def isStringLikeNode(node) {
    return (node.type == "string"
            || node.type == "AST_ENCAPS_LIST"
            || (node.type == "AST_BINARY_OP" && node.flags.contains("BINARY_CONCAT")))
}

def getAllDefValue(node, valueName, defValMap, sanitizations, visited, ret) {
    if (visited.contains(node)) {
        return
    }
    visited.add(node)
    def start = new HashSet<Boolean>()
    start.add(true)
    def defValMapClone = new HashMap<String, ArrayList<AbstractMap.SimpleEntry<Vertex, String>>>(defValMap)
    for (v in node.in("REACHES")) {
        System.out.println("####"+v)
        System.out.println("####"+getLocation(v))
        if (v.type == "AST_ASSIGN") {
            def assignName = getAllValName(v.ithChildren(0).next())
            assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
            if (assignName != "" && (valueName == "" || assignName == valueName)) {
                ret.add("assignName:  " +getLocation(v.ithChildren(0).next()) +"  " +assignName)
                def valueNode = v.ithChildren(1).next()
                if (isStringLikeNode(valueNode)) {
                    if (valueName == "") {
                        def value = statementToString(valueNode, start, new HashMap<>(), new HashSet<String>(), sanitizations)
                        if (!defValMap.containsKey(assignName)) {
                            defValMap.put(assignName, new ArrayList<AbstractMap.SimpleEntry<Vertex, String>>())
                        }
                        defValMap.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(v, value))
                        ret.add("valueNode:  " + getLocation(valueNode) + "  " + value)
                    }
                    else {
                        def value = statementToString(valueNode, start, new HashMap<>(), new HashSet<String>(), sanitizations)
                        def postValue = ""
                        if (defValMapClone.containsKey(assignName)) {
                            for (entry in defValMapClone.get(assignName)) {
                                postValue = entry.getValue()
                                break
                            }
                        }
                        if (postValue != "") {
                            value = value + postValue
                        }
                        if (!defValMap.containsKey(assignName)) {
                            defValMap.put(assignName, new ArrayList<AbstractMap.SimpleEntry<Vertex, String>>())
                        }
                        defValMap.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(v, value))
                        ret.add("valueNode_all:  " + getLocation(valueNode) + "  " + value)
                    }
                }
                else {
                    ret.add("other valueNode in getAllDefValue")
                    ret.add(getLocation(valueNode))
                }
            }
            else {
                ret.add("other assignName in getAllDefValue")
                ret.add(getLocation(v.ithChildren(0).next()))
            }
        }
        else if (v.type == "AST_ASSIGN_OP") {
            def assignName = getAllValName(v.ithChildren(0).next())
            assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
            if (assignName != "" && (valueName == "" || assignName == valueName)) {
                ret.add("assignName_op:  " + getLocation(v.ithChildren(0).next()) + "  " + assignName)
                def valueNode = v.ithChildren(1).next()
                if (isStringLikeNode(valueNode)) {
                    def value = statementToString(valueNode, start, new HashMap<>(), new HashSet<String>(), sanitizations)
                    def postValue = ""
                    if (defValMapClone.containsKey(assignName)) {
                        for (entry in defValMapClone.get(assignName)) {
                            postValue = entry.getValue()
                            break
                        }
                    }
                    if (postValue != "") {
                        value = value + postValue
                    }
                    def defValMapForASSIGNOP = new HashMap<String, ArrayList<AbstractMap.SimpleEntry<Vertex, String>>>()
                    if (!defValMapForASSIGNOP.containsKey(assignName)) {
                        defValMapForASSIGNOP.put(assignName, new ArrayList<AbstractMap.SimpleEntry<Vertex, String>>())
                    }
                    defValMapForASSIGNOP.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(v, value))
                    getAllDefValue(v, assignName, defValMapForASSIGNOP, sanitizations, new HashSet<>(visited), ret)
                    if (!defValMap.containsKey(assignName)) {
                        defValMap.put(assignName, new ArrayList<AbstractMap.SimpleEntry<Vertex, String>>())
                    }
                    def preValue = ""
                    for (elem in defValMapForASSIGNOP.get(assignName)) {
                        def vNode = elem.getKey()
                        if (vNode != v) {
                            preValue = elem.getValue()
                            defValMap.get(assignName).add(elem)
                        }
                    }
                    if (preValue != "") {
                        defValMap.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(v, preValue))
                        ret.add("valueNode_op_pre:  " + getLocation(valueNode) + "  " + preValue)
                    }
                    else {
                        defValMap.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(v, value))
                        ret.add("valueNode_op:  " + getLocation(valueNode) + "  " + value)
                    }
                }
                else {
                    ret.add("other valueNode_op in getAllDefValue")
                    ret.add(getLocation(valueNode))
                }
            }
            else {
                ret.add("other assignName_op in getAllDefValue")
                ret.add(getLocation(v.ithChildren(0).next()))
            }
        }
        else {
            ret.add("other v in getAllDefValue")
            ret.add(getLocation(v))
        }
    }
}

def getAllUseValue(node, valueName, useValMap, nodeUseValMap, sanitizations, visited, ret) {
    if (nodeUseValMap.containsKey(node)) {
        useValMap.putAll(nodeUseValMap.get(node))
        return
    }
    if (visited.contains(node)) {
        return
    }
    //System.out.println(getLocation(node))
    visited.add(node)
    def start = new HashSet<Boolean>()
    start.add(true)
    def useValMapClone = new HashMap<String, ArrayList<AbstractMap.SimpleEntry<Vertex, String>>>(useValMap)
    for (v in node.out("REACHES")) {
        if (v.type == "AST_ASSIGN_OP") {
            def assignName = getAllValName(v.ithChildren(0).next())
            assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
            if (assignName != "" && assignName == valueName) {
                ret.add("assignName_op_use:  " + getLocation(v.ithChildren(0).next()) + "  " + assignName)
                def valueNode = v.ithChildren(1).next()
                if (isStringLikeNode(valueNode)) {
                    def value = statementToString(valueNode, start, new HashMap<>(), new HashSet<String>(), sanitizations)
                    def preValue = ""
                    if (useValMapClone.containsKey(assignName)) {
                        for (entry in useValMapClone.get(assignName)) {
                            preValue = entry.getValue()
                            break
                        }
                    }
                    if (preValue != "") {
                        value = preValue + value
                    }
                    def useValMapForASSIGNOP = new HashMap<String, ArrayList<AbstractMap.SimpleEntry<Vertex, String>>>()
                    if (!useValMapForASSIGNOP.containsKey(assignName)) {
                        useValMapForASSIGNOP.put(assignName, new ArrayList<AbstractMap.SimpleEntry<Vertex, String>>())
                    }
                    useValMapForASSIGNOP.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(v, value))
                    getAllUseValue(v, assignName, useValMapForASSIGNOP, nodeUseValMap, sanitizations, new HashSet<>(visited), ret)
                    if (!useValMap.containsKey(assignName)) {
                        useValMap.put(assignName, new ArrayList<AbstractMap.SimpleEntry<Vertex, String>>())
                    }
                    def postValue = ""
                    for (elem in useValMapForASSIGNOP.get(assignName)) {
                        def vNode = elem.getKey()
                        if (vNode != v) {
                            postValue = elem.getValue()
                            useValMap.get(assignName).add(elem)
                        }
                    }
                    if (postValue != "") {
                        useValMap.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(v, postValue))
                        ret.add("valueNode_op_post:  " + getLocation(valueNode) + "  " + postValue)
                    }
                    else {
                        useValMap.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(v, value))
                        ret.add("valueNode_op_use:  " + getLocation(valueNode) + "  " + value)
                    }
                }
                else {
                    ret.add("other valueNode_op_use in getAllUseValue")
                    ret.add(getLocation(valueNode))
                }
            }
            else {
                ret.add("other assignName_op_use in getAllUseValue")
                ret.add(getLocation(v.ithChildren(0).next()))
            }
        }
        else {
            ret.add("other v in getAllUseValue")
            ret.add(getLocation(v))
        }
    }
    nodeUseValMap.put(node, useValMap)
}

def getAllArrayValue(node, array, defArrayMap, sanitizations, visited, ret) {
    if (visited.contains(node)) {
        return
    }
    visited.add(node)
    def start = new HashSet<Boolean>()
    start.add(true)
    def newArray = array
    for (v in node.in("REACHES")) {
        if (!defArrayMap.containsKey(v)) {
            if (v.type == "AST_ASSIGN" || v.type == "AST_ASSIGN_OP") {
                def assignName = getAllValName(v.ithChildren(0).next())
                def valueNode = v.ithChildren(1).next()
                if (assignName.startsWith(array + "[")) {
                    def column = assignName.substring(array.length() + 1, assignName.indexOf("]"))
                    def value = statementToString(valueNode, start, new HashMap<>(), new HashSet<String>(), sanitizations)
                    if (value == "") {
                        value = "''"
                    }
                    if (isCallExpression(valueNode)) {
                        value = value.replaceAll(/(([^'"\/])(\$[\w]+\[[\w]+\])([^'"\/]))/, '$2\'$3\'$4')
                        value = value.replaceAll(/(([^'"\/])(\%\$[\w]+\%)([^'"\/]))/, '$2\'$3\'$4')
                        value = value.replaceAll(/(([^'"\/])(\$[\w]+->[\w]+)([^'"\/]))/, '$2\'$3\'$4')
                        value = "\""+value+"\""
                    }
                    def columnValueList = new ArrayList<AbstractMap.SimpleEntry<String, String>>()
                    columnValueList.add(new AbstractMap.SimpleEntry<String, String>(column, value))
                    defArrayMap.put(v, columnValueList)
                }
                else if (assignName == array) {
                    if (valueNode.type == "AST_ARRAY") {
                        def columnValuesList = getColumnValuesFromArray(valueNode, sanitizations)
                        defArrayMap.put(v, columnValuesList)
                    }
                    else if (valueNode.type == "AST_CALL") {
                        def funcName = getFuncName(valueNode)
                        if (funcName == "compact") {
                            def columnValuesList = getColumnValuesFromCall(valueNode, sanitizations)
                            defArrayMap.put(v, columnValuesList)
                        }
                        else {
                            ret.add("other funcName "+funcName+" in getAllArrayValue")
                            ret.add(getLocation(valueNode))
                        }
                    }
                    else if (valueNode.type == "AST_VAR") {
                        newArray = getAllValName(valueNode)
                    }
                    else {
                        ret.add("other valueNode in getAllArrayValue")
                        ret.add(getLocation(valueNode))
                    }
                }
                getAllArrayValue(v, newArray, defArrayMap, sanitizations, visited, ret)
            }
        }
    }
}

def isSqlQueryFunc(ArrayList<String> sql_query_funcs, Vertex node) {
    if (!node.get_calls()) {
        return false;
    }
    Vertex caller = node.get_calls().next();
    if (caller == null) {
        return false;
    }
    if (sql_query_funcs.contains(getFuncName(caller))) {
        return true;
    }
    return false;
}

def isErrorFunc(HashSet<Vertex> exit_funcs, Vertex node) {
    if (!node.get_calls()) {
        return false
    }
    Vertex caller = node.get_calls().next()
    if (caller == null) {
        return false
    }
    for (Vertex func in caller.out("CALLS")) {
        if (exit_funcs.contains(func)) {
            return true
        }
    }
    return false
}

def getArrayIndex(node) {
    def index = "";
    if (node.type == 'AST_DIM') {
        if (node.ithChildren(1).type.next() == 'AST_CONST') {
            index = node.ithChildren(1).out.out.code.next();
        } else {
            index = node.ithChildren(1).code.next();
        }
    }
    return index
}

def getValName(node) {
    def valName = "";
    if (node.type == 'AST_VAR') {
        valName = node.varToName().next();
    } else if (node.type == 'AST_DIM') {
        valName = node.ithChildren(0).varToName.next();
    }
    return valName
}

def getNum(valName, ret) {
    def num = -1;
    try {
        num = Integer.parseInt(valName)
    } catch (Exception e) {
        if (valName == "false") {
            num = 0
        } else if (valName == "true") {
            num = 1
        } else {
            ret.add(valName + " is not a number")
        }
    }
    return num
}

def getAllValName(node) {
    def valName = ""
    if (node.type == "NULL") {
        return valName
    }
    if (node.type == 'AST_VAR') {
        valName = '$'+node.varToName().next()
    }
    else if (node.type == 'AST_DIM') {
        def index = getAllValName(node.ithChildren(1).next())
        if (index.startsWith("\$") && !isWithinForeach(node)) {
            valName = getAllValName(node.ithChildren(0).next())
        }
        else {
            valName = getAllValName(node.ithChildren(0).next()) + '[' + index + ']'
        }
    }
    else if (node.type == 'AST_CONST') {
        valName = node.out.out.code.next()
    }
    else if (node.type == "string") {
        if (node.code) {
            valName = node.code
            if (valName == "%" || valName == "{%") {
                valName = ""
            }
        }
    }
    else if (node.type == "integer") {
        if (node.code) {
            valName = node.code;
        }
    }
    else if (node.type == "AST_LIST") {
        valName = "["
        def count = node.numChildren().next()
        for (int i = 0; i < count; ++i) {
            valName += getAllValName(node.ithChildren(i).next())
            if (i < count-1) {
                valName += ","
            }
        }
        valName += "]"
    }
    else if (node.type == "AST_PARAM") {
        valName = '$'+getAllValName(node.ithChildren(1).next())
    }
    else if (node.type == "AST_RETURN") {
        valName = getAllValName(node.ithChildren(0).next())
    }
    else if (node.type == "AST_GLOBAL") {
        valName = getAllValName(node.ithChildren(0).next())
    }
    else if (node.type == "AST_CAST") {
        valName = getAllValName(node.ithChildren(0).next())
    }
    else if (node.type == "AST_ENCAPS_LIST") {
        def count = node.numChildren().next()
        for (int i = 0; i < count; ++i) {
            valName += getAllValName(node.ithChildren(i).next())
        }
    }
    else if (node.type == "AST_NAME") {
        valName = getAllValName(node.ithChildren(0).next())
    }
    else if (node.type == "AST_PROP") {
        valName = getAllValName(node.ithChildren(0).next())
        valName += "->"
        valName += getAllValName(node.ithChildren(1).next())
    }
    else if (node.type == "AST_UNARY_OP" && node.flags != null) {
        if (node.flags.contains("UNARY_BOOL_NOT") || node.flags.contains("UNARY_SILENCE")) {
            valName += getAllValName(node.ithChildren(0).next())
        }
        else {
            valName = node.flags.toString();
        }
    }
    else if (node.type == "AST_BINARY_OP" && node.flags != null) {
        if (node.flags.contains("BINARY_CONCAT")) {
            valName = getAllValName(node.ithChildren(0).next())
            valName += getAllValName(node.ithChildren(1).next())
        }
    }
    else if (node.type == "AST_ARRAY") {
        valName = "array("
        def count = node.numChildren().next()
        for (int i = 0; i < count; ++i) {
            valName += getAllValName(node.ithChildren(i).next())
            if (i < count - 1) {
                valName += ","
            }
        }
        valName += ")"
    }
    else if (node.type == "AST_ARRAY_ELEM") {
        def key = getAllValName(node.ithChildren(1).next())
        def value = getAllValName(node.ithChildren(0).next())
        if (value == "") {
            value = "''"
        }
        if (key != "") {
            valName = key + "=>" + value
        }
        else {
            valName = value
        }
    }
    else if (node.type == "AST_METHOD_CALL") {
        def obj = getAllValName(node.ithChildren(0).next())
        def func = getFuncName(node)
        if (func == "value") {
            def count = node.numArguments().next()
            if (count == 1) {
                def column = getAllValName(node.ithArguments(0).next())
                valName = obj + "[" + column + "]"
            }
        }
    }
    return valName
}

def getMapKey(key, sql_source_paths, sql_source_map) {
    mapKey = [];
    index = ""
    key = key.replace("\$", "")
    if (key.contains("[")) {
        index = key.substring(key.indexOf("[") + 1, key.indexOf("]"))
        key = key.substring(0, key.indexOf("["))
    }

    for (path in sql_source_paths) {
        len = path.size()
        if (len > 2) {
            query = path[len-1]
            if (sql_source_map.containsKey(query)) {
                sensitive_index = sql_source_map.get(query)
                if (path[1].var == key) {
                    for (int i = 0; i < sensitive_index.size(); i += 5) {
                        if (index == sensitive_index[i] || index == sensitive_index[i+2]) {
                            mapKey.add(sensitive_index[i+1]+"."+sensitive_index[i+2])
                        }
                    }
                    for (int i = 2; i < len; i += 2) {
                        node = path[i]
                        if (isAssignment(node)) {
                            index = getArrayIndex(node.rval().next())
                            for (int j = 0; j < sensitive_index.size(); j += 5) {
                                if (index == sensitive_index[j] || index == sensitive_index[j+2]) {
                                    mapKey.add(sensitive_index[j+1]+"."+sensitive_index[j+2])
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return mapKey
}

def setTableRelations(String key1, String key2) {
    def table1 = key1.substring(0, key1.indexOf("."))
    def column1 = key1.substring(key1.indexOf(".")+1)
    def table2 = key2.substring(0, key2.indexOf("."))
    def column2 = key2.substring(key2.indexOf(".")+1)
    if (table1 == table2) return
    if (QueryProcessing.containColumn(table1, column1) && QueryProcessing.containColumn(table2, column2)) {
        if (QueryProcessing.tableRelations.get(key1) == null) {
            QueryProcessing.tableRelations.put(key1, new HashSet<>());
        }
        QueryProcessing.tableRelations.get(key1).add(key2)
        if (QueryProcessing.tableRelations.get(key2) == null) {
            QueryProcessing.tableRelations.put(key2, new HashSet<>());
        }
        QueryProcessing.tableRelations.get(key2).add(key1)
    }
}

def getAllParents(node) {
    def parents = []
    while (node.type != 'AST_TOPLEVEL') {
        node = node.in('PARENT_OF').next()
        parents.add(node)
    }
    return parents
}

def filter(source_to_sink_paths) {
    def result = []
    def source = source_to_sink_paths[0]
    def sink = source_to_sink_paths[source_to_sink_paths.size()-1]
    def parents = getAllParents(sink)
    for (path in source_to_sink_paths) {
        def parent = path.in('PARENT_OF').in('PARENT_OF').next()
        if (source == path || (path.lineno <= sink.lineno && parents.contains(parent))) {
            def location = path.toFileAbs().next().name
            location += ":"+path.lineno
            result.add(location)
        }
    }
    return result
}

def findPaths(sourceVertex, sinkVertex, paths, error_funcs, check_args, check_type) {
    Queue<Vertex> queue = new LinkedList<Vertex>()
    HashSet<Vertex> visitedNodes = new HashSet<Vertex>()
    queue.offer(sourceVertex)
    visitedNodes.add(sourceVertex)

    paths.add(sourceVertex)

    while (queue.size() > 0) {
        currentVertex = queue.poll()
        currpath = [currentVertex]

        canPass = true
        isCycle = false

        while (currentVertex.out('FLOWS_TO').count() == 1) {

            if (currentVertex == sinkVertex) {
                break
            }

            if (isExit(currentVertex) || isCheck(currentVertex, check_args, check_type) || isErrorFunc(error_funcs, currentVertex)) {
                canPass = false
                break
            }

            nextVertex = currentVertex.out('FLOWS_TO').next()
            if (nextVertex.id < currentVertex.id) {
                currentVertex = nextVertex
                isCycle = true
                break
            }
            if (visitedNodes.contains(nextVertex)) {
                break;
            }
            currpath.add(nextVertex)
            visitedNodes.add(nextVertex)
            currentVertex = nextVertex
            if (nextVertex == sinkVertex) {
                break
            }
        }

        if (canPass) {
            //paths.add(currpath)
        }

        if (currentVertex == sinkVertex) {
            paths.add(sinkVertex)
            return true
        }

        if (!isCycle && currentVertex.out('FLOWS_TO').count() > 1) {
            if (!isCheck(currentVertex, check_args, check_type)) {
                paths.add(currentVertex)
                for (Vertex v : currentVertex.out('FLOWS_TO')) {
                    if (visitedNodes.contains(v)) {
                        continue
                    }
                    visitedNodes.add(v)
                    queue.offer(v)
                }
            }
        }
    }
    return false
}

def getLastReachVar(paths) {
    lastReachVar = []
    for (path in paths) {
        len = path.size()
        if (len > 2) {
            lastReachVar.add(path[1].var)
        }
    }
    return lastReachVar
}

def getSources(var, source_paths) {
    sources = []
    for (path in source_paths) {
        len = path.size()
        if (len > 2) {
            if (path[1].var == var) {
                sources.add(path[len-1])
            }
        }
    }
    return sources
}

def getSinks(sink_paths) {
    sinks = []
    for (path in sink_paths) {
        len = path.size()
        if (len > 2) {
            sinks.add(path[len-1])
        }
    }
    return sinks
}

def isCheck(node, check_args, check_type) {
    if (check_type == 0) {
        return isCheckForMOC(node, check_args)
    }
    if (check_type == 1) {
        return isCheckForMSC(node, check_args)
    }
    if (check_type == 2) {
        return isCheckForMMC(node, check_args)
    }
    if (check_type == 3) {
        return isCheckForMHC(node, check_args)
    }
    return false
}

def isCheckForMOC(node, check_args_for_MOC) {
    if (node.type == 'AST_BINARY_OP') {
        if (node.flags.contains(FLAG_BINARY_EQUAL)) {
            session_source_paths = getSessionSourcePaths(node)
            userVars = getLastReachVar(session_source_paths)
            leftVar = getValName(node.ithChildren(0).next())
            rightVar = getValName(node.ithChildren(1).next())
            sql_source_map = check_args_for_MOC[0]
            userTable = check_args_for_MOC[1]
            userTableKey = check_args_for_MOC[2]
            sql_query_funcs = check_args_for_MOC[3]
            isCheck = true
            i = 4
            while (i < check_args_for_MOC.size()) {
                flag = check_args_for_MOC[i]
                if (flag == "userTable") {
                    source = check_args_for_MOC[++i]
                    source_paths = getSourcePaths(node)
                    if (userVars.contains(leftVar)) {
                        sources = getSources(rightVar, source_paths)
                        if (sources.contains(source)) {
                            isCheck = isCheck && true
                        } else {
                            isCheck = isCheck && false
                        }
                    } else if (userVars.contains(rightVar)) {
                        sources = getSources(leftVar, source_paths)
                        if (sources.contains(source)) {
                            isCheck = isCheck && true
                        } else {
                            isCheck = isCheck && false
                        }
                    } else {
                        isCheck = isCheck && false
                    }
                }
                else if (flag == "ownTable") {
                    sql_sink_paths = check_args_for_MOC[++i]
                    table = check_args_for_MOC[++i]
                    column = check_args_for_MOC[++i]
                    sql_source_paths = getSqlSourcePaths(node, sql_query_funcs)
                    if (userVars.contains(leftVar)) {
                        sqlSinks = getSinks(sql_sink_paths)
                        isUser = false
                        for (sql_source_path in sql_source_paths) {
                            sqlSources = getSources(rightVar, [sql_source_path])
                            sqlReachs = sqlSources.intersect(sqlSinks)
                            if (sqlReachs.size() > 0) {
                                rightVarToKeys = getMapKey(rightVar, [sql_source_path], sql_source_map)
                                for (key in rightVarToKeys) {
                                    for (userKey in userTableKey) {
                                        user = userTable+userKey
                                        if (key == user) {
                                            isUser = true
                                        }
                                    }
                                }
                            }
                        }
                        isCheck = isCheck && isUser
                    }
                    else if (userVars.contains(rightVar)) {
                        sqlSinks = getSinks(sql_sink_paths)
                        isUser = false
                        for (sql_source_path in sql_source_paths) {
                            sqlSources = getSources(leftVar, [sql_source_path])
                            sqlReachs = sqlSources.intersect(sqlSinks)
                            if (sqlReachs.size() > 0) {
                                leftVarToKeys = getMapKey(leftVar, [sql_source_path], sql_source_map)
                                for (key in leftVarToKeys) {
                                    for (userKey in userTableKey) {
                                        user = userTable+"."+userKey
                                        if (key == user) {
                                            isUser = true
                                        }
                                    }
                                }
                            }
                        }
                        isCheck = isCheck && isUser
                    }
                    else {
                        isCheck = isCheck && false
                    }
                }
                ++i
            }
            return isCheck
        }
    }
    return false
}

def isCheckForMSC(node, check_args_for_MSC) {
    if (node.type == 'AST_BINARY_OP') {
        if (node.flags.contains(FLAG_BINARY_EQUAL)) {
            session_source_paths = getSessionSourcePaths(node)
            leftVar = getValName(node.ithChildren(0).next())
            rightVar = getValName(node.ithChildren(1).next())
            sql_source_map = check_args_for_MSC[0]
            sql_query_funcs = check_args_for_MSC[1]
            isCheck = true
            i = 2
            while (i < check_args_for_MSC.size()) {
                flag = check_args_for_MSC[i]
                if (flag == "statusTable") {
                    sql_sink_paths = check_args_for_MSC[++i]
                    table = check_args_for_MSC[++i]
                    column = check_args_for_MSC[++i]
                    statusColumn = table+"."+column
                    sql_source_paths = getSqlSourcePaths(node, sql_query_funcs)
                    sqlSinks = getSinks(sql_sink_paths)
                    isStatus = false
                    for (sql_source_path in source_for_var_paths) {
                        sqlSources = getSources(rightVar, [sql_source_path])
                        sqlReachs = sqlSources.intersect(sqlSinks)
                        if (sqlReachs.size() > 0) {
                            leftVarToKeys = getMapKey(leftVar, [sql_source_path], sql_source_map)
                            for (key in leftVarToKeys) {
                                if (key == statusColumn) {
                                    isStatus = true
                                }
                            }
                            rightVarToKeys = getMapKey(rightVar, [sql_source_path], sql_source_map)
                            for (key in rightVarToKeys) {
                                if (key == statusColumn) {
                                    System.out.println(rightVar)
                                    isStatus = true
                                }
                            }
                        }
                    }
                    isCheck = isCheck && isStatus
                }
                ++i
            }
            return isCheck
        }
    }
    return false
}

def isCheckForMMC(node, check_args_for_MMC) {
    return false
}

def isCheckForMHC(node, check_args_for_MHC) {

    return false
}


def isExit(node) {
    if (node.type && node.type == 'AST_EXIT') {
        return true
    }
    return false
}

def findUniquePaths(currentVertex, targetVertex, visitedNodes, path, paths) {
    path.add(currentVertex)
    visitedNodes.add(currentVertex)

    if (currentVertex == targetVertex) {
        result = []
        System.out.println("result:")
        for (Vertex v : path) {
            result.add(v)
            System.out.println(print(v))
        }
        System.out.println("end")
        paths.add(result)
    } else {
        if (path.size > 50) {
            return
        }
        for (Vertex v : currentVertex.in('FLOWS_TO')) {
            if (!visitedNodes.contains(v)) {
                findUniquePaths(v, targetVertex, visitedNodes, path, paths)
            }
        }
    }
    path.remove(currentVertex)
    visitedNodes.remove(currentVertex)
}

def print(Vertex v) {
    if (v.lineno)
        return "lineno "+v.lineno
    else
        return "id "+v.id
}

def getPrimaryKeyOf(table, primaryKeys) {
    for (key in primaryKeys) {
        if (key.startsWith(table)) {
            return key.substring(table.size()+1)
        }
    }
    return ""
}

def getSourcePaths(node) {
    visited = new HashSet<Vertex>()
    source_paths_first = node.as('s').inE('REACHES').outV.loop('s'){it.loops < 100 && (it.object.containsLowSource().toList() == [] && visited.contains(it.object) == false && visited.add(it.object))}.path().toList()//may sql_query in mid/may source is a parameter
    source_paths = []
    for (p in source_paths_first) {
        len = p.size()
        if (len > 0) {
            if (p[len-1].containsLowSource().toList() != []) {
                source_paths.add(p)
            }
        }
    }
    return source_paths
}

def getSessionSourcePaths(node) {
    visited = new HashSet<Vertex>()
    session_source_paths_first = node.as('s').inE('REACHES').outV.loop('s'){it.loops < 100 && (it.object.containsSession().toList() == [] && visited.contains(it.object) == false && visited.add(it.object))}.path().toList()//why result does not session variable
    session_source_paths = []
    for (p in session_source_paths_first) {
        len = p.size()
        if (len > 0) {
            if (p[len-1].containsSession().toList() != []) {
                session_source_paths.add(p)
            }
        }
    }
    return session_source_paths
}

def getSqlSinkPaths(node, sql_query_funcs) {
    visited = new HashSet<Vertex>()
    sql_sink_paths_first = node.as('s').outE('REACHES').inV.loop('s'){it.loops < 100 && isSqlQueryFunc(sql_query_funcs,it.object) == false && visited.contains(it.object) == false && visited.add(it.object)}.path().toList() //may node itself is sql query
    sql_sink_paths = []
    for (p in sql_sink_paths_first) {
        len = p.size()
        if (len > 0) {
            if (isSqlQueryFunc(sql_query_funcs,p[len-1])) {
                sql_sink_paths.add(p)
            }
        }
    }
    return sql_sink_paths
}

def getSqlSourcePaths(node, sql_query_funcs) {
    visited = new HashSet<Vertex>()
    sql_source_paths_first = node.as('s').inE('REACHES').outV.loop('s'){it.loops < 100 && isSqlQueryFunc(sql_query_funcs,it.object) == false && visited.contains(it.object) == false && visited.add(it.object)}.path().toList() //may node itself is sql query
    sql_source_paths = []
    for (p in sql_source_paths_first) {
        len = p.size()
        if (len > 0) {
            if (isSqlQueryFunc(sql_query_funcs,p[len-1])) {
                sql_source_paths.add(p)
            }
        }
    }
    return sql_source_paths
}

def getSourceForVarPaths(var, source_paths) {
    arr_index = ""
    valName = var.replace("\$", "")
    if (valName.contains("[")) {
        arr_index = valName.substring(valName.indexOf("[") + 1, valName.indexOf("]"))
        valName = valName.substring(0, valName.indexOf("["))
    }
    source_for_var_paths = []
    for (p in source_paths) {
        len = p.size()
        if (len > 2) {
            if (p[1].var == valName) {
                source_for_var_paths.add(p)
            }
        }
    }
    return source_for_var_paths
}

def hasUserCheck(conditionCols, conditionVals, userTable, userTableKey) {
    for (int i = 0; i < conditionCols.size(); ++i) {
        def val = conditionVals.get(i)
        if (val instanceof String && val.startsWith("\$")) {
            for (rel in QueryProcessing.tableRelations.get(conditionCols.get(i))) {
                for (key in userTableKey) {
                    if (rel == userTable+"."+key) {
                        return true
                    }
                }
            }
        }
        else if (val instanceof ArrayList) {
            for (v in val) {
                if (v.startsWith("\$")) {
                    for (rel in QueryProcessing.tableRelations.get(conditionCols.get(i))) {
                        for (key in userTableKey) {
                            if (rel == userTable+"."+key) {
                                return true
                            }
                        }
                    }
                }
            }
        }
    }
    return false
}

def getVarToKeysForCol(colNames, itemNames, primaryKeys, table) {
    def varToKeysForCol = new HashMap<String, ArrayList<String>>()
    for (int i = 0; i < colNames.size(); ++i) {
        if (itemNames.get(i).startsWith("\$")) {
            if (primaryKeys.contains(table+"."+colNames.get(i))) {
                if (varToKeysForCol.get(itemNames.get(i)) == null) {
                    varToKeysForCol.put(itemNames.get(i), new ArrayList<String>())
                }
                varToKeysForCol.get(itemNames.get(i)).add(table+"."+colNames.get(i))
            }
            for (rel in QueryProcessing.tableRelations.get(table+"."+colNames.get(i))) {
                if (primaryKeys.contains(rel)) {
                    if (varToKeysForCol.get(itemNames.get(i)) == null) {
                        varToKeysForCol.put(itemNames.get(i), new ArrayList<String>())
                    }
                    varToKeysForCol.get(itemNames.get(i)).add(rel)
                }
            }
        }
    }
    return varToKeysForCol
}

def getVarToKeysForCond(conditionCols, conditionVals, primaryKeys) {
    def varToKeys = new HashMap<String, ArrayList<String>>()
    for (int i = 0; i < conditionCols.size(); ++i) {
        val = conditionVals.get(i)
        if (val instanceof String && val.startsWith("\$")) {
            if (primaryKeys.contains(conditionCols.get(i))) {
                if (varToKeys.get(val) == null) {
                    varToKeys.put(val, new ArrayList<String>())
                }
                varToKeys.get(val).add(conditionCols.get(i))
            }
            for (rel in QueryProcessing.tableRelations.get(conditionCols.get(i))) {
                if (primaryKeys.contains(rel)) {
                    if (varToKeys.get(val) == null) {
                        varToKeys.put(val, new ArrayList<String>())
                    }
                    varToKeys.get(val).add(rel)
                }
            }
        }
        else if (val instanceof ArrayList) {
            for (v in val) {
                if (v.startsWith("\$")) {
                    if (primaryKeys.contains(conditionCols.get(i))) {
                        if (varToKeys.get(val) == null) {
                            varToKeys.put(val, new ArrayList<String>())
                        }
                        varToKeys.get(val).add(conditionCols.get(i))
                    }
                    for (rel in QueryProcessing.tableRelations.get(conditionCols.get(i))) {
                        if (primaryKeys.contains(rel)) {
                            if (varToKeys.get(v) == null) {
                                varToKeys.put(v, new ArrayList<String>())
                            }
                            varToKeys.get(v).add(rel)
                        }
                    }
                }
            }
        }
    }
    return varToKeys
}

def isUserOwnTable(table, userOwnTables, userOneToOne, oneToMany) {
    if (userOwnTables.containsKey(table) || userOneToOne.containsKey(table)) {
        return true
    }
    for (userTable in userOwnTables.keySet()) {
        def ownTables = userOwnTables.get(userTable)
        for (userKey in ownTables.keySet()) {
            def ot = ownTables.get(userKey)
            for (ownTableColumn in ot) {
                def ownTable = ownTableColumn.substring(0, ownTableColumn.indexOf("."))
                if (ownTable == table) {
                    return true
                }
            }
        }
    }
    for (userTable in userOneToOne.keySet()) {
        def oneToOne = userOneToOne.get(userTable)
        for (userKey in oneToOne.keySet()) {
            def oo = oneToOne.get(userKey)
            for (oneToOneTableColumn in oo) {
                def oneToOneTable = oneToOneTableColumn.substring(0, oneToOneTableColumn.indexOf("."))
                def oneToOneColumn = oneToOneTableColumn.substring(oneToOneTableColumn.indexOf(".") + 1)
                if (oneToMany.containsKey(oneToOneTable)) {
                    def keyManyTables = oneToMany.get(oneToOneTable)
                    for (oneToOneKey in keyManyTables.keySet()) {
                        def manyTables = keyManyTables.get(oneToOneKey)
                        for (manyTableColumn in manyTables) {
                            def manyTable = manyTableColumn.substring(0, manyTableColumn.indexOf("."))
                            if (manyTable == table && manyTable != userTable) {
                                return true
                            }
                        }
                    }
                }
            }
        }
    }
    return false
}

def isUserManyTable(table, userUserMany, userOneToOne, manyToMany, PrimaryKeysMap) {
    for (userTable in userUserMany.keySet()) {
        def userMany = userUserMany.get(userTable)
        for (userKey in userMany.keySet()) {
            def um = userMany.get(userKey)
            for (entry in um) {
                def many = entry.getKey()
                def manyTable = many.substring(0, many.indexOf("."))
                if (manyTable == table) {
                    return true
                }
            }
        }
    }
    for (userTable in userOneToOne.keySet()) {
        def oneToOne = userOneToOne.get(userTable)
        for (userKey in oneToOne.keySet()) {
            def oo = oneToOne.get(userKey)
            for (oneToOneTableColumn in oo) {
                def oneToOneTable = oneToOneTableColumn.substring(0, oneToOneTableColumn.indexOf("."))
                def oneToOneColumn = oneToOneTableColumn.substring(oneToOneTableColumn.indexOf(".") + 1)
                def oneToOneTableKey = PrimaryKeysMap.get(oneToOneTable)
                if (manyToMany.containsKey(oneToOneTable+"."+oneToOneTableKey)) {
                    def manyTables = manyToMany.get(oneToOneTable+"."+oneToOneTableKey)
                    for (entry in manyTables) {
                        def many = entry.getKey()
                        def manyTable = many.substring(0, many.indexOf("."))
                        if (manyTable == table) {
                            return true
                        }
                    }
                }
            }
        }
    }
    return false
}

def findInclusionChains(table, column, parentTable, oneToMany, PrimaryKeysMap, inclusionChain, inclusionChains, visitedTables, ret) {
    if (visitedTables.contains(parentTable)) {
        return
    }
    visitedTables.add(parentTable)
    if (oneToMany.containsKey(parentTable)) {
        def keyManyTables = oneToMany.get(parentTable)
        for (parentKey in keyManyTables.keySet()) {
            def manyTables = keyManyTables.get(parentKey)
            for (manyTable in manyTables) {
                def newInclusionChain = new ArrayList<String>(inclusionChain)
                newInclusionChain.add(parentTable+"."+parentKey)
                newInclusionChain.add(manyTable)
                if (manyTable.startsWith(table+".")) {
                    newInclusionChain.add(table+"."+column)
                    inclusionChains.add(newInclusionChain)
                }
                else {
                    findInclusionChains(table, column, manyTable.substring(0, manyTable.indexOf(".")), oneToMany, PrimaryKeysMap, newInclusionChain, inclusionChains, visitedTables, ret)
                }
            }
        }
    }
}

def checkInPathRecords(path, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, node, query_info, exit_blocks, condStringsMap, ret) {
    def length = path.size()
    def hasCheck = parseCondInQuery(node, query_info, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, condColumnsMap, ret)
    if (hasCheck) {
        ret.add("###################check in sql success###################")
        return true
    }
    for (int i = length-1; i > 0; --i) {
        def source = path.get(i).getValue().getKey()
        def value = path.get(i).getKey()
        value = value.substring(value.indexOf(" ") + 1)
        def sourceFlag = path.get(i).getValue().getValue()
        def target = path.get(i - 1).getValue().getKey()
        System.out.println("sourceFlag "+sourceFlag)
        if (sourceFlag != "arg") {
            if (path_records.containsKey(new AbstractMap.SimpleEntry<Vertex, Vertex>(source, target))) {
                def records = path_records.get(new AbstractMap.SimpleEntry<Vertex, Vertex>(source, target))
                def fPath = records[0]
                def controlNodesOfTarget = records[1]
                def controlNodesOfExit = records[2]
                def condNodes = new HashSet<Vertex>()
                ret.add("###################check in controlNodesOfTarget###################")
                System.out.println("###################check in controlNodesOfTarget###################")
                condNodes.addAll(controlNodesOfTarget.keySet())
                for (controlNodeOfTarget in controlNodesOfTarget.keySet()) {
                    def controlEdgeOfTarget = controlNodesOfTarget.get(controlNodeOfTarget)
                    def controlVar = ""
                    if (controlEdgeOfTarget.getProperty("var")) {
                        controlVar = controlEdgeOfTarget.getProperty("var")
                    }
                    ret.add("****@@@@****")
                    ret.add(getLocation(controlNodeOfTarget)+" "+controlVar)
                    def condString = controlNodeOfTarget.id+controlVar+"true"+parentTable+parentKey+statusColumn+childTable+childColumn+childOwnColumn+manyTable+manyKey+manyOwnColumn
                    if (condStringsMap.containsKey(condString)) {
                        hasCheck = condStringsMap.get(condString)
                    }
                    else {
                        System.out.println("in")
                        hasCheck = parseCondNodes(controlNodeOfTarget, controlEdgeOfTarget, true, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                        System.out.println("out")
                        condStringsMap.put(condString, hasCheck)
                    }
                    if (hasCheck) {
                        ret.add("###################check in controlNodesOfTarget success###################")
                        return true
                    }
                }

                ret.add("###################check in controlNodesOfExit###################")
                System.out.println("###################check in controlNodesOfExit###################")
                for (controlNodeOfExit in controlNodesOfExit) {
                    def controlPaths = exit_blocks.get(controlNodeOfExit)
                    for (controlPath in controlPaths) {
                        def entry = controlPath.get(0)
                        def controlEdgeOfExit = entry.getValue()
                        def controlVar = ""
                        if (controlEdgeOfExit && controlEdgeOfExit.getProperty("var")) {
                            controlVar = controlEdgeOfExit.getProperty("var")
                        }
                        ret.add("****@@@@****")
                        ret.add(getLocation(controlNodeOfExit)+" "+controlVar)
                        def condString = controlNodeOfExit.id+controlVar+"false"+parentTable+parentKey+statusColumn+childTable+childColumn+childOwnColumn+manyTable+manyKey+manyOwnColumn
                        if (condStringsMap.containsKey(condString)) {
                            hasCheck = condStringsMap.get(condString)
                        }
                        else {
                            hasCheck = parseCondNodes(controlNodeOfExit, controlEdgeOfExit, false, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                            condStringsMap.put(condString, hasCheck)
                        }
                        if (hasCheck) {
                            ret.add("###################check in controlNodesOfExit success###################")
                            return true
                        }
                    }
                }
                System.out.println("###################check in controlNodesOfExit over###################")
            }
        }
    }
    return false
}

def checkMOCForCol(node, sourceNode, path, table, column, userTables, userOneToOne, userOwnTables, oneToMany, middleTables, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, ret) {
    ret.add("******************************checkMOCForCol start******************************")
    for (rel in QueryProcessing.tableRelations.get(table+"."+column)) {
        def tableOfRel = rel.substring(0, rel.indexOf("."))
        def columnOfRel = rel.substring(rel.indexOf(".") + 1)
        if (userTables.containsKey(tableOfRel) && userTables.get(tableOfRel).contains(columnOfRel)) {
            ret.add(tableOfRel + "." + columnOfRel + " ref userTable")
            checkSummary.add(tableOfRel + "." + columnOfRel + " ref userTable")
        }
    }
    ret.add("******************************checkMOCForCol over******************************")
}

def checkMSCForCol(node, sourceNode, path, table, column, statusColumns, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, ret) {
    ret.add("******************************checkMSCForCol start******************************")
    for (rel in QueryProcessing.tableRelations.get(table+"."+column)) {
        def tableOfRel = rel.substring(0, rel.indexOf("."))
        def columnOfRel = rel.substring(rel.indexOf(".") + 1)
        if (PrimaryKeysMap.containsKey(tableOfRel) && (PrimaryKeysMap.get(tableOfRel).equalsIgnoreCase(columnOfRel) || columnOfRel.endsWith("_uuid"))) {
            for (statusTableColumn in statusColumns) {
                def statusTable = statusTableColumn.substring(0, statusTableColumn.indexOf("."))
                if (statusTable == tableOfRel) {
                    def statusColumn = statusTableColumn.substring(statusTableColumn.indexOf(".") + 1)
                    ret.add(tableOfRel + "." + columnOfRel + " with " + statusColumn + " is referenced by " + table + "." + column)
                    checkSummary.add(tableOfRel + "." + columnOfRel + " with " + statusColumn + " is referenced by " + table + "." + column)
                    def hasCheck = checkInPathRecords(path, tableOfRel, columnOfRel, statusColumn, table, "", column, "", "", "", valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, node, query_info, exit_blocks, condStringsMap, ret)
                    if (!hasCheck) {
                        ret.add("!!!!!!!!!!!!!!!!!MSC check fail!!!!!!!!!!!!!!!!!!")
                        checkSummary.add("!!!!!!!!!!!!!!!!!S_MSC check fail!!!!!!!!!!!!!!!!!!")
                    }
                    else {
                        ret.add("!!!!!!!!!!!!!!!!!MSC check success!!!!!!!!!!!!!!!!!!")
                        checkSummary.add("!!!!!!!!!!!!!!!!!S_MSC check success!!!!!!!!!!!!!!!!!!")
                    }
                }
            }
        }
    }

    ret.add("******************************checkMSCForCol over******************************")
}

def checkMMCForCol(node, sourceNode, path, table, column, userTables, userOneToOne, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, ret) {
    ret.add("******************************checkMMCForCol start******************************")

    ret.add("******************************checkMMCForCol over******************************")
}

def checkMHCForCol(node, sourceNode, path, table, column, userTables, userOneToOne, userOwnTables, oneToMany, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, ret) {
    ret.add("******************************checkMHCForCol start******************************")

    ret.add("******************************checkMHCForCol over******************************")
}

def checkMOCForCond(node, sourceNode, path, table, column, userTables, userOneToOne, userOwnTables, oneToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, ret) {
    ret.add("******************************checkMOCForCond start******************************")
    System.out.println("******************************checkMOCForCond start******************************")
    if (PrimaryKeysMap.containsKey(table) && (PrimaryKeysMap.get(table).equalsIgnoreCase(column) || column.endsWith("_uuid"))) {
        def isUserOwnTable = false
        if (userTables.containsKey(table) && userTables.get(table).contains(column)) {
            ret.add(table + "." + column + " is userTable")
            checkSummary.add(table + "." + column + " is userTable")
        }
        System.out.println("userOwnTables.keySet() ")
        for (userTable in userOwnTables.keySet()) {
            def ownTables = userOwnTables.get(userTable)
            for (userKey in ownTables.keySet()) {
                def ot = ownTables.get(userKey)
                for (ownTableColumn in ot) {
                    def ownTable = ownTableColumn.substring(0, ownTableColumn.indexOf("."))
                    if (ownTable == table) {
                        isUserOwnTable = true
                        def ownColumn = ownTableColumn.substring(ownTableColumn.indexOf(".") + 1)
                        ret.add(table + "." + column + " is " + userTable + "." + userKey + " ownTable by " + ownTableColumn)
                        checkSummary.add(table + "." + column + " is " + userTable + "." + userKey + " ownTable by " + ownTableColumn)
                        System.out.println("table "+table)
                        def hasCheck = checkInPathRecords(path, userTable, userKey, "", table, column, ownColumn, "", "", "", valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, node, query_info, exit_blocks, condStringsMap, ret)
                        System.out.println("hasCheck "+hasCheck)
                        if (!hasCheck) {
                            ret.add("!!!!!!!!!!!!!!!!!MOC check fail!!!!!!!!!!!!!!!!!!")
                            checkSummary.add("!!!!!!!!!!!!!!!!!S_MOC check fail!!!!!!!!!!!!!!!!!!")
                        }
                        else {
                            ret.add("!!!!!!!!!!!!!!!!!MOC check success!!!!!!!!!!!!!!!!!!")
                            checkSummary.add("!!!!!!!!!!!!!!!!!S_MOC check success!!!!!!!!!!!!!!!!!!")
                        }
                    }
                }
            }
        }
        System.out.println("isUserOwnTable "+isUserOwnTable)
        if (!isUserOwnTable) {
            System.out.println("userOneToOne.keySet() ")
            for (userTable in userOneToOne.keySet()) {
                def oneToOne = userOneToOne.get(userTable)
                for (userKey in oneToOne.keySet()) {
                    def oo = oneToOne.get(userKey)
                    for (oneToOneTableColumn in oo) {
                        def oneToOneTable = oneToOneTableColumn.substring(0, oneToOneTableColumn.indexOf("."))
                        def oneToOneColumn = oneToOneTableColumn.substring(oneToOneTableColumn.indexOf(".") + 1)
                        if (oneToMany.containsKey(oneToOneTable)) {
                            def keyManyTables = oneToMany.get(oneToOneTable)
                            for (oneToOneKey in keyManyTables.keySet()) {
                                def manyTables = keyManyTables.get(oneToOneKey)
                                for (manyTableColumn in manyTables) {
                                    def manyTable = manyTableColumn.substring(0, manyTableColumn.indexOf("."))
                                    if (manyTable == table && manyTable != userTable) {
                                        def manyColumn = manyTableColumn.substring(manyTableColumn.indexOf(".") + 1)
                                        ret.add(table + "." + column + " is " + userTable + "." + userKey + " oneToOne by " + oneToOneTableColumn + " " + oneToOneKey + " " + manyTableColumn)
                                        checkSummary.add(table + "." + column + " is " + userTable + "." + userKey + " oneToOne by " + oneToOneTableColumn + " " + oneToOneKey + " " + manyTableColumn)
                                        def hasCheck = checkInPathRecords(path, oneToOneTable, oneToOneKey, "", table, column, manyColumn, "", "", "", valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, node, query_info, exit_blocks, condStringsMap, ret)
                                        if (!hasCheck) {
                                            ret.add("!!!!!!!!!!!!!!!!!MOC check fail!!!!!!!!!!!!!!!!!!")
                                            checkSummary.add("!!!!!!!!!!!!!!!!!S_MOC check fail!!!!!!!!!!!!!!!!!!")
                                        }
                                        else {
                                            ret.add("!!!!!!!!!!!!!!!!!MOC check success!!!!!!!!!!!!!!!!!!")
                                            checkSummary.add("!!!!!!!!!!!!!!!!!S_MOC check success!!!!!!!!!!!!!!!!!!")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else {
        ret.add(table+"."+column+" is not primary key")
    }
    ret.add("******************************checkMOCForCond over******************************")
    System.out.println("******************************checkMOCForCond over******************************")
}

def checkMSCForCond(node, sourceNode, path, table, column, statusColumns, PrimaryKeysMap, valTableColumnMap, adminCondColumns, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, query_info, ret) {
    ret.add("******************************checkMSCForCond start******************************")

    ret.add("******************************checkMSCForCond over******************************")
}

def checkMMCForCond(node, sourceNode, path, table, column, userTables, userOneToOne, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, ret) {
    ret.add("******************************checkMMCForCond start******************************")
    if (PrimaryKeysMap.containsKey(table) && (PrimaryKeysMap.get(table).equalsIgnoreCase(column) || column.endsWith("_uuid"))) {
        def isUserOwnTable = false
        for (userTable in userUserMany.keySet()) {
            def userMany = userUserMany.get(userTable)
            for (userKey in userMany.keySet()) {
                def um = userMany.get(userKey)
                for (entry in um) {
                    def many = entry.getKey()
                    def manyTable = many.substring(0, many.indexOf("."))
                    if (manyTable == table) {
                        isUserOwnTable = true
                        def middle = entry.getValue().split(" ")
                        def middleTable = middle[0]
                        def middleColumnForUser = middle[1]
                        def middleColumnForMany = middle[2]
                        ret.add(table + "." + column + " is " + userTable + "." + userKey + " userUserMany by " + middleTable + " " + middleColumnForUser + " " + middleColumnForMany)
                        checkSummary.add(table + "." + column + " is " + userTable + "." + userKey + " userUserMany by " + middleTable + " " + middleColumnForUser + " " + middleColumnForMany)
                        def hasCheck = checkInPathRecords(path, userTable, userKey, "", middleTable, PrimaryKeysMap.get(middleTable), middleColumnForUser, table, column, middleColumnForMany, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, node, query_info, exit_blocks, condStringsMap, ret)
                        if (!hasCheck) {
                            ret.add("!!!!!!!!!!!!!!!!!MMC check fail!!!!!!!!!!!!!!!!!!")
                            checkSummary.add("!!!!!!!!!!!!!!!!!S_MMC check fail!!!!!!!!!!!!!!!!!!")
                        }
                        else {
                            ret.add("!!!!!!!!!!!!!!!!!MMC check success!!!!!!!!!!!!!!!!!!")
                            checkSummary.add("!!!!!!!!!!!!!!!!!S_MMC check success!!!!!!!!!!!!!!!!!!")
                        }
                    }
                }
            }
        }
        if (!isUserOwnTable) {
            for (userTable in userOneToOne.keySet()) {
                def oneToOne = userOneToOne.get(userTable)
                for (userKey in oneToOne.keySet()) {
                    def oo = oneToOne.get(userKey)
                    for (oneToOneTableColumn in oo) {
                        def oneToOneTable = oneToOneTableColumn.substring(0, oneToOneTableColumn.indexOf("."))
                        def oneToOneColumn = oneToOneTableColumn.substring(oneToOneTableColumn.indexOf(".") + 1)
                        def oneToOneTableKey = PrimaryKeysMap.get(oneToOneTable)
                        if (manyToMany.containsKey(oneToOneTable + "." + oneToOneTableKey)) {
                            def manyTables = manyToMany.get(oneToOneTable + "." + oneToOneTableKey)
                            for (entry in manyTables) {
                                def many = entry.getKey()
                                def manyTable = many.substring(0, many.indexOf("."))
                                if (manyTable == table) {
                                    def middle = entry.getValue().split(" ")
                                    def middleTable = middle[0]
                                    def middleColumnForOneToOne = middle[1]
                                    def middleColumnForMany = middle[2]
                                    ret.add(table + "." + column + " is " + userTable + "." + userKey + " oneToOne by " + oneToOneTableColumn + " " + oneToOneTableKey + " manyToMany by " + middleTable + " " + middleColumnForOneToOne + " " + middleColumnForMany)
                                    checkSummary.add(table + "." + column + " is " + userTable + "." + userKey + " oneToOne by " + oneToOneTableColumn + " " + oneToOneTableKey + " manyToMany by " + middleTable + " " + middleColumnForOneToOne + " " + middleColumnForMany)
                                    def hasCheck = checkInPathRecords(path, oneToOneTable, oneToOneTableKey, "", middleTable, PrimaryKeysMap.get(middleTable), middleColumnForOneToOne, manyTable, column, middleColumnForMany, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, node, query_info, exit_blocks, condStringsMap, ret)
                                    if (!hasCheck) {
                                        ret.add("!!!!!!!!!!!!!!!!!MMC check fail!!!!!!!!!!!!!!!!!!")
                                        checkSummary.add("!!!!!!!!!!!!!!!!!S_MMC check fail!!!!!!!!!!!!!!!!!!")
                                    } else {
                                        ret.add("!!!!!!!!!!!!!!!!!MMC check success!!!!!!!!!!!!!!!!!!")
                                        checkSummary.add("!!!!!!!!!!!!!!!!!S_MMC check success!!!!!!!!!!!!!!!!!!")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else {
        ret.add(table+"."+column+" is not primary key")
    }
    ret.add("******************************checkMMCForCond over******************************")
}

def checkMHCForCond(node, sourceNode, path, table, column, userTables, userOneToOne, userOwnTables, oneToMany, userUserMany, manyToMany, PrimaryKeysMap, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, skip_func, exit_funcs, exit_blocks, may_exit_blocks, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, query_info, condStringsMap, checkSummary, ret) {
    ret.add("******************************checkMHCForCond start******************************")
    if (PrimaryKeysMap.containsKey(table) && (PrimaryKeysMap.get(table).equalsIgnoreCase(column) || column.endsWith("_uuid"))) {
        if (!(isUserOwnTable(table, userOwnTables, userOneToOne, oneToMany) || isUserManyTable(table, userUserMany, userOneToOne, manyToMany, PrimaryKeysMap))) {
            for (userTable in userOwnTables.keySet()) {
                def ownTables = userOwnTables.get(userTable)
                for (userKey in ownTables.keySet()) {
                    def ot = ownTables.get(userKey)
                    for (ownTableColumn in ot) {
                        def ownTable = ownTableColumn.substring(0, ownTableColumn.indexOf("."))
                        def ownColumn = ownTableColumn.substring(ownTableColumn.indexOf(".") + 1)
                        def inclusionChains = new HashSet<ArrayList<String>>()
                        def inclusionChain = new ArrayList<String>()
                        inclusionChain.add(userTable + "." + userKey)
                        inclusionChain.add(ownTableColumn)
                        def visited = new HashSet<String>()
                        visited.add(userTable)
                        findInclusionChains(table, column, ownTable, oneToMany, PrimaryKeysMap, inclusionChain, inclusionChains, visited, ret)
                        if (inclusionChains.size() > 0) {
                            for (incChain in inclusionChains) {
                                ret.add("@@@@@@@@@@@@@@@incChain@@@@@@@@@@@@@@@")
                                ret.add(incChain)
                                checkSummary.add("@@@@@@@@@@@@@@@incChain@@@@@@@@@@@@@@@")
                                checkSummary.add(incChain)
                                def length = incChain.size()
                                def hasAllCheck = true
                                if (length > 3) {
                                    for (int i = 0; i < length - 1; i += 2) {
                                        def parent = incChain.get(i)
                                        def parentTable = parent.substring(0, parent.indexOf("."))
                                        def parentColumn = parent.substring(parent.indexOf(".") + 1)
                                        def child = incChain.get(i + 1)
                                        def childTable = child.substring(0, child.indexOf("."))
                                        def childColumn = child.substring(child.indexOf(".") + 1)
                                        def hasCheck = checkInPathRecords(path, parentTable, parentColumn, "", childTable, "", childColumn, "", "", "", valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, node, query_info, exit_blocks, condStringsMap, ret)
                                        hasAllCheck = hasAllCheck && hasCheck
                                        if (!hasCheck) {
                                            break
                                        }
                                    }
                                    if (hasAllCheck) {
                                        ret.add("!!!!!!!!!!!!!!!!!MHC check success!!!!!!!!!!!!!!!!!!")
                                        checkSummary.add("!!!!!!!!!!!!!!!!!S_MHC check success!!!!!!!!!!!!!!!!!!")
                                    }
                                    else {
                                        ret.add("!!!!!!!!!!!!!!!!!MHC check fail!!!!!!!!!!!!!!!!!!")
                                        checkSummary.add("!!!!!!!!!!!!!!!!!S_MHC check fail!!!!!!!!!!!!!!!!!!")
                                    }
                                }
                            }
                        }
                    }
                }
            }
            for (userTable in userUserMany.keySet()) {
                def userMany = userUserMany.get(userTable)
                for (userKey in userMany.keySet()) {
                    def um = userMany.get(userKey)
                    for (entry in um) {
                        def many = entry.getKey()
                        def manyTable = many.substring(0, many.indexOf("."))
                        def middle = entry.getValue().split(" ")
                        def middleTable = middle[0]
                        def middleColumnForUser = middle[1]
                        def middleColumnForMany = middle[2]
                        def inclusionChains = new HashSet<ArrayList<String>>()
                        def inclusionChain = new ArrayList<String>()
                        inclusionChain.add(userTable + "." + userKey)
                        inclusionChain.add(many)
                        inclusionChain.add(middleTable+" "+middleColumnForUser+" "+middleColumnForMany)
                        def visited = new HashSet<String>()
                        visited.add(userTable)
                        findInclusionChains(table, column, manyTable, oneToMany, PrimaryKeysMap, inclusionChain, inclusionChains, visited, ret)
                        if (inclusionChains.size() > 0) {
                            for (incChain in inclusionChains) {
                                ret.add("@@@@@@@@@@@@@@@incChain@@@@@@@@@@@@@@@")
                                ret.add(incChain)
                                checkSummary.add("@@@@@@@@@@@@@@@incChain@@@@@@@@@@@@@@@")
                                checkSummary.add(incChain)
                            }
                        }
                    }
                }
            }
            for (userTable in userOneToOne.keySet()) {
                def oneToOne = userOneToOne.get(userTable)
                for (userKey in oneToOne.keySet()) {
                    def oo = oneToOne.get(userKey)
                    for (oneToOneTableColumn in oo) {
                        def oneToOneTable = oneToOneTableColumn.substring(0, oneToOneTableColumn.indexOf("."))
                        def oneToOneColumn = oneToOneTableColumn.substring(oneToOneTableColumn.indexOf(".") + 1)
                        def oneToOneTableKey = PrimaryKeysMap.get(oneToOneTable)
                        if (oneToMany.containsKey(oneToOneTable)) {
                            def keyManyTables = oneToMany.get(oneToOneTable)
                            for (oneToOneKey in keyManyTables.keySet()) {
                                def manyTables = keyManyTables.get(oneToOneKey)
                                for (manyTableColumn in manyTables) {
                                    def manyTable = manyTableColumn.substring(0, manyTableColumn.indexOf("."))
                                    if (manyTable != userTable) {
                                        def manyColumn = manyTableColumn.substring(manyTableColumn.indexOf(".") + 1)
                                        def inclusionChains = new HashSet<ArrayList<String>>()
                                        def inclusionChain = new ArrayList<String>()
                                        inclusionChain.add(oneToOneTable + "." + oneToOneKey)
                                        inclusionChain.add(manyTableColumn)
                                        def visited = new HashSet<String>()
                                        visited.add(userTable)
                                        visited.add(oneToOneTable)
                                        findInclusionChains(table, column, manyTable, oneToMany, PrimaryKeysMap, inclusionChain, inclusionChains, visited, ret)
                                        if (inclusionChains.size() > 0) {
                                            for (incChain in inclusionChains) {
                                                ret.add("@@@@@@@@@@@@@@@incChain@@@@@@@@@@@@@@@")
                                                checkSummary.add("@@@@@@@@@@@@@@@incChain@@@@@@@@@@@@@@@")
                                                ret.add(incChain)
                                                checkSummary.add(incChain)
                                                def length = incChain.size()
                                                def hasAllCheck = true
                                                if (length > 3) {
                                                    for (int i = 0; i < length - 1; i += 2) {
                                                        def parent = incChain.get(i)
                                                        def parentTable = parent.substring(0, parent.indexOf("."))
                                                        def parentColumn = parent.substring(parent.indexOf(".") + 1)
                                                        def child = incChain.get(i + 1)
                                                        def childTable = child.substring(0, child.indexOf("."))
                                                        def childColumn = child.substring(child.indexOf(".") + 1)
                                                        def hasCheck = checkInPathRecords(path, parentTable, parentColumn, "", childTable, "", childColumn, "", "", "", valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, path_records, node, query_info, exit_blocks, condStringsMap, ret)
                                                        hasAllCheck = hasAllCheck && hasCheck
                                                        if (!hasCheck) {
                                                            break
                                                        }
                                                    }
                                                    if (hasAllCheck) {
                                                        ret.add("!!!!!!!!!!!!!!!!!MHC check success!!!!!!!!!!!!!!!!!!")
                                                        checkSummary.add("!!!!!!!!!!!!!!!!!S_MHC check success!!!!!!!!!!!!!!!!!!")
                                                    }
                                                    else {
                                                        ret.add("!!!!!!!!!!!!!!!!!MHC check fail!!!!!!!!!!!!!!!!!!")
                                                        checkSummary.add("!!!!!!!!!!!!!!!!!S_MHC check fail!!!!!!!!!!!!!!!!!!")
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (manyToMany.containsKey(oneToOneTable+"."+oneToOneTableKey)) {
                            def manyTables = manyToMany.get(oneToOneTable + "." + oneToOneTableKey)
                            for (entry in manyTables) {
                                def many = entry.getKey()
                                def manyTable = many.substring(0, many.indexOf("."))
                                def middle = entry.getValue().split(" ")
                                def middleTable = middle[0]
                                def middleColumnForOneToOne = middle[1]
                                def middleColumnForMany = middle[2]
                                def inclusionChains = new HashSet<ArrayList<String>>()
                                def inclusionChain = new ArrayList<String>()
                                inclusionChain.add(oneToOneTable + "." + oneToOneTableKey)
                                inclusionChain.add(many)
                                inclusionChain.add(middleTable+" "+middleColumnForOneToOne+" "+middleColumnForMany)
                                def visited = new HashSet<String>()
                                visited.add(userTable)
                                visited.add(oneToOneTable)
                                visited.add(middleTable)
                                findInclusionChains(table, column, manyTable, oneToMany, PrimaryKeysMap, inclusionChain, inclusionChains, visited, ret)
                                if (inclusionChains.size() > 0) {
                                    for (incChain in inclusionChains) {
                                        ret.add("@@@@@@@@@@@@@@@incChain@@@@@@@@@@@@@@@")
                                        ret.add(incChain)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else {
        ret.add(table+"."+column+" is not primary key")
    }
    ret.add("******************************checkMHCForCond over******************************")
}

def collectModels(userTables, userOneToOne, userOwnTables, oneToMany, userUserMany, manyToMany, statusColumns, PrimaryKeysMap, ownershipModels, membershipModels, hierarchicalModels, statusModels) {
    def ut = new HashSet<String>()
    for (userTable in userOwnTables.keySet()) {
        ut.add(userTable)
        def ownTables = userOwnTables.get(userTable)
        for (userKey in ownTables.keySet()) {
            def ot = ownTables.get(userKey)
            for (ownTableColumn in ot) {
                def ownTable = ownTableColumn.substring(0, ownTableColumn.indexOf("."))
                ownershipModels.add(userTable+" owns "+ownTable)
            }
        }
    }
    for (userTable in userUserMany.keySet()) {
        def userMany = userUserMany.get(userTable)
        for (userKey in userMany.keySet()) {
            def um = userMany.get(userKey)
            for (entry in um) {
                def many = entry.getKey()
                def manyTable = many.substring(0, many.indexOf("."))
                membershipModels.add(userTable+" join "+manyTable)
            }
        }
    }
    for (userTable in userOneToOne.keySet()) {
        def oneToOne = userOneToOne.get(userTable)
        for (userKey in oneToOne.keySet()) {
            def oo = oneToOne.get(userKey)
            for (oneToOneTableColumn in oo)  {
                def oneToOneTable = oneToOneTableColumn.substring(0, oneToOneTableColumn.indexOf("."))
                def oneToOneTableKey = PrimaryKeysMap.get(oneToOneTable)
                ut.add(oneToOneTable)
                if (oneToMany.containsKey(oneToOneTable)) {
                    def keyManyTables = oneToMany.get(oneToOneTable)
                    for (oneToOneKey in keyManyTables.keySet()) {
                        def manyTables = keyManyTables.get(oneToOneKey)
                        for (manyTableColumn in manyTables) {
                            def manyTable = manyTableColumn.substring(0, manyTableColumn.indexOf("."))
                            ownershipModels.add(oneToOneTable+" owns "+manyTable)
                        }
                    }
                }
                if (manyToMany.containsKey(oneToOneTable+"."+oneToOneTableKey)) {
                    def manyTables = manyToMany.get(oneToOneTable + "." + oneToOneTableKey)
                    for (entry in manyTables) {
                        def many = entry.getKey()
                        def manyTable = many.substring(0, many.indexOf("."))
                        membershipModels.add(oneToOneTable+" join "+manyTable)
                    }
                }
            }
        }
    }
    for (statusTableColumn in statusColumns) {
        def statusTable = statusTableColumn.substring(0, statusTableColumn.indexOf("."))
        if (userOwnTables.containsKey(statusTable)) {
            def ownTables = userOwnTables.get(statusTable)
            for (userKey in ownTables.keySet()) {
                def ot = ownTables.get(userKey)
                for (ownTableColumn in ot) {
                    def ownTable = ownTableColumn.substring(0, ownTableColumn.indexOf("."))
                    statusModels.add(statusTable + " " + ownTable)
                }
            }
        }
        if (oneToMany.containsKey(statusTable)) {
            def keyManyTables = oneToMany.get(statusTable)
            for (oneToOneKey in keyManyTables.keySet()) {
                def manyTables = keyManyTables.get(oneToOneKey)
                for (manyTableColumn in manyTables) {
                    def manyTable = manyTableColumn.substring(0, manyTableColumn.indexOf("."))
                    statusModels.add(statusTable + " " + manyTable)
                }
            }
        }
    }
    for (table in PrimaryKeysMap.keySet()) {
        def column = PrimaryKeysMap.get(table)
        def modelChains = new HashSet<String>()
        if (!ut.contains(table)) {
            for (userTable in userOwnTables.keySet()) {
                def ownTables = userOwnTables.get(userTable)
                for (userKey in ownTables.keySet()) {
                    def ot = ownTables.get(userKey)
                    for (ownTableColumn in ot) {
                        def ownTable = ownTableColumn.substring(0, ownTableColumn.indexOf("."))
                        if (ownTable == table) {
                            continue
                        }
                        def ownColumn = ownTableColumn.substring(ownTableColumn.indexOf(".") + 1)
                        def inclusionChains = new HashSet<ArrayList<String>>()
                        def inclusionChain = new ArrayList<String>()
                        inclusionChain.add(userTable + "." + userKey)
                        inclusionChain.add(ownTableColumn)
                        def visited = new HashSet<String>()
                        visited.add(userTable)
                        findInclusionChains(table, column, ownTable, oneToMany, PrimaryKeysMap, inclusionChain, inclusionChains, visited, [])
                        if (inclusionChains.size() > 0) {
                            for (incChain in inclusionChains) {
                                def chains = "\""
                                for (inc in incChain) {
                                    if (inc.indexOf(".") != -1) {
                                        inc = inc.substring(0, inc.indexOf("."))
                                    }
                                    chains = chains + inc + " "
                                }
                                chains = chains.substring(0, chains.length() - 1)
                                chains = chains + "\""
                                modelChains.add(chains)
                            }
                        }
                    }
                }
            }
            for (userTable in userUserMany.keySet()) {
                def userMany = userUserMany.get(userTable)
                for (userKey in userMany.keySet()) {
                    def um = userMany.get(userKey)
                    for (entry in um) {
                        def many = entry.getKey()
                        def manyTable = many.substring(0, many.indexOf("."))
                        if (manyTable == table) {
                            continue
                        }
                        def middle = entry.getValue().split(" ")
                        def middleTable = middle[0]
                        def middleColumnForUser = middle[1]
                        def middleColumnForMany = middle[2]
                        def inclusionChains = new HashSet<ArrayList<String>>()
                        def inclusionChain = new ArrayList<String>()
                        inclusionChain.add(userTable + "." + userKey)
                        inclusionChain.add(many)
                        inclusionChain.add(middleTable+" "+middleColumnForUser+" "+middleColumnForMany)
                        def visited = new HashSet<String>()
                        visited.add(userTable)
                        visited.add(middleTable)
                        findInclusionChains(table, column, manyTable, oneToMany, PrimaryKeysMap, inclusionChain, inclusionChains, visited, [])
                        if (inclusionChains.size() > 0) {
                            for (incChain in inclusionChains) {
                                def chains = "\""
                                for (inc in incChain) {
                                    if (inc.indexOf(".") != -1) {
                                        inc = inc.substring(0, inc.indexOf("."))
                                    }
                                    chains = chains + " " + inc
                                }
                                chains = chains + "\""
                                modelChains.add(chains)
                            }
                        }
                    }
                }
            }
            for (userTable in userOneToOne.keySet()) {
                def oneToOne = userOneToOne.get(userTable)
                for (userKey in oneToOne.keySet()) {
                    def oo = oneToOne.get(userKey)
                    for (oneToOneTableColumn in oo) {
                        def oneToOneTable = oneToOneTableColumn.substring(0, oneToOneTableColumn.indexOf("."))
                        def oneToOneColumn = oneToOneTableColumn.substring(oneToOneTableColumn.indexOf(".") + 1)
                        def oneToOneTableKey = PrimaryKeysMap.get(oneToOneTable)
                        if (oneToMany.containsKey(oneToOneTable)) {
                            def keyManyTables = oneToMany.get(oneToOneTable)
                            for (oneToOneKey in keyManyTables.keySet()) {
                                def manyTables = keyManyTables.get(oneToOneKey)
                                for (manyTableColumn in manyTables) {
                                    def manyTable = manyTableColumn.substring(0, manyTableColumn.indexOf("."))
                                    if (manyTable != userTable && manyTable != table) {
                                        def manyColumn = manyTableColumn.substring(manyTableColumn.indexOf(".") + 1)
                                        def inclusionChains = new HashSet<ArrayList<String>>()
                                        def inclusionChain = new ArrayList<String>()
                                        inclusionChain.add(oneToOneTable + "." + oneToOneKey)
                                        inclusionChain.add(manyTableColumn)
                                        def visited = new HashSet<String>()
                                        visited.add(userTable)
                                        visited.add(oneToOneTable)
                                        findInclusionChains(table, column, manyTable, oneToMany, PrimaryKeysMap, inclusionChain, inclusionChains, visited, [])
                                        if (inclusionChains.size() > 0) {
                                            for (incChain in inclusionChains) {
                                                def chains = "\""
                                                for (inc in incChain) {
                                                    if (inc.indexOf(".") != -1) {
                                                        inc = inc.substring(0, inc.indexOf("."))
                                                    }
                                                    chains = chains + " " + inc
                                                }
                                                chains = chains + "\""
                                                modelChains.add(chains)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (manyToMany.containsKey(oneToOneTable+"."+oneToOneTableKey)) {
                            def manyTables = manyToMany.get(oneToOneTable + "." + oneToOneTableKey)
                            for (entry in manyTables) {
                                def many = entry.getKey()
                                def manyTable = many.substring(0, many.indexOf("."))
                                if (manyTable == table) {
                                    continue
                                }
                                def middle = entry.getValue().split(" ")
                                def middleTable = middle[0]
                                def middleColumnForOneToOne = middle[1]
                                def middleColumnForMany = middle[2]
                                def inclusionChains = new HashSet<ArrayList<String>>()
                                def inclusionChain = new ArrayList<String>()
                                inclusionChain.add(oneToOneTable + "." + oneToOneTableKey)
                                inclusionChain.add(many)
                                inclusionChain.add(middleTable+" "+middleColumnForOneToOne+" "+middleColumnForMany)
                                def visited = new HashSet<String>()
                                visited.add(userTable)
                                visited.add(oneToOneTable)
                                visited.add(middleTable)
                                findInclusionChains(table, column, manyTable, oneToMany, PrimaryKeysMap, inclusionChain, inclusionChains, visited, [])
                                if (inclusionChains.size() > 0) {
                                    for (incChain in inclusionChains) {
                                        def chains = "\""
                                        for (inc in incChain) {
                                            if (inc.indexOf(".") != -1) {
                                                inc = inc.substring(0, inc.indexOf("."))
                                            }
                                            chains = chains + " " + inc
                                        }
                                        chains = chains + "\""
                                        modelChains.add(chains)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (modelChains.size() > 0) {
            hierarchicalModels.put(table + "." + column, modelChains)
        }
    }
    ownershipModels.addAll(ut)
    ownershipModels.addAll(userTables.keySet())
}

def getHierarchialModelNums(hierarchicalModels) {
    def modelNums = 0
    for (table in hierarchicalModels.keySet()) {
        def chains = hierarchicalModels.get(table)
        modelNums += chains.size()
    }
    return modelNums
}

def getAllValsInCond(val) {
    def vals = new HashSet<String>()
    if (val instanceof String) {
       if (val.startsWith("\$")) {
           vals.add(val)
       }
    }
    else if (val instanceof ArrayList) {
        for (v in val) {
            if (v.startsWith("\$")) {
                vals.add(v)
            }
        }
    }
    return vals
}

def getCondTableColumns(conditionCols) {
    def condTableColumns = new HashSet<String>()
    for (int i = 0; i < conditionCols.size(); ++i) {
        if (conditionCols.get(i).indexOf(".") != -1) {
            condTableColumns.add(conditionCols.get(i))
        }
    }
    return condTableColumns
}

def isCondUseValue(conditionVals) {
    def use = false
    for (int i = 0; i < conditionVals.size(); ++i) {
        def val = conditionVals.get(i)
        if (val instanceof String && val.startsWith("\$")) {
            use = true
        }
        else if (val instanceof ArrayList) {
            for (v in val) {
                if (v.startsWith("\$")) {
                    use = true
                }
            }
        }
    }
    return use
}

def isSensitiveSql(table, column, PrimaryKeysMap, userTables) {
    def sensitive_sql = false
    if (PrimaryKeysMap.containsKey(table) && (PrimaryKeysMap.get(table).equalsIgnoreCase(column) || column.endsWith("_uuid"))) {
        sensitive_sql = true
    }
    if (userTables.containsKey(table) && userTables.get(table).contains(column)) {
        sensitive_sql = true
    }
    for (rel in QueryProcessing.tableRelations.get(table+"."+column)) {
        def tableOfRel = rel.substring(0, rel.indexOf("."))
        def columnOfRel = rel.substring(rel.indexOf(".")+1)
        if (PrimaryKeysMap.containsKey(tableOfRel) && (PrimaryKeysMap.get(tableOfRel).equalsIgnoreCase(columnOfRel) || columnOfRel.endsWith("_uuid"))) {
            sensitive_sql = true
            break
        }
        if (userTables.containsKey(tableOfRel) && userTables.get(tableOfRel).contains(columnOfRel)) {
            sensitive_sql = true
            break
        }
    }
    return sensitive_sql
}

def getValColumns(node, valName, valTableColumnMap, sessionMap, adminCondColumns, condVal, ret) {
    def hasDef = false
    if (valName.startsWith("\$")) {
        for (v in node.in("REACHES")) {
            def location = v.toFileAbs().next().name + ":" + v.lineno
            def scopeLocation = v.toFileAbs().next().name
            if (isWithinFunction(v)) {
                scopeLocation = scopeLocation +"_" + v.functions.next().name + ":" + v.functions().next().lineno
            }
            def defVal = location+" "+valName
            if (valTableColumnMap.containsKey(defVal) || (valName.startsWith("\$_SESSION[") && valTableColumnMap.containsKey(valName))) {
                def entry = null
                if (valTableColumnMap.containsKey(defVal)) {
                    entry = valTableColumnMap.get(defVal)
                }
                else {
                    entry = valTableColumnMap.get(valName)
                }
                def sensitiveIndex = entry.getValue()
                if (valName.startsWith("\$_SESSION[")) {
                    ret.add("valName is session "+valName)
                    ret.add(sensitiveIndex)
                }
                for (int i = 0; i < sensitiveIndex.size(); i += 5) {
                    if (sensitiveIndex.get(i) != "-1") {
                        hasDef = true
                        def sensitiveKey = sensitiveIndex.get(i + 1) + "." + sensitiveIndex.get(i + 2)
                        def condVals = new HashSet<String>()
                        if (adminCondColumns.containsKey(sensitiveKey)) {
                            condVals.addAll(adminCondColumns.get(sensitiveKey))
                        }
                        condVals.add(condVal)
                        adminCondColumns.put(sensitiveKey, condVals)
                        for (cv in condVals) {
                            ret.add(cv)
                        }
                    }
                }
            }
            else if (sessionMap.containsKey(defVal) || sessionMap.containsKey(scopeLocation+" "+valName)) {
                def sessionVals = new HashSet<String>()
                if (sessionMap.containsKey(defVal)) {
                    def entry = sessionMap.get(defVal)
                    sessionVals = entry.getValue()
                }
                else {
                    def entry = sessionMap.get(scopeLocation+" "+valName)
                    sessionVals = entry.getValue()
                }
                for (sessionVal in sessionVals) {
                    if (valTableColumnMap.containsKey(sessionVal)) {
                        def sensitiveIndex = valTableColumnMap.get(sessionVal).getValue()
                        for (int i = 0; i < sensitiveIndex.size(); i += 5) {
                            if (sensitiveIndex.get(i) != "-1") {
                                hasDef = true
                                def sensitiveKey = sensitiveIndex.get(i + 1) + "." + sensitiveIndex.get(i + 2)
                                def condVals = new HashSet<String>()
                                if (adminCondColumns.containsKey(sensitiveKey)) {
                                    condVals.addAll(adminCondColumns.get(sensitiveKey))
                                }
                                condVals.add(condVal)
                                adminCondColumns.put(sensitiveKey, condVals)
                                for (cv in condVals) {
                                    ret.add(cv)
                                }
                            }
                        }
                    }
                }
            }
            else if (v.type == "AST_GLOBAL") {
                def globalValName = getAllValName(v.ithChildren(0).next())
                if (valName == globalValName || valName.startsWith(globalValName+"[")) {
                    for (valTableColumnVal in valTableColumnMap.keySet()) {
                        if (valTableColumnVal.endsWith(valName)) {
                            ret.add("global find")
                            ret.add(valTableColumnVal)
                            hasDef = true
                            def sensitiveIndex = valTableColumnMap.get(valTableColumnVal).getValue()
                            for (int i = 0; i < sensitiveIndex.size(); i += 5) {
                                def sensitiveKey = sensitiveIndex.get(i + 1) + "." + sensitiveIndex.get(i + 2)
                                def condVals = new HashSet<String>()
                                if (adminCondColumns.containsKey(sensitiveKey)) {
                                    condVals.addAll(adminCondColumns.get(sensitiveKey))
                                }
                                condVals.add(condVal)
                                adminCondColumns.put(sensitiveKey, condVals)
                                for (cv in condVals) {
                                    ret.add(cv)
                                }
                            }
                        }
                    }
                }
            }
        }
        if (!hasDef) {
            if (valName.startsWith("\$_SESSION[") && valTableColumnMap.containsKey(valName)) {
                hasDef = true
                def sensitiveIndex = valTableColumnMap.get(valName).getValue()
                for (int i = 0; i < sensitiveIndex.size(); i += 5) {
                    def sensitiveKey = sensitiveIndex.get(i + 1) + "." + sensitiveIndex.get(i + 2)
                    def condVals = new HashSet<String>()
                    if (adminCondColumns.containsKey(sensitiveKey)) {
                        condVals.addAll(adminCondColumns.get(sensitiveKey))
                    }
                    condVals.add(condVal)
                    adminCondColumns.put(sensitiveKey, condVals)
                    ret.add("valName is session")
                    for (cv in condVals) {
                        ret.add(cv)
                    }
                }
            }
            else if (valName.indexOf("[") != -1) {
                ret.add("valName.indexOf(\"[\") != -1 in getValColumns")
                def scopeLocation = node.toFileAbs().next().name
                if (isWithinFunction(node)) {
                    scopeLocation = scopeLocation + "_" + node.functions().next().name + ":" + node.functions().next().lineno
                }
                def array = valName
                def index = ""
                def pendingIndexs = new ArrayList<String>()
                pendingIndexs.add("")
                while (array.indexOf("[") != -1) {
                    index = array.substring(array.lastIndexOf("["))
                    for (int i = 0; i < pendingIndexs.size(); ++i) {
                        pendingIndexs.set(i, index + pendingIndexs.get(i))
                    }
                    pendingIndexs.add("")
                    array = array.substring(0, array.lastIndexOf("["))
                    if (sessionMap.containsKey(scopeLocation+" "+array)) {
                        ret.add(pendingIndexs)
                        def entry = sessionMap.get(scopeLocation+" "+array)
                        def sessionVals = entry.getValue()
                        for (sessionVal in sessionVals) {
                            for (int j = 0; j < pendingIndexs.size(); ++j) {
                                def pendingIndex = pendingIndexs.get(j)
                                def newSessionVal = sessionVal + pendingIndex
                                ret.add(newSessionVal)
                                if (valTableColumnMap.containsKey(newSessionVal)) {
                                    def sensitiveIndex = valTableColumnMap.get(newSessionVal).getValue()
                                    for (int i = 0; i < sensitiveIndex.size(); i += 5) {
                                        if (sensitiveIndex.get(i) != "-1") {
                                            hasDef = true
                                            def sensitiveKey = sensitiveIndex.get(i + 1) + "." + sensitiveIndex.get(i + 2)
                                            def condVals = new HashSet<String>()
                                            if (adminCondColumns.containsKey(sensitiveKey)) {
                                                condVals.addAll(adminCondColumns.get(sensitiveKey))
                                            }
                                            condVals.add(condVal)
                                            adminCondColumns.put(sensitiveKey, condVals)
                                            for (cv in condVals) {
                                                ret.add(cv)
                                            }
                                        }
                                    }
                                    ret.add("session find")
                                    ret.add(adminCondColumns)
                                    break
                                }
                            }
                        }
                        break
                    }
                }
            }
            else {
                if (isWithinFunction(node)) {
                    ret.add("node isWithinFunction in getValColumns")
                    ret.add(getLocation(node))
                }
                else {
                    def file = node.toFileAbs().next()
                    def file_queue = new LinkedList<Vertex>()
                    file_queue.offer(file)
                    while (file_queue.size() > 0) {
                        def current_file = file_queue.poll()
                        for (includeOrRequire in current_file.in("CALLS")) {
                            if (includeOrRequire.type == "AST_INCLUDE_OR_EVAL") {
                                def includeOrRequire_file = includeOrRequire.toFileAbs().next()
                                def includeOrRequire_lineno = includeOrRequire.lineno
                                for (locVal in valTableColumnMap.keySet()) {
                                    if (locVal.startsWith(includeOrRequire_file.name + ":")) {
                                        def lineno = locVal.substring(locVal.indexOf(":") + 1, locVal.indexOf(" "))
                                        def val = locVal.substring(locVal.indexOf(" ") + 1)
                                        if (valName.startsWith(val)) {
                                            if (Integer.parseInt(lineno) <= includeOrRequire_lineno) {
                                                if (valName == val) {
                                                    def entry = valTableColumnMap.get(locVal)
                                                    def sensitiveIndex = entry.getValue()
                                                    for (int i = 0; i < sensitiveIndex.size(); i += 5) {
                                                        if (sensitiveIndex.get(i) != "-1") {
                                                            hasDef = true
                                                            def sensitiveKey = sensitiveIndex.get(i + 1) + "." + sensitiveIndex.get(i + 2)
                                                            def condVals = new HashSet<String>()
                                                            if (adminCondColumns.containsKey(sensitiveKey)) {
                                                                condVals.addAll(adminCondColumns.get(sensitiveKey))
                                                            }
                                                            condVals.add(condVal)
                                                            adminCondColumns.put(sensitiveKey, condVals)
                                                            ret.add("include or eval")
                                                            for (cv in condVals) {
                                                                ret.add(cv)
                                                            }
                                                        }
                                                    }
                                                }
                                                else {
                                                    ret.add("valName not equal to val in getValColumns")
                                                    ret.add(valName)
                                                    ret.add(val)
                                                }
                                            }
                                            else {
                                                ret.add(lineno+" "+val+" > "+includeOrRequire_lineno+" for "+valName+" in getValColumns")
                                            }
                                        }
                                    }
                                }
                                if (!hasDef) {
                                    file_queue.offer(includeOrRequire_file)
                                }
                                else {
                                    break
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else {
        ret.add("valName not start with \$")
        ret.add(valName)
    }
    return hasDef
}

def getControlNodesForCondVar(node, valName, condNodes, valTableColumnMap, sessionMap, nodes, ret) {
    def defNodes = new HashSet<Vertex>()
    def controlNodes = new HashMap<Vertex, Edge>()
    def controlNodesQueue = new LinkedList<Vertex>()
    def scopeLocation = node.toFileAbs().next().name
    if (isWithinFunction(node)) {
        scopeLocation = scopeLocation + "_" + node.functions.next().name + ":" + node.functions().next().lineno
    }
    for (v in node.in("REACHES")) {
        if (v.type == "AST_ASSIGN") {
            def assignName = getAllValName(v.ithChildren(0).next())
            System.out.println(assignName)
            if (assignName == valName) {
                defNodes.add(v)
                controlNodesQueue.offer(v)
                if (nodes && nodes.contains(v)) {
                    ret.add("nodes contains v")
                    controlNodes.put(v, null)
                }
            }
            else {

            }
        }
        else {
            ret.add("other type in getControlNodesForCondVar")
            ret.add(getLocation(v))
            System.out.println("other type in getControlNodesForCondVar")
            System.out.println(getLocation(v))
        }
    }
    if (defNodes.size() == 0) {
        if (valTableColumnMap.containsKey(valName)) {
            def entry = valTableColumnMap.get(valName)
            defNodes.add(entry.getKey())
            controlNodesQueue.offer(entry.getKey())
        }
        else if (sessionMap.containsKey(scopeLocation+" "+valName)) {
            def entry = sessionMap.get(scopeLocation+" "+valName)
            defNodes.add(entry.getKey())
            controlNodesQueue.offer(entry.getKey())
        }
        else if (sessionMap.containsKey(valName)) {
            def entry = sessionMap.get(valName)
            defNodes.add(entry.getKey())
            controlNodesQueue.offer(entry.getKey())
        }
    }
    System.out.println("defNodes "+defNodes)

    while (controlNodesQueue.size() > 0) {
        def currentVertex = controlNodesQueue.poll()
        System.out.println(getLocation(currentVertex))
        for (v in currentVertex.in("CONTROLS")) {
            def controlEdges = currentVertex.inE("CONTROLS").toList()
            for (edge in controlEdges) {
                if (edge.outV().next().id == v.id) {
                    if (v.type != "CFG_FUNC_ENTRY" && !condNodes.contains(v)) {
                        condNodes.add(v)
                        controlNodes.put(v, edge)
                        controlNodesQueue.offer(v)
                    }
                }
            }
        }
    }
    return controlNodes
}

def getControlNodesForCall(node, condNodes, ret) {
    def controlNodes = new HashMap<Vertex, Edge>()
    def controlNodesQueue = new LinkedList<Vertex>()
    def thisNodes = new HashSet<Vertex>()
    for (func in node.out("CALLS")) {
        def funcExit = func.out("EXIT").next()
        for (r in funcExit.in("FLOWS_TO")) {
            controlNodesQueue.offer(r)
            if (r.type == "AST_RETURN") {
                def val = r.ithChildren(0).next()
                if (val.type == "AST_PROP") {
                    def obj = val.ithChildren(0).next()
                    def objName = getAllValName(obj)
                    if (objName == "\$this") {
                        def prop = val.ithChildren(1).next()
                        def propName = getAllValName(prop)
                        def className = obj.classname
                        if (className) {
                            def classNodes = g.V().filter{it.classname && it.classname == className}.statements().toList()
                            classNodes = classNodes.unique()
                            for (classNode in classNodes) {
                                if (classNode.type == "AST_ASSIGN") {
                                    def assignName = getAllValName(classNode.ithChildren(0).next())
                                    if (assignName == objName+"->"+propName || assignName == propName) {
                                        controlNodesQueue.offer(classNode)
                                        thisNodes.add(classNode)
                                        ret.add(getLocation(classNode))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    while (controlNodesQueue.size() > 0) {
        def currentVertex = controlNodesQueue.poll()
        for (v in currentVertex.in("CONTROLS")) {
            def controlEdges = currentVertex.inE("CONTROLS").toList()
            for (edge in controlEdges) {
                if (edge.outV().next().id == v.id) {
                    if (v.type != "CFG_FUNC_ENTRY" && !condNodes.contains(v)) {
                        condNodes.add(v)
                        controlNodes.put(v, edge)
                        if (!thisNodes.contains(currentVertex)) {
                            controlNodesQueue.offer(v)
                        }
                    }
                }
            }
        }
    }
    return controlNodes
}

def parseCondInQuery(node, query_info, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, condColumnsMap, ret) {
    ret.add("*********************parseCondInQuery start*********************")
    def hasCheck = false
    if (statusColumn != "") {
        if (query_info instanceof WhereInfo) {
            def whereInfo = (WhereInfo) query_info
            def tables = whereInfo.getTNames()

            if (tables.contains(parentTable)) {
                def conditionCols = whereInfo.getConditionCols()
                def conditionVals = whereInfo.getConditionVals()
                for (int i = 0; i < conditionCols.size(); ++i) {
                    def conditionCol = conditionCols.get(i)
                    if (conditionCol == parentTable + "." + statusColumn) {
                        def val = conditionVals.get(i)
                        def vals = getAllValsInCond(val)
                        ret.add(val)
                        hasCheck = true
                    }
                }
            }
        }
    }
    else {
        def whereInfo = (WhereInfo) query_info
        def tables = whereInfo.getTNames()

        ret.add("tables: "+tables)
        ret.add("childTable: "+childTable+" "+childColumn+" "+childOwnColumn)
        ret.add("parentTable: "+parentTable+" "+parentKey)
        if (tables.contains(childTable)) {
            def conditionCols = whereInfo.getConditionCols()
            def conditionVals = whereInfo.getConditionVals()
            for (int i = 0; i < conditionCols.size(); ++i) {
                def conditionCol = conditionCols.get(i)
                def conditionVal = conditionVals.get(i)
                ret.add(conditionCol+" "+conditionVal)
                if (conditionCol == childTable + "." + childOwnColumn) {
                    def vals = getAllValsInCond(conditionVal)
                    for (v in vals) {
                        def condColumns = new HashMap<String, HashSet<String>>()
                        def hasDef = false
                        ret.add("nodeCond1 : "+getLocation(node))
                        if (condColumnsMap.containsKey(node)) {
                            condColumns = condColumnsMap.get(node).clone()
                            if (condColumns.size() > 0) {
                                hasDef = true
                            }
                        }
                        hasDef = getValColumns(node, v, valTableColumnMap, sessionMap, condColumns, "''", ret) || hasDef
                        condColumnsMap.put(node, condColumns)
                        if (hasDef) {
                            ret.add(v + " has def")
                            ret.add(condColumns)
                            for (condColumn in condColumns.keySet()) {
                                if (condColumn == parentTable + "." + parentKey) {
                                    hasCheck = true
                                }
                            }
                        }
                        else {
                            if (v.startsWith("\$GLOBALS")) {
                                hasCheck = true
                            }
                            ret.add(v + " has no def")
                        }
                    }
                    if (conditionVal instanceof String) {
                        if (conditionVal.startsWith(":") || conditionVal.startsWith("?")) {
                            hasCheck = true
                        }
                        if (conditionVal == parentTable + "." + parentKey) {
                            hasCheck = true
                        }
                    }
                }
                else if (conditionVal instanceof String && (conditionVal == childTable + "." + childOwnColumn)) {
                    if (conditionCol == parentTable + "." + parentKey) {
                        hasCheck = true
                    }
                }
            }
        }
    }
    ret.add("*********************parseCondInQuery over*********************")
    return hasCheck
}

def parseCondNodes(node, edge, pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret) {
    def edgeVar = ""
    if (edge && edge.getProperty("var")) {
        edgeVar = edge.getProperty("var")
    }
    if (node.type == "AST_BINARY_OP" && node.flags != null) {
        if (node.flags.contains("BINARY_IS_EQUAL")
                || node.flags.contains("BINARY_IS_NOT_EQUAL")
                || node.flags.contains("BINARY_IS_SMALLER")
                || node.flags.contains("BINARY_IS_GREATER")
                || node.flags.contains("BINARY_IS_IDENTICAL")
                || node.flags.contains("BINARY_IS_NOT_IDENTICAL")
        ) {
            def leftNode = node.ithChildren(0).next()
            def rightNode = node.ithChildren(1).next()
            def leftValName = getAllValName(leftNode)
            def rightValName = getAllValName(rightNode)
            def leftCondColumns = new HashMap<String, HashSet<String>>()
            def leftHasDef = false
            def hasCheck = false
            ret.add("nodeCond2 : "+getLocation(leftNode))
            if (condColumnsMap.containsKey(leftNode)) {
                leftCondColumns = condColumnsMap.get(leftNode).clone()
                if (leftCondColumns.size() > 0) {
                    leftHasDef = true
                }
            }
            else {
                leftHasDef = getValColumns(getStatement(node), leftValName, valTableColumnMap, sessionMap, leftCondColumns, "left", ret)
                condColumnsMap.put(leftNode, leftCondColumns)
            }
            if (leftHasDef) {
                ret.add(leftValName+" has def")
                ret.add(leftCondColumns)
                if (statusColumn != "") {
                    for (leftCondColumn in leftCondColumns.keySet()) {
                        if (leftCondColumn == parentTable + "." + statusColumn) {
                            hasCheck = true
                        }
                    }
                }
            }
            else {
                if (leftValName.startsWith("\$")) {
                    ret.add(leftValName+" has no def")
                }
                else if (leftNode.type == "AST_CALL" || leftNode.type == "AST_METHOD_CALL" || leftNode.type == "AST_STATIC_CALL") {
                    def funcName = getFuncName(leftNode)
                    if (sql_num_rows_funcs.contains(funcName)) {
                        ret.add("sql_num_rows_funcs")
                        ret.add(funcName)
                        if (leftNode.numArguments().next() > 0) {
                            ret.add(getAllValName(leftNode.ithArguments(0).next()))
                        }
                        else if (leftNode.type == "AST_METHOD_CALL") {
                            ret.add(getAllValName(leftNode.ithChildren(0).next()))
                        }
                        def leftStatement = getStatement(leftNode)
                        def leftLocation = leftStatement.toFileAbs().next().name + ":" + leftStatement.lineno
                        if (sqlNumRowsMap.containsKey(leftLocation + " " + funcName)) {
                            def sqlNumRows = sqlNumRowsMap.get(leftLocation + " " + funcName)
                            def rightNum = getNum(rightValName, ret)
                            def hasSqlNumRowsCheck = false
                            ret.add(node.flags)
                            ret.add(rightNum)
                            ret.add(pass)
                            ret.add(edgeVar)
                            if (node.flags.contains("BINARY_IS_EQUAL") || node.flags.contains("BINARY_IS_IDENTICAL")) {
                                if (rightNum > 0 && pass && edgeVar == "True") {
                                    hasSqlNumRowsCheck = true
                                }
                                else if (rightNum == 0 && !pass && edgeVar == "True") {
                                    hasSqlNumRowsCheck = true
                                }
                            }
                            else if (node.flags.contains("BINARY_IS_NOT_EQUAL") || node.flags.contains("BINARY_IS_NOT_IDENTICAL")) {
                                if (rightNum == 0 && pass && edgeVar == "True") {
                                    hasSqlNumRowsCheck = true
                                }
                            }
                            ret.add("sqlNumRows")
                            ret.add(hasSqlNumRowsCheck)
                            for (sqlNumRow in sqlNumRows) {
                                ret.add(sqlNumRow)
                                def selectNode = nodes[sqlNumRow]
                                ret.add(getLocation(selectNode))
                                def query_info = QueryProcessing.querys.get(sqlNumRow)
                                def hasNumCheck = parseCondInQuery(selectNode, query_info, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, condColumnsMap, ret)
                                if (hasNumCheck) {
                                    hasSqlNumRowsCheck = hasSqlNumRowsCheck && hasNumCheck
                                    ret.add(hasNumCheck)
                                    continue
                                }
                                def controlNodesOfSelect = getControlNodes(selectNode, ret)
                                for (controlNode in controlNodesOfSelect.keySet()) {
                                    def controlEdge = controlNodesOfSelect.get(controlNode)
                                    def controlVar = ""
                                    if (controlEdge && controlEdge.getProperty("var")) {
                                        controlVar = controlEdge.getProperty("var")
                                    }
                                    def condString = controlNode.id + controlVar + pass + parentTable + parentKey + statusColumn + childTable + childColumn + childOwnColumn + manyTable + manyKey + manyOwnColumn
                                    if (condStringsMap.containsKey(condString)) {
                                        hasNumCheck = condStringsMap.get(condString)
                                    } else {
                                        hasNumCheck = parseCondNodes(controlNode, controlEdge, pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                                        condStringsMap.put(condString, hasNumCheck)
                                    }
                                    if (hasNumCheck) {
                                        break
                                    }
                                }
                                ret.add(hasNumCheck)
                                hasSqlNumRowsCheck = hasSqlNumRowsCheck && hasNumCheck
                            }
                            if (hasSqlNumRowsCheck) {
                                return true
                            }
                        }
                    }
                    else {
                        ret.add(funcName+" not sql_num_rows_funcs")
                    }
                }
                else {
                    ret.add("other leftNode "+getLocation(leftNode))
                }
            }
            def rightCondColumns = new HashMap<String, HashSet<String>>()
            def rightHasDef = false
            ret.add("nodeCond3 : "+getLocation(rightNode))
            if (condColumnsMap.containsKey(rightNode)) {
                rightCondColumns = condColumnsMap.get(rightNode).clone()
                if (rightCondColumns.size() > 0) {
                    rightHasDef = true
                }
            }
            else {
                rightHasDef = getValColumns(getStatement(node), rightValName, valTableColumnMap, sessionMap, rightCondColumns, "right", ret)
                condColumnsMap.put(rightNode, rightCondColumns)
            }
            if (rightHasDef) {
                ret.add(rightValName+" has def")
                ret.add(rightCondColumns)
                if (statusColumn != "") {
                    for (rightCondColumn in rightCondColumns.keySet()) {
                        if (rightCondColumn == parentTable + "." + statusColumn) {
                            hasCheck = true
                        }
                    }
                }
            }
            else {
                if (rightValName.startsWith("\$")) {
                    ret.add(rightValName+" has no def")
                }
                else {
                    ret.add("other rightNode "+getLocation(rightNode))
                }
            }
            if (adminCondColumns.size() > 0) {
                def isAdminCondCheck = true
                for (adminCondColumn in adminCondColumns.keySet()) {
                    def adminCondVals = adminCondColumns.get(adminCondColumn)
                    def isAdminCond = false
                    for (leftCondColumn in leftCondColumns.keySet()) {
                        if (adminCondColumn == leftCondColumn) {
                            if (adminCondVals.contains(rightValName)) {
                                if ((node.flags.contains("BINARY_IS_EQUAL") || node.flags.contains("BINARY_IS_IDENTICAL")) && pass && edgeVar == "True") {
                                    isAdminCond = true
                                }
                                else if ((node.flags.contains("BINARY_IS_NOT_EQUAL") || node.flags.contains("BINARY_IS_NOT_IDENTICAL")) && !pass && edgeVar == "True") {
                                    isAdminCond = true
                                }
                            }
                        }
                    }
                    for (rightCondColumn in rightCondColumns.keySet()) {
                        if (adminCondColumn == rightCondColumn) {
                            if (adminCondVals.contains(leftValName)) {
                                if ((node.flags.contains("BINARY_IS_EQUAL") || node.flags.contains("BINARY_IS_IDENTICAL")) && pass) {
                                    isAdminCond = true
                                }
                                else if ((node.flags.contains("BINARY_IS_NOT_EQUAL") || node.flags.contains("BINARY_IS_NOT_IDENTICAL")) && !pass) {
                                    isAdminCond = true
                                }
                            }
                        }
                    }
                    isAdminCondCheck = isAdminCondCheck && isAdminCond
                    if (!isAdminCondCheck) {
                        break
                    }
                }
                if (isAdminCondCheck) {
                    ret.add("@@@@@@@@@@@@@@@@@@@@@@@@isAdminCondCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                    return true
                }
            }
            return hasCheck
        }
        else if (node.flags.contains("BINARY_BOOL_AND")) {
            def hasCheck = false
            def controlVar = ""
            if (edge && edge.getProperty("var")) {
                controlVar = edge.getProperty("var")
            }
            def condString = node.ithChildren(0).next().id+controlVar+pass+parentTable+parentKey+statusColumn+childTable+childColumn+childOwnColumn+manyTable+manyKey+manyOwnColumn
            if (condStringsMap.containsKey(condString)) {
                hasCheck = condStringsMap.get(condString)
            }
            else {
                hasCheck = parseCondNodes(node.ithChildren(0).next(), edge, pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                condStringsMap.put(condString, hasCheck)
            }
            condString = node.ithChildren(1).next().id+controlVar+pass+parentTable+parentKey+statusColumn+childTable+childColumn+childOwnColumn+manyTable+manyKey+manyOwnColumn
            if (condStringsMap.containsKey(condString)) {
                if (statusColumn != "") {
                    hasCheck = condStringsMap.get(condString) || hasCheck
                }
                else {
                    hasCheck = condStringsMap.get(condString) && hasCheck
                }
            }
            else {
                def hasCheck2 = parseCondNodes(node.ithChildren(1).next(), edge, pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                if (statusColumn != "") {
                    hasCheck = hasCheck2 || hasCheck
                }
                else {
                    hasCheck = hasCheck2 && hasCheck
                }
                condStringsMap.put(condString, hasCheck)
            }
            return hasCheck
        }
        else if (node.flags.contains("BINARY_BOOL_OR")) {
            def hasCheck = false
            def controlVar = ""
            if (edge && edge.getProperty("var")) {
                controlVar = edge.getProperty("var")
            }
            def condString = node.ithChildren(0).next().id+controlVar+pass+parentTable+parentKey+statusColumn+childTable+childColumn+childOwnColumn+manyTable+manyKey+manyOwnColumn
            if (condStringsMap.containsKey(condString)) {
                hasCheck = condStringsMap.get(condString)
            }
            else {
                hasCheck = parseCondNodes(node.ithChildren(0).next(), edge, pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                condStringsMap.put(condString, hasCheck)
            }
            condString = node.ithChildren(1).next().id+controlVar+pass+parentTable+parentKey+statusColumn+childTable+childColumn+childOwnColumn+manyTable+manyKey+manyOwnColumn
            if (condStringsMap.containsKey(condString)) {
                hasCheck = hasCheck || condStringsMap.get(condString)
            }
            else {
                hasCheck = hasCheck || parseCondNodes(node.ithChildren(1).next(), edge, pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                condStringsMap.put(condString, hasCheck)
            }
            return hasCheck
        }
        else {
            ret.add("other binary op in parseCondNodes")
            ret.add(getLocation(node))
            ret.add(node.flags)
        }
    }
    else if (node.type == "AST_UNARY_OP" && node.flags != null) {
        if (node.flags.contains("UNARY_BOOL_NOT") || node.flags.contains("UNARY_SILENCE")) {
            return parseCondNodes(node.ithChildren(0).next(), edge, !pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
        }
        else {
            ret.add("other unary op in parseCondNodes")
            ret.add(getLocation(node))
            ret.add(node.flags)
        }
    }
    else if (node.type == "AST_ISSET") {
        ret.add("isset in parseCondNodes begin")
        ret.add(getAllValName(node.ithChildren(0).next()))
        def statement = getStatement(node)
        def valName = getAllValName(node.ithChildren(0).next())
        def controlNodes = getControlNodesForCondVar(statement, valName, new HashSet<Vertex>(), valTableColumnMap, sessionMap, nodes, ret)
        def hasOneCheck = false
        for (controlNode in controlNodes.keySet()) {
            def controlEdge = controlNodes.get(controlNode)
            def controlVar = ""
            if (controlEdge && controlEdge.getProperty("var")) {
                controlVar = controlEdge.getProperty("var")
            }
            def hasCheck = false
            def condString = controlNode.id+controlVar+pass+parentTable+parentKey+statusColumn+childTable+childColumn+childOwnColumn+manyTable+manyKey+manyOwnColumn
            if (condStringsMap.containsKey(condString)) {
                hasCheck = condStringsMap.get(condString)
            }
            else {
                hasCheck = parseCondNodes(controlNode, controlEdge, pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                condStringsMap.put(condString, hasCheck)
            }
            ret.add("controlNode in isset "+getLocation(controlNode))
            ret.add(condString)
            ret.add(hasCheck)
            hasOneCheck = hasOneCheck || hasCheck
            if (hasCheck) {
                break
            }
        }
        ret.add("isset in parseCondNodes end")
        return hasOneCheck
    }
    else if (node.type == "AST_CALL" || node.type == "AST_METHOD_CALL" || node.type == "AST_STATIC_CALL") {
        def funcName = getFuncName(node)
        ret.add("call in parseCondNodes "+funcName)
        if (funcName == "current_user_can") {
            return true
        }
        if (funcName == "strlen") {
            def statement = getStatement(node)
            def valName = getAllValName(node.ithChildren(0).next())
            def controlNodes = getControlNodesForCondVar(statement, valName, new HashSet<Vertex>(), valTableColumnMap, sessionMap, nodes, ret)
            def hasOneCheck = false
            for (controlNode in controlNodes.keySet()) {
                def controlEdge = controlNodes.get(controlNode)
                def controlVar = ""
                if (controlEdge && controlEdge.getProperty("var")) {
                    controlVar = controlEdge.getProperty("var")
                }
                def hasCheck = false
                def condString = controlNode.id+controlVar+pass+parentTable+parentKey+statusColumn+childTable+childColumn+childOwnColumn+manyTable+manyKey+manyOwnColumn
                if (condStringsMap.containsKey(condString)) {
                    hasCheck = condStringsMap.get(condString)
                }
                else {
                    hasCheck = parseCondNodes(controlNode, controlEdge, pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                    condStringsMap.put(condString, hasCheck)
                }
                hasOneCheck = hasOneCheck || hasCheck
                if (hasCheck) {
                    break
                }
            }
            return hasOneCheck
        }
        else {
            def controlNodes = getControlNodesForCall(node, condNodes, ret)
            def hasOneCheck = false
            for (controlNode in controlNodes.keySet()) {
                def controlEdge = controlNodes.get(controlNode)
                def controlVar = ""
                if (controlEdge && controlEdge.getProperty("var")) {
                    controlVar = controlEdge.getProperty("var")
                }
                def hasCheck = false
                def condString = controlNode.id+controlVar+pass+parentTable+parentKey+statusColumn+childTable+childColumn+childOwnColumn+manyTable+manyKey+manyOwnColumn
                if (condStringsMap.containsKey(condString)) {
                    hasCheck = condStringsMap.get(condString)
                }
                else {
                    hasCheck = parseCondNodes(controlNode, controlEdge, pass, condNodes, parentTable, parentKey, statusColumn, childTable, childColumn, childOwnColumn, manyTable, manyKey, manyOwnColumn, valTableColumnMap, sessionMap, adminCondColumns, condColumnsMap, sql_num_rows_funcs, nodes, sqlNumRowsMap, condStringsMap, ret)
                    condStringsMap.put(condString, hasCheck)
                }
                hasOneCheck = hasOneCheck || hasCheck
                if (hasCheck) {
                    break
                }
            }
            return hasOneCheck
        }
    }
    else {
        ret.add("other node in parseCondNodes")
        ret.add(getLocation(node))
        def valName = getAllValName(node)
        def condColumns = new HashMap<String, HashSet<String>>()
        def hasDef = false
        def hasCheck = false
        ret.add("nodeCond4 : "+getLocation(node))
        if (condColumnsMap.containsKey(node)) {
            condColumns = condColumnsMap.get(node).clone()
            if (condColumns.size() > 0) {
                hasDef = true
            }
        }
        else {
            hasDef = getValColumns(getStatement(node), valName, valTableColumnMap, sessionMap, condColumns, "''", ret)
            condColumnsMap.put(node, condColumns)
        }
        if (hasDef) {
            ret.add(valName+" has def")
            ret.add(condColumns)
            ret.add(parentTable+"."+statusColumn)
            if (statusColumn != "") {
                for (condColumn in condColumns.keySet()) {
                    if (condColumn == parentTable + "." + statusColumn) {
                        hasCheck = true
                    }
                }
            }
        }
        else {
            if (valName.startsWith("\$")) {
                ret.add(valName+" has no def")
            }
        }
        if (adminCondColumns.size() > 0) {
            def isAdminCondCheck = true
            for (adminCondColumn in adminCondColumns.keySet()) {
                def adminCondVals = adminCondColumns.get(adminCondColumn)
                def isAdminCond = false
                for (condColumn in condColumns.keySet()) {
                    if (adminCondColumn == condColumn) {
                        if (adminCondVals.size() == 0) {
                            isAdminCond = true
                        }
                        else {
                            if (adminCondVals.contains("")) {
                                isAdminCond = true
                            }
                        }
                    }
                }
                isAdminCondCheck = isAdminCondCheck && isAdminCond
                if (!isAdminCondCheck) {
                    break
                }
            }
            if (isAdminCondCheck) {
                ret.add("@@@@@@@@@@@@@@@@@@@@@@@@isAdminCondCheck@@@@@@@@@@@@@@@@@@@@@@@@@@@")
                return true
            }
        }
        return hasCheck
    }
    return false
}

def getCondColumns(node, condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, condVal, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret) {
    def location = node.toFileAbs().next().name + ":" + node.lineno
    if (node.type == "AST_BINARY_OP" && node.flags != null) {
        if (node.flags.contains("BINARY_IS_EQUAL")
                || node.flags.contains("BINARY_IS_NOT_EQUAL")
                || node.flags.contains("BINARY_IS_SMALLER")
                || node.flags.contains("BINARY_IS_GREATER")
                || node.flags.contains("BINARY_IS_IDENTICAL")
                || node.flags.contains("BINARY_IS_NOT_IDENTICAL")
        ) {
            def leftValName = getAllValName(node.ithChildren(0).next())
            def rightValName = getAllValName(node.ithChildren(1).next())
            if ((node.ithChildren(1).next().type == "string" || node.ithChildren(1).next().type == "integer" || node.ithChildren(1).next().type == "AST_CONST") && rightValName != "") {
                getCondColumns(node.ithChildren(0).next(), condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, rightValName, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
            }
            else if ((node.ithChildren(0).next().type == "string" || node.ithChildren(0).next().type == "integer" || node.ithChildren(0).next().type == "AST_CONST") && leftValName != "") {
                getCondColumns(node.ithChildren(1).next(), condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, leftValName, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
            }
            else {
                ret.add("other binary equal op")
                ret.add(getLocation(node.ithChildren(0).next()))
                ret.add(getLocation(node.ithChildren(1).next()))
            }
        }
        else if (node.flags.contains("BINARY_BITWISE_AND")) {
            def leftValName = getAllValName(node.ithChildren(0).next())
            def rightValName = getAllValName(node.ithChildren(1).next())
            getCondColumns(node.ithChildren(0).next(), condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, rightValName, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
            getCondColumns(node.ithChildren(1).next(), condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, leftValName, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
        }
        else if (node.flags.contains("BINARY_BOOL_AND") || node.flags.contains("BINARY_BOOL_OR")) {
            getCondColumns(node.ithChildren(0).next(), condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, condVal, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
            getCondColumns(node.ithChildren(1).next(), condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, condVal, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
        }
        else {
            ret.add("other binary op in getCondColumns")
            ret.add(getLocation(node))
        }
    }
    else if (node.type == "AST_UNARY_OP" && node.flags != null) {
        if (node.flags.contains("UNARY_BOOL_NOT") || node.flags.contains("UNARY_SILENCE")) {
            getCondColumns(node.ithChildren(0).next(), condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, condVal, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
        }
        else {
            ret.add("other unary op")
            ret.add(getLocation(node))
        }
    }
    else if (node.type == "AST_ISSET") {
        def statement = getStatement(node)
        def valName = getAllValName(node.ithChildren(0).next())
        def controlNodes = getControlNodesForCondVar(statement, valName, condNodes, valTableColumnMap, sessionMap, null, ret)
        for (controlNode in controlNodes.keySet()) {
            ret.add("getControlNodesForCondVar : "+getLocation(controlNode))
            def condColumns = new HashMap<String, HashSet<String>>()
            if (condColumnsMap.containsKey(controlNode)) {
                condColumns = condColumnsMap.get(controlNode).clone()
            }
            else {
                getCondColumns(controlNode, condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, condColumns, condColumnsMap, condVal, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
                condColumnsMap.put(controlNode, condColumns)
            }
            for (condColumn in condColumns.keySet()) {
                def condVals = new HashSet<String>(condColumns.get(condColumn))
                if (adminCondColumns.containsKey(condColumn)) {
                    def adminCondVals = new HashSet<String>()
                    adminCondVals.addAll(adminCondColumns.get(condColumn))
                    adminCondVals.addAll(condVals)
                    adminCondColumns.put(condColumn, adminCondVals)
                }
                else {
                    adminCondColumns.put(condColumn, condVals)
                }
            }
        }
    }
    else if (node.type == "AST_CALL" || node.type == "AST_METHOD_CALL" || node.type == "AST_STATIC_CALL") {
        def funcName = getFuncName(node)
        if (sql_num_rows_funcs.contains(funcName) || (isDAL && dal_sql_num_rows_funcs.contains(funcName))) {
            ret.add("sql_num_rows_funcs")
            def callerStatement = getStatement(node)
            def callerLocation = callerStatement.toFileAbs().next().name + ":" + callerStatement.lineno
            if (sqlNumRowsMap.containsKey(callerLocation+" "+funcName)) {
                def sqlNumRows = sqlNumRowsMap.get(callerLocation+" "+funcName)
                ret.add("sqlNumRows")
                ret.add(sqlNumRows)
                for (sqlNumRow in sqlNumRows) {
                    def query_info = QueryProcessing.querys.get(sqlNumRow)
                    def whereInfo = (WhereInfo) query_info
                    def tables = whereInfo.getTNames()
                    for (table in tables) {
                        if (PrimaryKeysMap.containsKey(table)) {
                            def key = PrimaryKeysMap.get(table)
                            def condVals = new HashSet<String>()
                            if (adminCondColumns.containsKey(table+"."+key)) {
                                condVals.addAll(adminCondColumns.get(table+"."+key))
                            }
                            condVals.add(condVal)
                            adminCondColumns.put(table+"."+key, condVals)
                            ret.add(table+"."+key)
                        }
                    }
                }
            }
            return
        }
        ret.add("call in getCondColumns "+funcName)
        if (funcName == "strlen") {
            def statement = getStatement(node)
            def valName = getAllValName(node.ithChildren(0).next())
            def controlNodes = getControlNodesForCondVar(statement, valName, condNodes, valTableColumnMap, sessionMap, null, ret)
            for (controlNode in controlNodes.keySet()) {
                ret.add("getControlNodesForCondVar : "+getLocation(controlNode))
                def condColumns = new HashMap<String, HashSet<String>>()
                if (condColumnsMap.containsKey(controlNode)) {
                    condColumns = condColumnsMap.get(controlNode).clone()
                }
                else {
                    getCondColumns(controlNode, condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, condColumns, condColumnsMap, condVal, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
                    condColumnsMap.put(controlNode, condColumns)
                }
                for (condColumn in condColumns.keySet()) {
                    def condVals = new HashSet<String>(condColumns.get(condColumn))
                    if (adminCondColumns.containsKey(condColumn)) {
                        def adminCondVals = new HashSet<String>()
                        adminCondVals.addAll(adminCondColumns.get(condColumn))
                        adminCondVals.addAll(condVals)
                        adminCondColumns.put(condColumn, adminCondVals)
                    }
                    else {
                        adminCondColumns.put(condColumn, condVals)
                    }
                }
            }
        }
        else {
            def controlNodes = getControlNodesForCall(node, condNodes, ret)
            for (controlNode in controlNodes.keySet()) {
                ret.add("getControlNodesForCall : "+getLocation(controlNode))
                def condColumns = new HashMap<String, HashSet<String>>()
                if (condColumnsMap.containsKey(controlNode)) {
                    condColumns = condColumnsMap.get(controlNode).clone()
                }
                else {
                    getCondColumns(controlNode, condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, condColumns, condColumnsMap, condVal, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
                    condColumnsMap.put(controlNode, condColumns)
                }
                for (condColumn in condColumns.keySet()) {
                    def condVals = new HashSet<String>(condColumns.get(condColumn))
                    if (adminCondColumns.containsKey(condColumn)) {
                        def adminCondVals = new HashSet<String>()
                        adminCondVals.addAll(adminCondColumns.get(condColumn))
                        adminCondVals.addAll(condVals)
                        adminCondColumns.put(condColumn, adminCondVals)
                    }
                    else {
                        adminCondColumns.put(condColumn, condVals)
                    }
                }
            }
        }
    }
    else {
        def valName = getAllValName(node)
        def statement = getStatement(node)
        def condColumns = new HashMap<String, HashSet<String>>()
        def hasDef = false
        ret.add("nodeCond : "+getLocation(node))
        if (condColumnsMap.containsKey(node)) {
            condColumns = condColumnsMap.get(node).clone()
            ret.add("condColumns size is "+condColumns.size())
            if (condColumns.size() > 0) {
                hasDef = true
            }
        }
        else {
            hasDef = getValColumns(statement, valName, valTableColumnMap, sessionMap, condColumns, condVal, ret)
            condColumnsMap.put(node, condColumns)
        }
        for (condColumn in condColumns.keySet()) {
            def condVals = new HashSet<String>(condColumns.get(condColumn))
            if (adminCondColumns.containsKey(condColumn)) {
                def adminCondVals = adminCondColumns.get(condColumn)
                adminCondVals.addAll(condVals)
                adminCondColumns.put(condColumn, adminCondVals)
            }
            else {
                adminCondColumns.put(condColumn, condVals)
            }
        }
        if (hasDef) {
            ret.add("exist")
            ret.add(getLocation(node)+" "+valName)
            ret.add(condVal)
            ret.add(condColumns)
            for (cc in condColumns.keySet()) {
                ret.add(cc)
                for (value in condColumns.get(cc)) {
                    ret.add(value)
                }
            }
        }
        else {
            ret.add("other node in getCondColumns")
            ret.add(getLocation(node)+" "+valName)
        }
    }
}

def getControlNodes(node, ret) {
    def controlNodes = new HashMap<Vertex, Edge>()
    def controlNodesQueue = new LinkedList<Vertex>()
    controlNodesQueue.offer(node)
    while (controlNodesQueue.size() > 0) {
        def currentVertex = controlNodesQueue.poll()
        for (v in currentVertex.in("CONTROLS")) {
            def controlEdges = currentVertex.inE("CONTROLS").toList()
            for (edge in controlEdges) {
                if (edge.outV().next().id == v.id) {
                    if (v.type != "CFG_FUNC_ENTRY") {
                        if (!controlNodes.containsKey(v)) {
                            controlNodes.put(v, edge)
                            controlNodesQueue.offer(v)
                        }
                    }
                    break
                }
            }
        }
    }
    return controlNodes
}

def printVulnerableResult(vulnerableResult, ret) {
    for (result in vulnerableResult) {
        ret.add("###################")
        ret.add(result.getKey())
        ret.add(result.getValue())
    }
}

def hasAdminCheck(condColumns, adminCondColumns) {
    if (adminCondColumns.size() == 0) {
        return false
    }
    def hasAllAdminCheck = true
    for (adminCondColumn in adminCondColumns.keySet()) {
        def adminCondVals = adminCondColumns.get(adminCondColumn)
        if (condColumns.containsKey(adminCondColumn)) {
            def condVals = condColumns.get(adminCondColumn)
            def isAdminVal = true
            for (adminCondVal in adminCondVals) {
                if (!condVals.contains(adminCondVal)) {
                    isAdminVal = false
                    break
                }
            }
            hasAllAdminCheck = hasAllAdminCheck && isAdminVal
            if (!hasAllAdminCheck) {
                break
            }
        }
        else {
            hasAllAdminCheck = false
            break
        }
    }
    return hasAllAdminCheck
}

def findAdminCondColumns(node, sql_query, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, adminCondColumns, condColumnsMap, exit_funcs, header_statements, sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret) {
    def terminateNodes = new HashSet<Vertex>()
    terminateNodes.add(node)
    def terminateNodesQueue = new LinkedList<Vertex>()
    terminateNodesQueue.offer(node)
    def controlNodes = new HashSet<Vertex>()
    def controlNodesQueue = new LinkedList<Vertex>()
    def condNodes = new HashSet<Vertex>()
    controlNodesQueue.offer(node)
    ret.add("****************************findAdminCondColumns*******************")
    ret.add(sql_query)
    ret.add(getLocation(node))
    System.out.println("****************************findAdminCondColumns*******************")
    System.out.println(sql_query)
    System.out.println(getLocation(node))

    long startTime = System.nanoTime()

    def calleeNodes = new HashSet<Vertex>()
    while (terminateNodesQueue.size() > 0) {
        def currentVertex = terminateNodesQueue.poll()
        for (v in currentVertex.in("FLOWS_TO")) {
            if (v.type == "CFG_FUNC_ENTRY") {
                def func = v.in("ENTRY").next()
                if (isFunction(func) && !calleeNodes.contains(func)) {
                    for (caller in func.in("CALLS")) {
                        if (isCallExpression(caller)) {
                            def callerStatement = getStatement(caller)
                            if (!terminateNodes.contains(callerStatement)) {
                                terminateNodes.add(callerStatement)
                                terminateNodesQueue.offer(callerStatement)
                            }
                        }
                    }
                }
                else if (func.type == "AST_TOPLEVEL" && !calleeNodes.contains(func)) {
                    if (func.in("CALLS").count() == 2) {
                        for (includeOrRequire in func.in("CALLS")) {
                            if (includeOrRequire.type == "AST_INCLUDE_OR_EVAL") {
                                ret.add("includeOrRequire : "+getLocation(includeOrRequire))
                                def includeOrRequireStatement = getStatement(includeOrRequire)
                                if (!terminateNodes.contains(includeOrRequireStatement)) {
                                    terminateNodes.add(includeOrRequireStatement)
                                    terminateNodesQueue.offer(includeOrRequireStatement)
                                }
                            }
                        }
                    }
                }
            }
            else {
                if (!terminateNodes.contains(v)) {
                    if (isExit(v) || isErrorFunc(exit_funcs, v) || header_statements.contains(v)) {
                        if (!controlNodes.contains(v)) {
                            controlNodesQueue.offer(v)
                        }
                    }
                    else {
                        terminateNodes.add(v)
                        terminateNodesQueue.offer(v)
                        if (isCallExpression(v)) {
                            for (func in v.out("CALLS")) {
                                calleeNodes.add(func)
                                def funcExit = func.out("EXIT").next()
                                for (r in funcExit.in("FLOWS_TO")) {
                                    if (!terminateNodes.contains(r)) {
                                        if (isExit(r) || isErrorFunc(exit_funcs, r) || header_statements.contains(r)) {
                                            if (!controlNodes.contains(r)) {
                                                controlNodesQueue.offer(r)
                                            }
                                        }
                                        else {
                                            terminateNodes.add(r)
                                            terminateNodesQueue.offer(r)
                                        }
                                    }
                                }
                            }
                        }
                        if (v.type == "AST_INCLUDE_OR_EVAL") {
                            for (topfile in v.out("CALLS")) {
                                calleeNodes.add(topfile)
                                ret.add("includeOrRequireFile : " + getLocation(topfile))
                                def fileExit = topfile.out("EXIT").next()
                                for (r in fileExit.in("FLOWS_TO")) {
                                    if (!terminateNodes.contains(r)) {
                                        if (isExit(r) || isErrorFunc(exit_funcs, r) || header_statements.contains(r)) {
                                            if (!controlNodes.contains(r)) {
                                                controlNodesQueue.offer(r)
                                            }
                                        }
                                        else {
                                            terminateNodes.add(r)
                                            terminateNodesQueue.offer(r)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    while (controlNodesQueue.size() > 0) {
        def currentVertex = controlNodesQueue.poll()
        def location = getLocation(currentVertex)
        if (location.startsWith("./modules/Students/Student.php:563")) {
            ret.add("currentVertex is "+getLocation(currentVertex))
        }
        for (v in currentVertex.in("CONTROLS")) {
            if (v.type == "CFG_FUNC_ENTRY") {
                if (isFunction(v.in("ENTRY").next()) && !calleeNodes.contains(v.in("ENTRY").next())) {
                    def func = v.in("ENTRY").next()
                    for (caller in func.in("CALLS")) {
                        if (isCallExpression(caller)) {
                            if (!controlNodes.contains(caller)) {
                                controlNodesQueue.offer(getStatement(caller))
                            }
                        }
                    }
                }
            }
            else {
                if (!controlNodes.contains(v)) {
                    controlNodes.add(v)
                    controlNodesQueue.offer(v)
                }
                else {
                    ret.add("controlNodes already contains "+getLocation(v))
                }
            }
        }
    }

    long endTime = System.nanoTime()

    long duration = (endTime - startTime) / 1000000
    ret.add("total: " + duration + " ms")
    System.out.println("total: " + duration + " ms")

    condNodes.addAll(controlNodes)
    for (controlNode in controlNodes) {
        ret.add("controlNode is :" + getLocation(controlNode))
        def condColumns = new HashMap<String, HashSet<String>>()
        if (condColumnsMap.containsKey(controlNode)) {
            condColumns = condColumnsMap.get(controlNode).clone()
        }
        else {
            getCondColumns(controlNode, condNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, PrimaryKeysMap, userTables, condColumns, condColumnsMap, "''", sql_num_rows_funcs, nodes, isWP, isDAL, dal_sql_num_rows_funcs, sqlNumRowsMap, ret)
            condColumnsMap.put(controlNode, condColumns)
        }
        for (condColumn in condColumns.keySet()) {
            def condVals = new HashSet<String>(condColumns.get(condColumn))
            ret.add("condColumn:"+condColumn)
            for (cv in condVals) {
                ret.add(cv)
            }
            if (adminCondColumns.containsKey(condColumn)) {
                def adminCondVals = adminCondColumns.get(condColumn)
                adminCondVals.addAll(condVals)
                adminCondColumns.put(condColumn, adminCondVals)
            }
            else {
                adminCondColumns.put(condColumn, condVals)
            }
        }
        ret.add("admincond")
        for (key in adminCondColumns.keySet()) {
            ret.add(key)
            for (value in adminCondColumns.get(key)) {
                ret.add(value)
            }
        }
    }

    def adminCondColumnsToRm = []
    for (adminCondColumn in adminCondColumns.keySet()) {
        def adminTable = adminCondColumn.substring(0, adminCondColumn.indexOf("."))
        def adminCond = adminCondColumn.substring(adminCondColumn.indexOf(".")+1)
        if (PrimaryKeysMap.containsKey(adminTable) && !PrimaryKeysMap.get(adminTable).equalsIgnoreCase(adminCond)) {
            adminCondColumnsToRm.add(adminTable+"."+PrimaryKeysMap.get(adminTable))
        }
        if (userTables.containsKey(adminTable) && !userTables.get(adminTable).contains(adminCond)) {
            for (userTableKey in userTables.get(adminTable)) {
                adminCondColumnsToRm.add(adminTable+"."+userTableKey)
            }
        }
    }
    for (adminCondColumn in adminCondColumnsToRm) {
        adminCondColumns.remove(adminCondColumn)
    }

    long end2Time = System.nanoTime()
    duration = (end2Time - endTime) / 1000000
    ret.add("total2: " + duration + " ms")
    System.out.println("total2: " + duration + " ms")
}

def findManyToMany(node, conditionCols, conditionVals, defNodes, valTableColumnMap, sql_query, PrimaryKeysMap, queryCondMap, columnValUseMap, userTables, manyToMany, ret) {
    def temp = new HashMap<String, String>()
    for (int i = 0; i < conditionCols.size(); ++i) {
        def val = conditionVals.get(i)
        def vals = getAllValsInCond(val)
        def table = conditionCols.get(i).substring(0, conditionCols.get(i).indexOf("."))
        def column = conditionCols.get(i).substring(conditionCols.get(i).indexOf(".")+1)
        if (vals.size() == 0) {
            if (conditionCols.get(i).indexOf(".") != -1 && val instanceof String && val.indexOf(".") != -1) {
                def valTable = val.substring(0, val.indexOf("."))
                def valColumn = val.substring(val.indexOf(".")+1)
                if (PrimaryKeysMap.containsKey(table) && PrimaryKeysMap.containsKey(valTable)) {
                    if ((PrimaryKeysMap.get(table).equalsIgnoreCase(column) || (userTables.containsKey(table) && userTables.get(table).contains(column)))
                            && table != valTable) {
                        for (key in temp.keySet()) {
                            def tableOfKey = key.substring(0, key.indexOf("."))
                            def columnOfKey = key.substring(key.indexOf(".")+1)
                            def many2 = temp.get(key)
                            if (tableOfKey == valTable && table != many2.substring(0, many2.indexOf("."))) {
                                ret.add(sql_query)
                                ret.add(getLocation(node))
                                ret.add("findManyToMany definitely " + conditionCols.get(i) + " " + valTable + " " + many2)
                                System.out.println(sql_query)
                                System.out.println("findManyToMany definitely " + conditionCols.get(i) + " " + valTable + " " + many2)
                                def many1Sets = new HashSet<>()
                                def many2Sets = new HashSet<>()
                                if (manyToMany.containsKey(conditionCols.get(i))) {
                                    many1Sets.addAll(manyToMany.get(conditionCols.get(i)))
                                }
                                if (manyToMany.containsKey(many2)) {
                                    many2Sets.addAll(manyToMany.get(many2))
                                }
                                many1Sets.add(new AbstractMap.SimpleEntry<String, String>(many2, valTable + " " + valColumn + " " + columnOfKey))
                                many2Sets.add(new AbstractMap.SimpleEntry<String, String>(conditionCols.get(i), valTable + " " + columnOfKey + " " + valColumn))
                                manyToMany.put(conditionCols.get(i), many1Sets)
                                manyToMany.put(many2, many2Sets)
                            }
                        }
                        temp.put(val, conditionCols.get(i))
                    }
                    if ((PrimaryKeysMap.get(valTable).equalsIgnoreCase(valColumn) || (userTables.containsKey(valTable) && userTables.get(valTable).contains(valColumn)))
                            && table != valTable) {
                        for (key in temp.keySet()) {
                            def tableOfKey = key.substring(0, key.indexOf("."))
                            def columnOfKey = key.substring(key.indexOf(".")+1)
                            def many2 = temp.get(key)
                            if (tableOfKey == table && valTable != many2.substring(0, many2.indexOf("."))) {
                                ret.add(sql_query)
                                ret.add(getLocation(node))
                                ret.add("findManyToMany definitely " + val + " " + table + " " + many2)
                                System.out.println(sql_query)
                                System.out.println("findManyToMany definitely " + val + " " + table + " " + many2)
                                def many1Sets = new HashSet<>()
                                def many2Sets = new HashSet<>()
                                if (manyToMany.containsKey(val)) {
                                    many1Sets.addAll(manyToMany.get(val))
                                }
                                if (manyToMany.containsKey(many2)) {
                                    many2Sets.addAll(manyToMany.get(many2))
                                }
                                many1Sets.add(new AbstractMap.SimpleEntry<String, String>(many2, table + " " + column + " " + columnOfKey))
                                many2Sets.add(new AbstractMap.SimpleEntry<String, String>(val, table + " " + columnOfKey + " " + column))
                                manyToMany.put(val, many1Sets)
                                manyToMany.put(many2, many2Sets)
                            }
                        }
                        temp.put(conditionCols.get(i), val)
                    }
                }
            }
        }
    }
    for (int i = 0; i < conditionCols.size(); ++i) {
        def val = conditionVals.get(i)
        def vals = getAllValsInCond(val)
        def table = conditionCols.get(i).substring(0, conditionCols.get(i).indexOf("."))
        def column = conditionCols.get(i).substring(conditionCols.get(i).indexOf(".")+1)
        for (v in vals) {
            if (v.startsWith("\$")) {
                for (defNode in defNodes) {
                    def location = defNode.toFileAbs().next().name + ":" + defNode.lineno
                    def defVal = location + " " + v
                    if (valTableColumnMap.containsKey(defVal)) {
                        def defEntry = valTableColumnMap.get(defVal)
                        def sensitive_index = defEntry.getValue()
                        for (int j = 0; j < sensitive_index.size(); j += 5) {
                            if (sensitive_index.get(j) != "-1") {
                                if (PrimaryKeysMap.containsKey(table)) {
                                    if ((PrimaryKeysMap.get(table).equalsIgnoreCase(column) || (userTables.containsKey(table) && userTables.get(table).contains(column)))
                                            && table != sensitive_index.get(j + 1)) {
                                        def defTableLocation = sensitive_index.get(j + 4)
                                        if (queryCondMap.containsKey(defTableLocation)) {
                                            def condColumns = queryCondMap.get(defTableLocation)
                                            for (condColumn in condColumns) {
                                                def defTable = condColumn.substring(0, condColumn.indexOf("."))
                                                def defColumn = condColumn.substring(condColumn.indexOf(".") + 1)
                                                if (defTable != sensitive_index.get(j + 1) && defTable != table && PrimaryKeysMap.containsKey(defTable) && (PrimaryKeysMap.get(defTable).equalsIgnoreCase(defColumn) || (userTables.containsKey(defTable) && userTables.get(defTable).contains(defColumn)))) {
                                                    ret.add(sql_query)
                                                    ret.add(getLocation(node))
                                                    ret.add("findManyToMany definitely " + conditionCols.get(i) + " " + sensitive_index.get(j + 1) + " " + condColumn)
                                                    System.out.println(sql_query)
                                                    System.out.println("findManyToMany definitely " + conditionCols.get(i) + " " + sensitive_index.get(j + 1) + " " + condColumn)
                                                    def many1Sets = new HashSet<>()
                                                    def many2Sets = new HashSet<>()
                                                    if (manyToMany.containsKey(conditionCols.get(i))) {
                                                        many1Sets.addAll(manyToMany.get(conditionCols.get(i)))
                                                    }
                                                    if (manyToMany.containsKey(condColumn)) {
                                                        many2Sets.addAll(manyToMany.get(condColumn))
                                                    }
                                                    for (relTableColumn in QueryProcessing.tableRelations.get(condColumn)) {
                                                        def relTable = relTableColumn.substring(0, relTableColumn.indexOf("."))
                                                        def relColumn = relTableColumn.substring(relTableColumn.indexOf(".") + 1)
                                                        if (relTable == sensitive_index.get(j + 1)) {
                                                            many1Sets.add(new AbstractMap.SimpleEntry<String, String>(condColumn, sensitive_index.get(j + 1) + " " + sensitive_index.get(j + 2) + " " + relColumn))
                                                            many2Sets.add(new AbstractMap.SimpleEntry<String, String>(conditionCols.get(i), sensitive_index.get(j + 1) + " " + relColumn + " " + sensitive_index.get(j + 2)))
                                                        }
                                                    }
                                                    manyToMany.put(conditionCols.get(i), many1Sets)
                                                    manyToMany.put(condColumn, many2Sets)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                for (middle in temp.keySet()) {
                    def tableOfMiddle = middle.substring(0, middle.indexOf("."))
                    def columnOfMiddle = middle.substring(middle.indexOf(".")+1)
                    def many1 = temp.get(middle)
                    if (table == tableOfMiddle) {
                        def location = node.toFileAbs().next().name + ":" + node.lineno
                        if (columnValUseMap.containsKey(location+" "+v)) {
                            def columnValUse = columnValUseMap.get(location+" "+v)
                            for (entry in columnValUse) {
                                def tableOfEntry = entry.key.substring(0, entry.key.indexOf("."))
                                def columnOfEntry = entry.key.substring(entry.key.indexOf(".")+1)
                                if (tableOfEntry != tableOfMiddle && tableOfEntry != many1.substring(0, many1.indexOf(".")) && PrimaryKeysMap.containsKey(tableOfEntry) && (PrimaryKeysMap.get(tableOfEntry).equalsIgnoreCase(columnOfEntry) || (userTables.containsKey(tableOfEntry) && userTables.get(tableOfEntry).contains(columnOfEntry)))) {
                                    ret.add(sql_query)
                                    ret.add(getLocation(node))
                                    ret.add("findManyToMany definitely " + many1 + " " + tableOfMiddle + " " + entry.key)
                                    System.out.println(sql_query)
                                    System.out.println("findManyToMany definitely " + many1 + " " + tableOfMiddle + " " + entry.key)
                                    def many1Sets = new HashSet<>()
                                    def many2Sets = new HashSet<>()
                                    if (manyToMany.containsKey(many1)) {
                                        many1Sets.addAll(manyToMany.get(many1))
                                    }
                                    if (manyToMany.containsKey(entry.key)) {
                                        many2Sets.addAll(manyToMany.get(entry.key))
                                    }
                                    many1Sets.add(new AbstractMap.SimpleEntry<String, String>(entry.key, tableOfMiddle + " " + columnOfMiddle + " " + column))
                                    many2Sets.add(new AbstractMap.SimpleEntry<String, String>(many1, tableOfMiddle + " " + column + " " + columnOfMiddle))
                                    manyToMany.put(many1, many1Sets)
                                    manyToMany.put(entry.key, many2Sets)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

def checkCanSet(sensitive_index, ret) {
    return false
}

def setRelationForCond(node, conditionCols, conditionVals, defNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, sql_query, PrimaryKeysMap, userTables,  isSelect, queryCondMap, columnValUseMap, callerDTableMaps, dynamicTableNodeMaps, ret) {
    def callerDTables = new HashSet<String>()
    if (dynamicTableNodeMaps.containsKey(node)) {
        callerDTables = dynamicTableNodeMaps.get(node)
    }
    for (int i = 0; i < conditionCols.size(); ++i) {
        def val = conditionVals.get(i)
        def vals = getAllValsInCond(val)
        def table = conditionCols.get(i).substring(0, conditionCols.get(i).indexOf("."))
        def column = conditionCols.get(i).substring(conditionCols.get(i).indexOf(".")+1)
        for (v in vals) {
            if (v.startsWith("\$")) {
                def hasDef = false
                if (v == "\$customers_id") {
                    ret.add("defNodes.size "+defNodes.size())
                }
                for (defNode in defNodes) {
                    def location = defNode.toFileAbs().next().name + ":" + defNode.lineno
                    def scopeLocation = defNode.toFileAbs().next().name
                    if (isWithinFunction(defNode)) {
                        scopeLocation = scopeLocation + "_" + defNode.functions.next().name + ":" + defNode.functions().next().lineno
                    }
                    def defVal = location + " " + v
                    if (defVal == "./catalog/admin/customers.php:238 \$customers_id") {
                        ret.add("defVal is " + defVal)
                        ret.add(valTableColumnMap.containsKey(defVal))
                    }
                    if (v == "\$customers_id") {
                        ret.add(getLocation(defNode))
                    }
                    if (valTableColumnMap.containsKey(defVal) || (v.startsWith("\$_SESSION[") && valTableColumnMap.containsKey(v))) {
                        hasDef = true
                        def defEntry = null
                        if (valTableColumnMap.containsKey(defVal)) {
                            defEntry = valTableColumnMap.get(defVal)
                        }
                        else {
                            defEntry = valTableColumnMap.get(v)
                        }
                        def sensitive_index = defEntry.getValue()
                        def canSet = checkCanSet(sensitive_index, ret)
                        for (int j = 0; j < sensitive_index.size(); j += 5) {
                            if (sensitive_index.get(j) == "-1" && callerDTables.contains(sensitive_index.get(j+1))) {
                                continue
                            }
                            def sensitiveKey = sensitive_index.get(j + 1) + "." + sensitive_index.get(j + 2)
                            if (sensitive_index.get(j+3) == "true") {
                                setTableRelations(sensitiveKey, conditionCols.get(i))
                                ret.add(sql_query)
                                ret.add("setTableRelations " + sensitiveKey + " " + conditionCols.get(i))
                                System.out.println(sql_query)
                                System.out.println("setTableRelations " + sensitiveKey + " " + conditionCols.get(i))
                            }
                            if (isSelect) {
                                if (PrimaryKeysMap.containsKey(table)) {
                                    if ((PrimaryKeysMap.get(table).equalsIgnoreCase(column) || userTables.containsKey(table))
                                            && table != sensitive_index.get(j+1)) {
                                        setTableRelations(sensitiveKey, conditionCols.get(i))
                                        ret.add(sql_query)
                                        ret.add("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                        System.out.println(sql_query)
                                        System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                        location = node.toFileAbs().next().name + ":" + node.lineno
                                        def condColumns = new HashSet<String>()
                                        if (queryCondMap.containsKey(location+" "+table)) {
                                            condColumns.addAll(queryCondMap.get(location + " " + table))
                                        }
                                        condColumns.add(sensitiveKey)
                                        queryCondMap.put(location+" "+table, condColumns)
                                    }
                                }
                                if (conditionCols.size() == 1 && PrimaryKeysMap.containsKey(sensitive_index.get(j+1))) {
                                    if ((PrimaryKeysMap.get(sensitive_index.get(j+1)).equalsIgnoreCase(sensitive_index.get(j+2)) || userTables.containsKey(sensitive_index.get(j+1)))
                                            && table != sensitive_index.get(j+1)) {
                                        setTableRelations(sensitiveKey, conditionCols.get(i))
                                        ret.add(sql_query)
                                        ret.add("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                        System.out.println(sql_query)
                                        System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                        location = node.toFileAbs().next().name + ":" + node.lineno
                                        def condColumns = new HashSet<String>()
                                        if (queryCondMap.containsKey(location+" "+table)) {
                                            condColumns.addAll(queryCondMap.get(location + " " + table))
                                        }
                                        condColumns.add(sensitiveKey)
                                        queryCondMap.put(location+" "+table, condColumns)
                                    }
                                }
                            }
                            location = node.toFileAbs().next().name + ":" + node.lineno
                            def columnValUse = new HashSet<AbstractMap.SimpleEntry<String, String>>()
                            if (columnValUseMap.containsKey(location+" "+v)) {
                                columnValUse.addAll(columnValUseMap.get(location+" "+v))
                            }
                            columnValUse.add(new AbstractMap.SimpleEntry<String, String>(sensitiveKey, "sql"))
                            columnValUseMap.put(location+" "+v, columnValUse)
                        }
                    }
                    else if (valDefTableColumnMap.containsKey(defVal)) {
                        hasDef = true
                        def defEntry = valDefTableColumnMap.get(defVal)
                        def defColumns = defEntry.getValue()
                        for (defColumn in defColumns) {
                            def defColumnTable = defColumn.substring(0, defColumn.indexOf("."))
                            if (callerDTables.contains(defColumnTable)) {
                                continue
                            }
                            setTableRelations(defColumn, conditionCols.get(i))
                            ret.add(sql_query)
                            ret.add("setTableRelations " + defColumn + " " + conditionCols.get(i))
                            System.out.println(sql_query)
                            System.out.println("setTableRelations " + defColumn + " " + conditionCols.get(i))
                            if (isSelect) {
                                def tableOfDef = defColumn.substring(0, defColumn.indexOf("."))
                                def columnOfDef = defColumn.substring(defColumn.indexOf(".") + 1)
                                if (PrimaryKeysMap.containsKey(table)) {
                                    if ((PrimaryKeysMap.get(table).equalsIgnoreCase(column) || userTables.containsKey(table))
                                            && table != tableOfDef) {
                                        ret.add(sql_query)
                                        ret.add("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                        System.out.println(sql_query)
                                        System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                        location = node.toFileAbs().next().name + ":" + node.lineno
                                        def condColumns = new HashSet<String>()
                                        if (queryCondMap.containsKey(location + " " + table)) {
                                            condColumns.addAll(queryCondMap.get(location + " " + table))
                                        }
                                        condColumns.add(defColumn)
                                        queryCondMap.put(location + " " + table, condColumns)
                                    }
                                }
                                if (conditionCols.size() == 1 && PrimaryKeysMap.containsKey(tableOfDef)) {
                                    if ((PrimaryKeysMap.get(tableOfDef).equalsIgnoreCase(columnOfDef) || userTables.containsKey(tableOfDef))
                                            && table != tableOfDef) {
                                        ret.add(sql_query)
                                        ret.add("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                        System.out.println(sql_query)
                                        System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                        location = node.toFileAbs().next().name + ":" + node.lineno
                                        def condColumns = new HashSet<String>()
                                        if (queryCondMap.containsKey(location + " " + table)) {
                                            condColumns.addAll(queryCondMap.get(location + " " + table))
                                        }
                                        condColumns.add(defColumn)
                                        queryCondMap.put(location + " " + table, condColumns)
                                    }
                                }
                            }
                            location = node.toFileAbs().next().name + ":" + node.lineno
                            def columnValUse = new HashSet<AbstractMap.SimpleEntry<String, String>>()
                            if (columnValUseMap.containsKey(location+" "+v)) {
                                columnValUse.addAll(columnValUseMap.get(location+" "+v))
                            }
                            columnValUse.add(new AbstractMap.SimpleEntry<String,String>(defColumn, "ref"))
                            columnValUseMap.put(location+" "+v, columnValUse)
                        }
                    }
                    else if (sessionMap.containsKey(defVal) || sessionMap.containsKey(scopeLocation+" "+v)) {
                        def sessionVals = new HashSet<String>()
                        if (sessionMap.containsKey(defVal)) {
                            def sessionEntry = sessionMap.get(defVal)
                            sessionVals = sessionEntry.getValue()
                        }
                        else {
                            def sessionEntry = sessionMap.get(scopeLocation+" "+v)
                            sessionVals = sessionEntry.getValue()
                        }
                        for (sessionVal in sessionVals) {
                            if (valTableColumnMap.containsKey(sessionVal)) {
                                hasDef = true
                                def defEntry = valTableColumnMap.get(sessionVal)
                                def sensitive_index = defEntry.getValue()
                                for (int j = 0; j < sensitive_index.size(); j += 5) {
                                    if (sensitive_index.get(j) != "-1") {
                                        def sensitiveKey = sensitive_index.get(j + 1) + "." + sensitive_index.get(j + 2)
                                        if (userTables.containsKey(sensitive_index.get(j + 1)) && !userTables.containsKey(table)
                                            && !(PrimaryKeysMap.containsKey(sensitive_index.get(j + 1)) && PrimaryKeysMap.get(sensitive_index.get(j + 1)).equalsIgnoreCase(sensitive_index.get(j + 2)))
                                            && !(PrimaryKeysMap.containsKey(table) && PrimaryKeysMap.get(table).equalsIgnoreCase(column))
                                        ) {
                                            ret.add("*******user column :" + conditionCols.get(i))
                                            userTables.get(sensitive_index.get(j + 1)).add(sensitive_index.get(j + 2))
                                        }
                                        setTableRelations(sensitiveKey, conditionCols.get(i))
                                        ret.add(sql_query)
                                        ret.add("setTableRelations " + sensitiveKey + " " + conditionCols.get(i))
                                        System.out.println(sql_query)
                                        System.out.println("setTableRelations " + sensitiveKey + " " + conditionCols.get(i))
                                        if (isSelect) {
                                            if (PrimaryKeysMap.containsKey(table)) {
                                                if ((PrimaryKeysMap.get(table).equalsIgnoreCase(column) || userTables.containsKey(table))
                                                        && table != sensitive_index.get(j + 1)) {
                                                    ret.add(sql_query)
                                                    ret.add("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                                    System.out.println(sql_query)
                                                    System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                                    location = node.toFileAbs().next().name + ":" + node.lineno
                                                    def condColumns = new HashSet<String>()
                                                    if (queryCondMap.containsKey(location + " " + table)) {
                                                        condColumns.addAll(queryCondMap.get(location + " " + table))
                                                    }
                                                    condColumns.add(sensitiveKey)
                                                    queryCondMap.put(location + " " + table, condColumns)
                                                }
                                            }
                                            if (conditionCols.size() == 1 && PrimaryKeysMap.containsKey(sensitive_index.get(j + 1))) {
                                                if ((PrimaryKeysMap.get(sensitive_index.get(j + 1)).equalsIgnoreCase(sensitive_index.get(j + 2)) || userTables.containsKey(sensitive_index.get(j + 1)))
                                                        && table != sensitive_index.get(j + 1)) {
                                                    ret.add(sql_query)
                                                    ret.add("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                                    System.out.println(sql_query)
                                                    System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                                    location = node.toFileAbs().next().name + ":" + node.lineno
                                                    def condColumns = new HashSet<String>()
                                                    if (queryCondMap.containsKey(location + " " + table)) {
                                                        condColumns.addAll(queryCondMap.get(location + " " + table))
                                                    }
                                                    condColumns.add(sensitiveKey)
                                                    queryCondMap.put(location + " " + table, condColumns)
                                                }
                                            }
                                        }
                                        location = node.toFileAbs().next().name + ":" + node.lineno
                                        def columnValUse = new HashSet<AbstractMap.SimpleEntry<String, String>>()
                                        if (columnValUseMap.containsKey(location + " " + v)) {
                                            columnValUse.addAll(columnValUseMap.get(location + " " + v))
                                        }
                                        columnValUse.add(new AbstractMap.SimpleEntry<String, String>(sensitiveKey, "session"))
                                        columnValUseMap.put(location + " " + v, columnValUse)
                                    }
                                }
                            }
                            else {
                                ret.add("sessionVal not found")
                                ret.add(sessionVal)
                                System.out.println("sessionVal not found")
                                System.out.println(sessionVal)
                            }
                        }
                    }
                    else if (sessionMap.containsKey(v)) {
                        def sessionEntry = sessionMap.get(v)
                        def sessionVals = sessionEntry.getValue()
                        for (sessionVal in sessionVals) {
                            if (valDefTableColumnMap.containsKey(sessionVal)) {
                                hasDef = true
                                def defEntry = valDefTableColumnMap.get(sessionVal)
                                def defColumns = defEntry.getValue()
                                for (defColumn in defColumns) {
                                    def defColumnTable = defColumn.substring(0, defColumn.indexOf("."))
                                    if (callerDTables.contains(defColumnTable)) {
                                        continue
                                    }
                                    setTableRelations(defColumn, conditionCols.get(i))
                                    ret.add(sql_query)
                                    ret.add("setTableRelations " + defColumn + " " + conditionCols.get(i))
                                    System.out.println(sql_query)
                                    System.out.println("setTableRelations " + defColumn + " " + conditionCols.get(i))
                                    if (isSelect) {
                                        def tableOfDef = defColumn.substring(0, defColumn.indexOf("."))
                                        def columnOfDef = defColumn.substring(defColumn.indexOf(".") + 1)
                                        if (PrimaryKeysMap.containsKey(table)) {
                                            if ((PrimaryKeysMap.get(table).equalsIgnoreCase(column) || userTables.containsKey(table))
                                                    && table != tableOfDef) {
                                                ret.add(sql_query)
                                                ret.add("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                                System.out.println(sql_query)
                                                System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                                location = node.toFileAbs().next().name + ":" + node.lineno
                                                def condColumns = new HashSet<String>()
                                                if (queryCondMap.containsKey(location + " " + table)) {
                                                    condColumns.addAll(queryCondMap.get(location + " " + table))
                                                }
                                                condColumns.add(defColumn)
                                                queryCondMap.put(location + " " + table, condColumns)
                                            }
                                        }
                                        if (conditionCols.size() == 1 && PrimaryKeysMap.containsKey(tableOfDef)) {
                                            if ((PrimaryKeysMap.get(tableOfDef).equalsIgnoreCase(columnOfDef) || userTables.containsKey(tableOfDef))
                                                    && table != tableOfDef) {
                                                ret.add(sql_query)
                                                ret.add("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                                System.out.println(sql_query)
                                                System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                                location = node.toFileAbs().next().name + ":" + node.lineno
                                                def condColumns = new HashSet<String>()
                                                if (queryCondMap.containsKey(location + " " + table)) {
                                                    condColumns.addAll(queryCondMap.get(location + " " + table))
                                                }
                                                condColumns.add(defColumn)
                                                queryCondMap.put(location + " " + table, condColumns)
                                            }
                                        }
                                    }
                                    location = node.toFileAbs().next().name + ":" + node.lineno
                                    def columnValUse = new HashSet<AbstractMap.SimpleEntry<String, String>>()
                                    if (columnValUseMap.containsKey(location + " " + v)) {
                                        columnValUse.addAll(columnValUseMap.get(location + " " + v))
                                    }
                                    columnValUse.add(new AbstractMap.SimpleEntry<String, String>(defColumn, "ref"))
                                    columnValUseMap.put(location + " " + v, columnValUse)
                                }
                            }
                            else {
                                ret.add("sessionVal not found")
                                ret.add(sessionVal)
                                System.out.println("sessionVal not found")
                                System.out.println(sessionVal)
                            }
                        }
                    }
                    else {
                        System.out.println("defVal not found")
                        System.out.println(defVal)
                    }
                }
                if (!hasDef) {
                    ret.add("!hasDef " + defNodes.size())
                    if (v.startsWith("\$_SESSION[") && valTableColumnMap.containsKey(v)) {
                        def defEntry = valTableColumnMap.get(v)
                        def sensitive_index = defEntry.getValue()
                        for (int j = 0; j < sensitive_index.size(); j += 5) {
                            if (sensitive_index.get(j) != "-1") {
                                def sensitiveKey = sensitive_index.get(j + 1) + "." + sensitive_index.get(j + 2)
                                if (userTables.containsKey(sensitive_index.get(j + 1)) && !userTables.containsKey(table)
                                    && !(PrimaryKeysMap.containsKey(sensitive_index.get(j + 1)) && PrimaryKeysMap.get(sensitive_index.get(j + 1)).equalsIgnoreCase(sensitive_index.get(j + 2)))
                                    && !(PrimaryKeysMap.containsKey(table) && PrimaryKeysMap.get(table).equalsIgnoreCase(column))
                                ) {
                                    ret.add("*******user column :" + conditionCols.get(i))
                                    userTables.get(sensitive_index.get(j + 1)).add(sensitive_index.get(j + 2))
                                }
                                setTableRelations(sensitiveKey, conditionCols.get(i))
                                ret.add(sql_query)
                                ret.add("setTableRelations " + sensitiveKey + " " + conditionCols.get(i))
                                System.out.println(sql_query)
                                System.out.println("setTableRelations " + sensitiveKey + " " + conditionCols.get(i))
                                if (isSelect) {
                                    if (PrimaryKeysMap.containsKey(table)) {
                                        if ((PrimaryKeysMap.get(table).equalsIgnoreCase(column) || userTables.containsKey(table))
                                                && table != sensitive_index.get(j + 1)) {
                                            ret.add(sql_query)
                                            ret.add("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                            System.out.println(sql_query)
                                            System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                            location = node.toFileAbs().next().name + ":" + node.lineno
                                            def condColumns = new HashSet<String>()
                                            if (queryCondMap.containsKey(location + " " + table)) {
                                                condColumns.addAll(queryCondMap.get(location + " " + table))
                                            }
                                            condColumns.add(sensitiveKey)
                                            queryCondMap.put(location + " " + table, condColumns)
                                        }
                                    }
                                    if (conditionCols.size() == 1 && PrimaryKeysMap.containsKey(sensitive_index.get(j + 1))) {
                                        if ((PrimaryKeysMap.get(sensitive_index.get(j + 1)).equalsIgnoreCase(sensitive_index.get(j + 2)) || userTables.containsKey(sensitive_index.get(j + 1)))
                                                && table != sensitive_index.get(j + 1)) {
                                            ret.add(sql_query)
                                            ret.add("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                            System.out.println(sql_query)
                                            System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + sensitiveKey)
                                            location = node.toFileAbs().next().name + ":" + node.lineno
                                            def condColumns = new HashSet<String>()
                                            if (queryCondMap.containsKey(location + " " + table)) {
                                                condColumns.addAll(queryCondMap.get(location + " " + table))
                                            }
                                            condColumns.add(sensitiveKey)
                                            queryCondMap.put(location + " " + table, condColumns)
                                        }
                                    }
                                }
                                location = node.toFileAbs().next().name + ":" + node.lineno
                                def columnValUse = new HashSet<AbstractMap.SimpleEntry<String, String>>()
                                if (columnValUseMap.containsKey(location + " " + v)) {
                                    columnValUse.addAll(columnValUseMap.get(location + " " + v))
                                }
                                columnValUse.add(new AbstractMap.SimpleEntry<String, String>(sensitiveKey, "session"))
                                columnValUseMap.put(location + " " + v, columnValUse)
                            }
                        }
                    }
                    else if (isWithinFunction(node)) {
                        func = node.functions().next()
                        funcLocation = func.toFileAbs().next().name + "_" + func.name + ":" + func.lineno
                        if (valDefTableColumnMap.containsKey(funcLocation + " " + v)) {
                            def defEntry = valDefTableColumnMap.get(funcLocation + " " + v)
                            def defColumns = defEntry.getValue()
                            for (defColumn in defColumns) {
                                setTableRelations(defColumn, conditionCols.get(i))
                                ret.add("global use in function")
                                ret.add(sql_query)
                                ret.add("setTableRelations " + defColumn + " " + conditionCols.get(i))
                                System.out.println("global use in function")
                                System.out.println(sql_query)
                                System.out.println("setTableRelations " + defColumn + " " + conditionCols.get(i))
                                if (isSelect) {
                                    def tableOfDef = defColumn.substring(0, defColumn.indexOf("."))
                                    def columnOfDef = defColumn.substring(defColumn.indexOf(".") + 1)
                                    if (PrimaryKeysMap.containsKey(table)) {
                                        if ((PrimaryKeysMap.get(table).equalsIgnoreCase(column) || userTables.containsKey(table))
                                                && table != tableOfDef) {
                                            ret.add(sql_query)
                                            ret.add("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                            System.out.println(sql_query)
                                            System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                            location = node.toFileAbs().next().name + ":" + node.lineno
                                            def condColumns = new HashSet<String>()
                                            if (queryCondMap.containsKey(location + " " + table)) {
                                                condColumns.addAll(queryCondMap.get(location + " " + table))
                                            }
                                            condColumns.add(defColumn)
                                            queryCondMap.put(location + " " + table, condColumns)
                                        }
                                    }
                                    if (conditionCols.size() == 1 && PrimaryKeysMap.containsKey(tableOfDef)) {
                                        if ((PrimaryKeysMap.get(tableOfDef).equalsIgnoreCase(columnOfDef) || userTables.containsKey(tableOfDef))
                                                && table != tableOfDef) {
                                            ret.add(sql_query)
                                            ret.add("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                            System.out.println(sql_query)
                                            System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                            location = node.toFileAbs().next().name + ":" + node.lineno
                                            def condColumns = new HashSet<String>()
                                            if (queryCondMap.containsKey(location + " " + table)) {
                                                condColumns.addAll(queryCondMap.get(location + " " + table))
                                            }
                                            condColumns.add(defColumn)
                                            queryCondMap.put(location + " " + table, condColumns)
                                        }
                                    }
                                }
                                location = node.toFileAbs().next().name + ":" + node.lineno
                                def columnValUse = new HashSet<AbstractMap.SimpleEntry<String, String>>()
                                if (columnValUseMap.containsKey(location+" "+v)) {
                                    columnValUse.addAll(columnValUseMap.get(location+" "+v))
                                }
                                columnValUse.add(new AbstractMap.SimpleEntry<String,String>(defColumn, "function global"))
                                columnValUseMap.put(location+" "+v, columnValUse)
                            }
                        }
                        else {
                            ret.add("!hasDef defVal not found in function")
                            ret.add(funcLocation + " " + v)
                            System.out.println("!hasDef defVal not found in function")
                            System.out.println(funcLocation + " " + v)
                        }
                    }
                    else if (valDefTableColumnMap.containsKey(node.toFileAbs().next().name + " " + v)) {
                        def defEntry = valDefTableColumnMap.get(node.toFileAbs().next().name + " " + v)
                        def defColumns = defEntry.getValue()
                        for (defColumn in defColumns) {
                            setTableRelations(defColumn, conditionCols.get(i))
                            ret.add("global use")
                            ret.add(sql_query)
                            ret.add("setTableRelations " + defColumn + " " + conditionCols.get(i))
                            System.out.println("global use")
                            System.out.println(sql_query)
                            System.out.println("setTableRelations " + defColumn + " " + conditionCols.get(i))
                            if (isSelect) {
                                def tableOfDef = defColumn.substring(0, defColumn.indexOf("."))
                                def columnOfDef = defColumn.substring(defColumn.indexOf(".") + 1)
                                if (PrimaryKeysMap.containsKey(table)) {
                                    if ((PrimaryKeysMap.get(table).equalsIgnoreCase(column) || userTables.containsKey(table))
                                            && table != tableOfDef) {
                                        ret.add(sql_query)
                                        ret.add("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                        System.out.println(sql_query)
                                        System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                        location = node.toFileAbs().next().name + ":" + node.lineno
                                        def condColumns = new HashSet<String>()
                                        if (queryCondMap.containsKey(location + " " + table)) {
                                            condColumns.addAll(queryCondMap.get(location + " " + table))
                                        }
                                        condColumns.add(defColumn)
                                        queryCondMap.put(location + " " + table, condColumns)
                                    }
                                }
                                if (conditionCols.size() == 1 && PrimaryKeysMap.containsKey(tableOfDef)) {
                                    if ((PrimaryKeysMap.get(tableOfDef).equalsIgnoreCase(columnOfDef) || userTables.containsKey(tableOfDef))
                                            && table != tableOfDef) {
                                        ret.add(sql_query)
                                        ret.add("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                        System.out.println(sql_query)
                                        System.out.println("findManyToMany potential " + conditionCols.get(i) + " " + defColumn)
                                        location = node.toFileAbs().next().name + ":" + node.lineno
                                        def condColumns = new HashSet<String>()
                                        if (queryCondMap.containsKey(location + " " + table)) {
                                            condColumns.addAll(queryCondMap.get(location + " " + table))
                                        }
                                        condColumns.add(defColumn)
                                        queryCondMap.put(location + " " + table, condColumns)
                                    }
                                }
                            }
                            location = node.toFileAbs().next().name + ":" + node.lineno
                            def columnValUse = new HashSet<AbstractMap.SimpleEntry<String, String>>()
                            if (columnValUseMap.containsKey(location+" "+v)) {
                                columnValUse.addAll(columnValUseMap.get(location+" "+v))
                            }
                            columnValUse.add(new AbstractMap.SimpleEntry<String,String>(defColumn, "global"))
                            columnValUseMap.put(location+" "+v, columnValUse)
                        }
                    }
                    else {
                        ret.add("!hasDef defVal not found")
                        ret.add(getLocation(node) + " " + v)
                        System.out.println("!hasDef defVal not found")
                        System.out.println(getLocation(node) + " " + v)
                    }
                }
            }
        }
    }
}

def setRelationForCol(node, colNames, itemNames, table, defNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, sql_query, PrimaryKeysMap, userTables, callerDTableMaps, dynamicTableNodeMaps, insertUserReltatedTables, ret) {
    def callerDTables = new HashSet<String>()
    if (dynamicTableNodeMaps.containsKey(node)) {
        callerDTables = dynamicTableNodeMaps.get(node)
    }
    for (int i = 0; i < colNames.size(); ++i) {
        if (i < itemNames.size()) {
            def val = itemNames.get(i)
            if (val.startsWith("\$")) {
                def hasDef = false
                for (defNode in defNodes) {
                    def location = defNode.toFileAbs().next().name + ":" + defNode.lineno
                    def scopeLocation = defNode.toFileAbs().next().name
                    if (isWithinFunction(defNode)) {
                        scopeLocation = scopeLocation + "_" + defNode.functions.next().name + ":" + defNode.functions().next().lineno
                    }
                    def defVal = location + " " + val
                    if (valTableColumnMap.containsKey(defVal) || (val.startsWith("\$_SESSION[") && valTableColumnMap.containsKey(val))) {
                        hasDef = true
                        def defEntry = null
                        if (valTableColumnMap.containsKey(defVal)) {
                            defEntry = valTableColumnMap.get(defVal)
                        }
                        else {
                            defEntry = valTableColumnMap.get(val)
                        }
                        def sensitive_index = defEntry.getValue()
                        for (int j = 0; j < sensitive_index.size(); j += 5) {
                            if (sensitive_index.get(j) != "-1" && callerDTables.contains(sensitive_index.get(j+1))) {
                                continue
                            }
                            if (sensitive_index.get(j+3) == "true") {
                                def sensitiveKey = sensitive_index.get(j + 1) + "." + sensitive_index.get(j + 2)
                                setTableRelations(sensitiveKey, table + "." + colNames.get(i))
                                ret.add(sql_query)
                                ret.add("setTableRelations " + sensitiveKey + " " + table + "." + colNames.get(i))
                                System.out.println(sql_query)
                                System.out.println("setTableRelations " + sensitiveKey + " " + table + "." + colNames.get(i))
                                if (insertUserReltatedTables != null) {
                                    if (userTables.containsKey(sensitive_index.get(j + 1))) {
                                        insertUserReltatedTables.add(table)
                                    }
                                }
                            }
                        }
                    }
                    else if (valDefTableColumnMap.containsKey(defVal)) {
                        hasDef = true
                        def defEntry = valDefTableColumnMap.get(defVal)
                        def defColumns = defEntry.getValue()
                        for (defColumn in defColumns) {
                            def defColumnTable = defColumn.substring(0, defColumn.indexOf("."))
                            if (callerDTables.contains(defColumnTable)) {
                                continue
                            }
                            setTableRelations(defColumn, table + "." + colNames.get(i))
                            ret.add(sql_query)
                            ret.add("setTableRelations " + defColumn + " " + table + "." + colNames.get(i))
                            System.out.println(sql_query)
                            System.out.println("setTableRelations " + defColumn + " " + table + "." + colNames.get(i))
                            if (insertUserReltatedTables != null) {
                                if (userTables.containsKey(defColumnTable)) {
                                    insertUserReltatedTables.add(table)
                                }
                            }
                        }
                    }
                    else if (sessionMap.containsKey(defVal) || sessionMap.containsKey(scopeLocation+" "+val)) {
                        hasDef = true
                        def sessionVals = new HashSet<String>()
                        if (sessionMap.containsKey(defVal)) {
                            def sessionEntry = sessionMap.get(defVal)
                            sessionVals = sessionEntry.getValue()
                        }
                        else {
                            def sessionEntry = sessionMap.get(scopeLocation+" "+val)
                            sessionVals = sessionEntry.getValue()
                        }
                        for (sessionVal in sessionVals) {
                            if (valTableColumnMap.containsKey(sessionVal)) {
                                def defEntry = valTableColumnMap.get(sessionVal)
                                def sensitive_index = defEntry.getValue()
                                for (int j = 0; j < sensitive_index.size(); j += 5) {
                                    if (sensitive_index.get(j) != "-1") {
                                        def sensitiveKey = sensitive_index.get(j + 1) + "." + sensitive_index.get(j + 2)
                                        if (userTables.containsKey(sensitive_index.get(j + 1)) && !userTables.containsKey(table)
                                            && !(PrimaryKeysMap.containsKey(sensitive_index.get(j + 1)) && PrimaryKeysMap.get(sensitive_index.get(j + 1)).equalsIgnoreCase(sensitive_index.get(j + 2)))
                                            && !(PrimaryKeysMap.containsKey(table) && PrimaryKeysMap.get(table).equalsIgnoreCase(colNames.get(i)))
                                        ) {
                                            ret.add("*******user column :" + table + "." + colNames.get(i))
                                            userTables.get(sensitive_index.get(j + 1)).add(sensitive_index.get(j + 2))
                                        }
                                        setTableRelations(sensitiveKey, table + "." + colNames.get(i))
                                        ret.add(sql_query)
                                        ret.add("setTableRelations " + sensitiveKey + " " + table + "." + colNames.get(i))
                                        System.out.println(sql_query)
                                        System.out.println("setTableRelations " + sensitiveKey + " " + table + "." + colNames.get(i))
                                        if (insertUserReltatedTables != null) {
                                            if (userTables.containsKey(sensitive_index.get(j + 1))) {
                                                insertUserReltatedTables.add(table)
                                            }
                                        }
                                    }
                                }
                            }
                            else {
                                ret.add("sessionVal not found")
                                ret.add(sessionVal)
                                System.out.println("sessionVal not found")
                                System.out.println(sessionVal)
                            }
                        }
                    }
                    else if (sessionMap.containsKey(val)) {
                        def sessionEntry = sessionMap.get(val)
                        def sessionVals = sessionEntry.getValue()
                        for (sessionVal in sessionVals) {
                            if (valDefTableColumnMap.containsKey(sessionVal)) {
                                hasDef = true
                                def defEntry = valDefTableColumnMap.get(sessionVal)
                                def defColumns = defEntry.getValue()
                                for (defColumn in defColumns) {
                                    def defColumnTable = defColumn.substring(0, defColumn.indexOf("."))
                                    if (callerDTables.contains(defColumnTable)) {
                                        continue
                                    }
                                    setTableRelations(defColumn, table + "." + colNames.get(i))
                                    ret.add(sql_query)
                                    ret.add("setTableRelations " + defColumn + " " + table + "." + colNames.get(i))
                                    System.out.println(sql_query)
                                    System.out.println("setTableRelations " + defColumn + " " + table + "." + colNames.get(i))
                                    if (insertUserReltatedTables != null) {
                                        if (userTables.containsKey(defColumnTable)) {
                                            insertUserReltatedTables.add(table)
                                        }
                                    }
                                }
                            }
                            else {
                                ret.add("sessionVal not found")
                                ret.add(sessionVal)
                                System.out.println("sessionVal not found")
                                System.out.println(sessionVal)
                            }
                        }
                    }
                    else {
                        System.out.println("defVal not found")
                        System.out.println(defVal)
                    }
                }
                if (!hasDef) {
                    ret.add("!hasDef " + defNodes.size())
                    if (val.startsWith("\$_SESSION[") && valTableColumnMap.containsKey(val)) {
                        def defEntry = valTableColumnMap.get(val)
                        def sensitive_index = defEntry.getValue()
                        for (int j = 0; j < sensitive_index.size(); j += 5) {
                            if (sensitive_index.get(j) != "-1") {
                                def sensitiveKey = sensitive_index.get(j + 1) + "." + sensitive_index.get(j + 2)
                                if (userTables.containsKey(sensitive_index.get(j + 1)) && !userTables.containsKey(table)
                                    && !(PrimaryKeysMap.containsKey(sensitive_index.get(j + 1)) && PrimaryKeysMap.get(sensitive_index.get(j + 1)).equalsIgnoreCase(sensitive_index.get(j + 2)))
                                    && !(PrimaryKeysMap.containsKey(table) && PrimaryKeysMap.get(table).equalsIgnoreCase(colNames.get(i)))
                                ) {
                                    ret.add("*******user column :" + table + "." + colNames.get(i))
                                    userTables.get(sensitive_index.get(j + 1)).add(sensitive_index.get(j + 2))
                                }
                                setTableRelations(sensitiveKey, table + "." + colNames.get(i))
                                ret.add(sql_query)
                                ret.add("setTableRelations " + sensitiveKey + " " + table + "." + colNames.get(i))
                                System.out.println(sql_query)
                                System.out.println("setTableRelations " + sensitiveKey + " " + table + "." + colNames.get(i))
                                if (insertUserReltatedTables != null) {
                                    if (userTables.containsKey(sensitive_index.get(j + 1))) {
                                        insertUserReltatedTables.add(table)
                                    }
                                }
                            }
                        }
                    }
                    else if (isWithinFunction(node)) {
                        def func = node.functions().next()
                        def funcLocation = func.toFileAbs().next().name +"_" + func.name + ":" + func.lineno
                        if (valDefTableColumnMap.containsKey(funcLocation + " " + val)) {
                            def defEntry = valDefTableColumnMap.get(funcLocation + " " + val)
                            def defColumns = defEntry.getValue()
                            for (defColumn in defColumns) {
                                setTableRelations(defColumn, table + "." + colNames.get(i))
                                ret.add("global use in function")
                                ret.add(sql_query)
                                ret.add("setTableRelations " + defColumn + " " + table + "." + colNames.get(i))
                                System.out.println("global use in function")
                                System.out.println(sql_query)
                                System.out.println("setTableRelations " + defColumn + " " + table + "." + colNames.get(i))
                                if (insertUserReltatedTables != null) {
                                    if (userTables.containsKey(defColumn.substring(0, defColumn.indexOf(".")))) {
                                        insertUserReltatedTables.add(table)
                                    }
                                }
                            }
                        }
                        else {
                            ret.add("!hasDef defVal not found in function")
                            ret.add(funcLocation + " " + val)
                            System.out.println("!hasDef defVal not found in function")
                            System.out.println(funcLocation + " " + val)
                        }
                    }
                    else if (valDefTableColumnMap.containsKey(node.toFileAbs().next().name + " " + val)) {
                        def defEntry = valDefTableColumnMap.get(node.toFileAbs().next().name + " " + val)
                        def defColumns = defEntry.getValue()
                        for (defColumn in defColumns) {
                            setTableRelations(defColumn, table + "." + colNames.get(i))
                            ret.add("global use")
                            ret.add(sql_query)
                            ret.add("setTableRelations " + defColumn + " " + table + "." + colNames.get(i))
                            System.out.println("global use")
                            System.out.println(sql_query)
                            System.out.println("setTableRelations " + defColumn + " " + table + "." + colNames.get(i))
                            if (insertUserReltatedTables != null) {
                                if (userTables.containsKey(defColumn.substring(0, defColumn.indexOf(".")))) {
                                    insertUserReltatedTables.add(table)
                                }
                            }
                        }
                    }
                    else {
                        ret.add("!hasDef defVal not found")
                        ret.add(node.toFileAbs().next().name + " " + val)
                        System.out.println("!hasDef defVal not found")
                        System.out.println(node.toFileAbs().next().name + " " + val)
                    }
                }
            }
        }
    }
}

def setSessionForReturn(node, sessionMap, sessionQueue, sessionNode, ret) {
    ret.add("set return")
    ret.add(getLocation(node))
    def retVal = getAllValName(node)
    retVal = retVal.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
    ret.add(retVal)
    if (!retVal.startsWith("\$_SESSION[")) {
        return
    }
    def func = node.functions().next()
    def funcName = func.name
    def callers = []
    for (v in func.in("CALLS")) {
        callers.add(v)
    }
    def location = node.toFileAbs().next().name + ":" + node.lineno
    def sessionVal = new HashSet<String>()
    if (sessionMap.containsKey(location+" "+retVal)) {
        def entry = sessionMap.get(location+" "+retVal)
        sessionVal.addAll(entry.getValue())
    }
    def changed = sessionVal.addAll(retVal)
    if (changed) {
        sessionMap.put(location + " " + retVal, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(sessionNode, sessionVal))
    }
    for (caller in callers) {
        if (isCallExpression(caller)) {
            def callerParent = caller.parents().next()
            if (callerParent.type == "AST_ASSIGN") {
                def assignName = getAllValName(callerParent.ithChildren(0).next())
                assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')

                def callerStatement = caller.statements().next()
                if (callerStatement.type == "AST_IF") {
                    callerStatement = callerStatement.ithChildren(0).next().ithChildren(0).next()
                }
                def callerParentLocation = callerStatement.toFileAbs().next().name + ":" + callerStatement.lineno
                if (assignName.startsWith("\$")) {
                    ret.add(assignName)
                    def newSessionVal = new HashSet<String>()
                    if (sessionMap.containsKey(callerParentLocation+" "+assignName)) {
                        def newEntry = sessionMap.get(callerParentLocation+" "+assignName)
                        newSessionVal.addAll(newEntry.getValue())
                    }
                    changed = newSessionVal.add(retVal)
                    if (changed) {
                        sessionMap.put(callerParentLocation+" "+assignName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(callerStatement, newSessionVal))
                        sessionQueue.offer(callerParentLocation+" "+assignName)
                    }
                }
                else {
                    ret.add(assignName)
                    ret.add("return caller assignName is not variable")
                }
            }
            else {
                def callerLocation = caller.toFileAbs().next().name + ":" + caller.lineno
                def newSessionVal = new HashSet<String>()
                if (sessionMap.containsKey(callerLocation+" "+funcName)) {
                    def newEntry = sessionMap.get(callerLocation+" "+funcName)
                    newSessionVal.addAll(newEntry.getValue())
                }
                changed = newSessionVal.add(retVal)
                if (changed) {
                    sessionMap.put(callerLocation + " " + funcName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(caller, newSessionVal))
                    ret.add(caller)
                    ret.add("return caller is not assignment")
                }
            }
        }
    }
}

def setSessionForCall(node, sessionMap, sessionQueue, sanitizations, ret) {
    ret.add("set call")
    ret.add(getLocation(node))
    def count = node.numArguments().next()
    def start = new HashSet<Boolean>()
    start.add(true)
    def funcs = []
    for (v in node.out("CALLS")) {
        funcs.add(v)
    }
    ret.add(funcs)
    for (int i = 0; i < count; ++i) {
        def arg = statementToString(node.ithArguments(i).next(), start, new HashMap<>(), new HashSet<>(), sanitizations)
        if (arg.startsWith("\$_SESSION[")) {
            ret.add(arg)
            for (func in funcs) {
                def paramsNum = func.numParams().next()
                if (i < paramsNum) {
                    def paramNode = func.ithParams(i).next()
                    def location = paramNode.toFileAbs().next().name + ":" + paramNode.lineno
                    def param = statementToString(paramNode, start, new HashMap<>(), new HashSet<>(), sanitizations)
                    if (param.startsWith("\$")) {
                        def sessionVal = new HashSet<String>()
                        if (sessionMap.containsKey(location + " " + param)) {
                            def entry = sessionMap.get(location + " " + param)
                            sessionVal.addAll(entry.getValue())
                        }
                        def changed = sessionVal.add(arg)
                        if (changed) {
                            sessionMap.put(location + " " + param, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(paramNode, sessionVal))
                            sessionQueue.offer(location + " " + param)
                            ret.add(location + " " + param)
                        }
                    } else {
                        ret.add("param is not variable")
                        ret.add(param)
                    }
                }
            }
        }
    }
}

def transSessionForReturn(node, nodeLocation, sessionMap, sessionQueue, statement, ret) {
    ret.add("trans return")
    ret.add(getLocation(node))
    ret.add(nodeLocation)
    def retVal = getAllValName(node)
    retVal = retVal.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
    ret.add(retVal)
    def func = node.functions().next()
    def funcName = func.name
    def callers = []
    for (v in func.in("CALLS")) {
        callers.add(v)
    }
    def location = node.toFileAbs().next().name + ":" + node.lineno
    def sessionRefVal = nodeLocation + " " + retVal
    if (sessionMap.containsKey(sessionRefVal)) {
        def entry = sessionMap.get(sessionRefVal)
        def sessionVal = entry.getValue()
        sessionMap.put(location+" "+retVal, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(statement, sessionVal))
        for (caller in callers) {
            if (isCallExpression(caller)) {
                def callerParent = caller.parents().next()
                if (callerParent.type == "AST_ASSIGN") {
                    def assignName = getAllValName(callerParent.ithChildren(0).next())
                    assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')

                    def callerStatement = getStatement(caller.statements().next())
                    def callerParentLocation = callerStatement.toFileAbs().next().name + ":" + callerStatement.lineno
                    if (assignName.startsWith("\$")) {
                        ret.add(assignName)
                        def newSessionVal = new HashSet<String>()
                        if (sessionMap.containsKey(callerParentLocation+" "+assignName)) {
                            def newEntry = sessionMap.get(callerParentLocation+" "+assignName)
                            newSessionVal.addAll(newEntry.getValue())
                        }
                        def changed = newSessionVal.addAll(sessionVal)
                        if (changed) {
                            sessionMap.put(callerParentLocation+" "+assignName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(callerStatement, newSessionVal))
                            sessionQueue.offer(callerParentLocation+" "+assignName)
                        }
                    }
                    else {
                        ret.add("return caller assignName is not variable")
                        ret.add(assignName)
                    }
                }
                else {
                    def callerLocation = caller.toFileAbs().next().name + ":" + caller.lineno
                    def newSessionVal = new HashSet<String>()
                    if (sessionMap.containsKey(callerLocation+" "+funcName)) {
                        def newEntry = sessionMap.get(callerLocation+" "+funcName)
                        newSessionVal.addAll(newEntry.getValue())
                    }
                    def changed = newSessionVal.addAll(sessionVal)
                    if (changed) {
                        sessionMap.put(callerLocation + " " + funcName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(caller, newSessionVal))
                        ret.add("return caller is not assignment")
                        ret.add(caller)
                    }
                }
            }
        }
    }
    else {
        ret.add("sessionRefVal not found")
        ret.add(sessionRefVal)
    }
}

def transSessionForCall(node, nodeLocation, sessionMap, sessionQueue, sanitizations, ret) {
    ret.add("trans call")
    ret.add(getLocation(node))
    ret.add(nodeLocation)
    def count = node.numArguments().next()
    def start = new HashSet<Boolean>()
    start.add(true)
    def funcs = []
    for (f in node.out("CALLS")) {
        funcs.add(f)
    }
    ret.add(funcs)
    for (int i = 0; i < count; ++i) {
        System.out.println(getLocation(node))
        def arg = statementToString(node.ithArguments(i).next(), start, new HashMap<>(), new HashSet<>(), sanitizations)
        def sessionRefVal = nodeLocation + " " + arg
        if (sessionMap.containsKey(sessionRefVal)) {
            def entry = sessionMap.get(sessionRefVal)
            def sessionVal = entry.getValue()
            for (func in funcs) {
                def paramsNum = func.numParams().next()
                if (i < paramsNum) {
                    def paramNode = func.ithParams(i).next()
                    def location = paramNode.toFileAbs().next().name + ":" + paramNode.lineno
                    def param = statementToString(paramNode, start, new HashMap<>(), new HashSet<>(), sanitizations)
                    if (param.startsWith("\$")) {
                        def newSessionVal = new HashSet<String>()
                        if (sessionMap.containsKey(location+" "+param)) {
                            def newEntry = sessionMap.get(location+" "+param)
                            newSessionVal.addAll(newEntry.getValue())
                        }
                        def changed = newSessionVal.addAll(sessionVal)
                        if (changed) {
                            sessionMap.put(location + " " + param, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(paramNode, newSessionVal))
                            sessionQueue.offer(location + " " + param)
                            ret.add(location + " " + param)
                        }
                    }
                    else {
                        ret.add("param is not variable")
                        ret.add(param)
                    }
                }
            }
        }
    }
}

def isViewRelated(node, ret) {
    def start = new HashSet<Boolean>()
    start.add(true)
    def result = false
    ret.add("*****isViewRelated begin*****")
    def statementString = statementToString(node, start, new HashMap<>(), new HashSet<>(), new HashMap<String, Integer>())
    ret.add(statementString)
    if (statementString.contains("AST_ECHO")
            || statementString.contains("AST_PRINT")
    ) {
        result = true
    }
    ret.add("*****isViewRelated end*****")
    return result
}

def isControlViewRelated(node, ret) {
    def start = new HashSet<Boolean>()
    start.add(true)
    def result = false
    ret.add("*****isControlViewRelated begin*****")
    for (v in node.out("CONTROLS")) {
        def statementString = statementToString(v, start, new HashMap<>(), new HashSet<>(), new HashMap<String, Integer>())
        ret.add(statementString)
        if (statementString.contains("AST_ECHO")
                || statementString.contains("AST_PRINT")
                || statementString.contains("AST_EXIT")
        ) {
            if (v.type == "AST_PRINT") {
                def content = statementToString(v.ithChildren(0).next(), start, new HashMap<>(), new HashSet<>(), new HashMap<String, Integer>())
                if (v.ithChildren(0).next().type == "string") {
                    ret.add(content)
                    continue
                }
            }
            else if (v.type == "AST_ECHO") {
                def content = statementToString(v.ithChildren(0).next(), start, new HashMap<>(), new HashSet<>(), new HashMap<String, Integer>())
                if (v.ithChildren(0).next().type == "string") {
                    ret.add(content)
                    continue
                }
                if (content.contains("mysqli_errno") || content.contains("mysqli_error") || content.contains("gettext")) {
                    ret.add(content)
                    continue
                }
            }
            result = true
            break
        }
    }
    ret.add("*****isControlViewRelated end*****")
    return result
}

def getSelectCondColumns(node, nodeLocation, selectCondColumns, valTableColumnMap, ret) {
    if (node.type == "AST_BINARY_OP" && node.flags != null) {
        if (node.flags.contains("BINARY_IS_EQUAL") || node.flags.contains("BINARY_IS_NOT_EQUAL")
                || node.flags.contains("BINARY_IS_IDENTICAL") || node.flags.contains("BINARY_IS_NOT_IDENTICAL")) {
            def left = getAllValName(node.ithChildren(0).next())
            def right = getAllValName(node.ithChildren(1).next())
            ret.add(nodeLocation+" "+left)
            ret.add(nodeLocation+" "+right)
            if (valTableColumnMap.containsKey(nodeLocation+" "+left)) {
                def leftEntry = valTableColumnMap.get(nodeLocation+" "+left)
                def leftSensitiveIndex = leftEntry.getValue()
                for (int i = 0; i < leftSensitiveIndex.size(); i += 5) {
                    if (leftSensitiveIndex.get(i) != "-1") {
                        def sensitiveKey = leftSensitiveIndex.get(i + 1) + "." + leftSensitiveIndex.get(i + 2)
                        ret.add(sensitiveKey)
                        selectCondColumns.add(sensitiveKey)
                    }
                }
            }
            if (valTableColumnMap.containsKey(nodeLocation+" "+right)) {
                def rightEntry = valTableColumnMap.get(nodeLocation+" "+right)
                def rightSensitiveIndex = rightEntry.getValue()
                for (int i = 0; i < rightSensitiveIndex.size(); i += 5) {
                    if (rightSensitiveIndex.get(i) != "-1") {
                        def sensitiveKey = rightSensitiveIndex.get(i + 1) + "." + rightSensitiveIndex.get(i + 2)
                        ret.add(sensitiveKey)
                        selectCondColumns.add(sensitiveKey)
                    }
                }
            }
        }
        else if (node.flags.contains("BINARY_BOOL_AND") || node.flags.contains("BINARY_BOOL_OR")) {
            getSelectCondColumns(node.ithChildren(0).next(), nodeLocation, selectCondColumns, valTableColumnMap, ret)
            getSelectCondColumns(node.ithChildren(1).next(), nodeLocation, selectCondColumns, valTableColumnMap, ret)
        }
    }
    else if (node.type == "AST_UNARY_OP" && node.flags != null) {
        if (node.flags.contains("UNARY_BOOL_NOT")) {
            getSelectCondColumns(node.ithChildren(0).next(), nodeLocation, selectCondColumns, valTableColumnMap, ret)
        }
    }
    else if (node.type == "AST_VAR" || node.type == "AST_DIM") {
        def var = getAllValName(node)
        ret.add(nodeLocation+" "+var)
        if (valTableColumnMap.containsKey(nodeLocation+" "+var) && !valTableColumnMap.containsKey(nodeLocation+" "+var+"[0]")) {
            def varEntry = valTableColumnMap.get(nodeLocation+" "+var)
            def varSensitiveIndex = varEntry.getValue()
            for (int i = 0; i < varSensitiveIndex.size(); i += 5) {
                if (varSensitiveIndex.get(i) != "-1") {
                    def sensitiveKey = varSensitiveIndex.get(i + 1) + "." + varSensitiveIndex.get(i + 2)
                    ret.add(sensitiveKey)
                    selectCondColumns.add(sensitiveKey)
                }
            }
        }
    }
}

def setValTableColumnForSession(assignName, statement, valTableColumnMap, sessionTables, newDefSensitiveIndex, newDefSensitiveIndexSize) {
    def newSessionDefSensitiveIndex = new ArrayList<String>()
    if (valTableColumnMap.containsKey(assignName)) {
        def newSessionDefEntry = valTableColumnMap.get(assignName)
        newSessionDefSensitiveIndex.addAll(newSessionDefEntry.getValue())
    }
    for (int j = newDefSensitiveIndexSize; j < newDefSensitiveIndex.size(); j += 5) {
        if (newSessionDefSensitiveIndex.contains(newDefSensitiveIndex.get(j + 4))) {
            continue
        }
        newSessionDefSensitiveIndex.add(newDefSensitiveIndex.get(j))
        newSessionDefSensitiveIndex.add(newDefSensitiveIndex.get(j + 1))
        newSessionDefSensitiveIndex.add(newDefSensitiveIndex.get(j + 2))
        newSessionDefSensitiveIndex.add(newDefSensitiveIndex.get(j + 3))
        newSessionDefSensitiveIndex.add(newDefSensitiveIndex.get(j + 4))
    }
    valTableColumnMap.put(assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, newSessionDefSensitiveIndex))
    for (int j = newDefSensitiveIndexSize; j < newDefSensitiveIndex.size(); j += 5) {
        sessionTables.add(newDefSensitiveIndex.get(j + 1))
    }
}

def transValTableColumnForReturn(node, nodeLocation, valTableColumnMap, valTableColumnQueue, sessionTables, statement, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, ret) {
    ret.add("trans valtable return")
    ret.add(getLocation(node.ithChildren(0).next()))

    def retVal = getAllValName(node)
    retVal = retVal.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
    ret.add(retVal)
    def className = node.classname
    def func = node.functions().next()
    def funcName = func.name
    ret.add(funcName)
    def callers = []
    for (v in func.in("CALLS")) {
        callers.add(v)
    }
    def hasFetched = false
    def defSensitiveIndex = new ArrayList<String>()
    def location = node.toFileAbs().next().name + ":" + node.lineno
    def returnIndex0 = false
    if (retVal.startsWith("\$")) {
        def defRetVal = nodeLocation + " " + retVal
        if (!valTableColumnMap.containsKey(defRetVal) && valTableColumnMap.containsKey(defRetVal+"[0]")) {
            defRetVal = defRetVal + "[0]"
            retVal = retVal + "[0]"
            returnIndex0 = true
        }
        if (valTableColumnMap.containsKey(defRetVal)) {
            if (valTableColumnMap.containsKey(defRetVal + "[0]")) {
                hasFetched = true
            }
            def defEntry = valTableColumnMap.get(defRetVal)
            defSensitiveIndex.addAll(defEntry.getValue())
            def retSensitiveIndex = new ArrayList<String>()
            if (valTableColumnMap.containsKey(location + " " + retVal)) {
                def retEntry = valTableColumnMap.get(location + " " + retVal)
                retSensitiveIndex.addAll(retEntry.getValue())
            }
            def retSensitiveIndexSize = retSensitiveIndex.size()
            for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                def hasExisted = false
                for (int j = 0; j < retSensitiveIndexSize; j += 5) {
                    if (retSensitiveIndex.get(j).equals(defSensitiveIndex.get(i))
                            && retSensitiveIndex.get(j + 1).equals(defSensitiveIndex.get(i + 1))
                            && retSensitiveIndex.get(j + 2).equals(defSensitiveIndex.get(i + 2))
                            && retSensitiveIndex.get(j + 3).equals(defSensitiveIndex.get(i + 3))
                    ) {
                        if (retSensitiveIndex.get(j + 4).equals(defSensitiveIndex.get(i + 4))) {
                            hasExisted = true
                            break
                        }
                        else {
                            def table1 = retSensitiveIndex.get(j + 4).substring(retSensitiveIndex.get(j + 4).indexOf(" ") + 1)
                            def table2 = defSensitiveIndex.get(i + 4).substring(defSensitiveIndex.get(i + 4).indexOf(" ") + 1)
                            if (table1.equals(table2)) {
                                //need = false
                                hasExisted = true
                                break
                            }
                        }
                    }
                }
                if (!hasExisted) {
                    retSensitiveIndex.add(defSensitiveIndex.get(i))
                    retSensitiveIndex.add(defSensitiveIndex.get(i + 1))
                    retSensitiveIndex.add(defSensitiveIndex.get(i + 2))
                    retSensitiveIndex.add(defSensitiveIndex.get(i + 3))
                    retSensitiveIndex.add(defSensitiveIndex.get(i + 4))
                }
            }
            if (retSensitiveIndex.size() > retSensitiveIndexSize) {
                valTableColumnMap.put(location + " " + retVal, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, retSensitiveIndex))
                if (hasFetched) {
                    for (int i = retSensitiveIndexSize; i < retSensitiveIndex.size(); i += 5) {
                        def retIndexSensitiveIndex = new ArrayList<String>()
                        if (valTableColumnMap.containsKey(location + " " + retVal + "[" + retSensitiveIndex.get(i) + "]")) {
                            def retIndexEntry = valTableColumnMap.get(location + " " + retVal + "[" + retSensitiveIndex.get(i) + "]")
                            retIndexSensitiveIndex.addAll(retIndexEntry.getValue())
                        }
                        if (retIndexSensitiveIndex.contains(retSensitiveIndex.get(i + 4))) {
                            continue
                        }
                        retIndexSensitiveIndex.add(retSensitiveIndex.get(i))
                        retIndexSensitiveIndex.add(retSensitiveIndex.get(i + 1))
                        retIndexSensitiveIndex.add(retSensitiveIndex.get(i + 2))
                        retIndexSensitiveIndex.add(retSensitiveIndex.get(i + 3))
                        retIndexSensitiveIndex.add(retSensitiveIndex.get(i + 4))
                        valTableColumnMap.put(location + " " + retVal + "[" + retSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, retIndexSensitiveIndex))
                        valTableColumnMap.put(location + " " + retVal + "[" + retSensitiveIndex.get(i + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, retIndexSensitiveIndex))
                        valTableColumnMap.put(location + " " + retVal + "->" + retSensitiveIndex.get(i + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, retIndexSensitiveIndex))
                    }
                }
            }
        }
        else {
        }
    }
    else {
        if (node.ithChildren(0).next().type == "AST_CALL" || node.ithChildren(0).next().type == "AST_METHOD_CALL" || node.ithChildren(0).next().type == "AST_STATIC_CALL") {
            transValTableColumnForCall(node.ithChildren(0).next(), nodeLocation, valTableColumnMap, valTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, ret)
            def retFuncName = getFuncName(node.ithChildren(0).next())
            def callerLocation = node.ithChildren(0).next().toFileAbs().next().name + ":" + node.ithChildren(0).next().lineno
            def defFunc = callerLocation+" "+retFuncName
            if (!valTableColumnMap.containsKey(defFunc) && valTableColumnMap.containsKey(defFunc+"[0]")) {
                defFunc = defFunc + "[0]"
                returnIndex0 = true
            }
            if (valTableColumnMap.containsKey(defFunc)) {
                if (valTableColumnMap.containsKey(defFunc + "[0]")) {
                    hasFetched = true
                }
                def defEntry = valTableColumnMap.get(defFunc)
                defSensitiveIndex.addAll(defEntry.getValue())
            }
            else {
                ret.add("defFunc not found in return in valtable")
                ret.add(defFunc)
            }
        }
        else {
            ret.add("other type in return in valtable")
        }
    }

    if (defSensitiveIndex.size() > 0) {
        for (caller in callers) {
            if (isCallExpression(caller)) {
                funcName = getFuncName(caller)
                if (isWP && skipWPFunc.contains(funcName)) {
                    continue
                }
                if (isWithinFunction(caller)) {
                    def callerFunc = caller.functions().next()
                    if (callerFunc != null) {
                        def callerFuncName = callerFunc.name
                        if (isWP && skipWPFunc.contains(callerFuncName)) {
                            continue
                        }
                    }
                }
                def callerParent = caller.parents().next()
                if (callerParent.type == "AST_ASSIGN") {
                    def assignName = getAllValName(callerParent.ithChildren(0).next())
                    assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                    if (returnIndex0) {
                        assignName = assignName + "[0]"
                    }

                    def callerStatement = getStatement(caller)
                    def callerParentLocation = callerStatement.toFileAbs().next().name + ":" + callerStatement.lineno
                    def isCallDTable = false
                    def dynamicTable = ""
                    if (callerDTableMaps.containsKey(callerStatement)) {
                        isCallDTable = true
                        dynamicTable = callerDTableMaps.get(callerStatement)
                    }
                    if (assignName.startsWith("\$")) {
                        ret.add(assignName)
                        def newDefSensitiveIndex = new ArrayList<String>()
                        if (valTableColumnMap.containsKey(callerParentLocation + " " + assignName)) {
                            def newDefEntry = valTableColumnMap.get(callerParentLocation + " " + assignName)
                            newDefSensitiveIndex.addAll(newDefEntry.getValue())
                        }
                        def newDefSensitiveIndexSize = newDefSensitiveIndex.size()
                        def needOffer = false
                        for (int j = 0; j < defSensitiveIndex.size(); j += 5) {
                            def hasExisted = false
                            def need = true
                            for (int k = 0; k < newDefSensitiveIndexSize; k += 5) {
                                if (newDefSensitiveIndex.get(k).equals(defSensitiveIndex.get(j)) &&
                                        newDefSensitiveIndex.get(k + 1).equals(defSensitiveIndex.get(j + 1)) &&
                                        newDefSensitiveIndex.get(k + 2).equals(defSensitiveIndex.get(j + 2)) &&
                                        newDefSensitiveIndex.get(k + 3).equals(defSensitiveIndex.get(j + 3))
                                ) {
                                    if (newDefSensitiveIndex.get(k + 4).equals(defSensitiveIndex.get(j + 4))) {
                                        hasExisted = true
                                        break
                                    }
                                    else {
                                        def table1 = newDefSensitiveIndex.get(k + 4).substring(newDefSensitiveIndex.get(k + 4).indexOf(" ") + 1)
                                        def table2 = defSensitiveIndex.get(j + 4).substring(defSensitiveIndex.get(j + 4).indexOf(" ") + 1)
                                        if (table1.equals(table2)) {
                                            //need = false
                                            hasExisted = true
                                            break
                                        }
                                    }
                                }
                            }
                            needOffer = needOffer || need
                            if (!hasExisted) {
                                if (isCallDTable) {
                                    if (dynamicTable.equals(defSensitiveIndex.get(j + 1))) {
                                        newDefSensitiveIndex.add(defSensitiveIndex.get(j))
                                        newDefSensitiveIndex.add(defSensitiveIndex.get(j + 1))
                                        newDefSensitiveIndex.add(defSensitiveIndex.get(j + 2))
                                        newDefSensitiveIndex.add(defSensitiveIndex.get(j + 3))
                                        newDefSensitiveIndex.add(defSensitiveIndex.get(j + 4))
                                    }
                                }
                                else {
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 1))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 2))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 3))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 4))
                                }
                            }
                        }
                        if (newDefSensitiveIndex.size() > newDefSensitiveIndexSize) {
                            valTableColumnMap.put(callerParentLocation + " " + assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(callerStatement, newDefSensitiveIndex))
                            if (needOffer) {
                                valTableColumnQueue.offer(callerParentLocation + " " + assignName)
                            }
                            if (assignName.startsWith("\$_SESSION[")) {
                                setValTableColumnForSession(assignName, callerStatement, valTableColumnMap, sessionTables, newDefSensitiveIndex, newDefSensitiveIndexSize)
                            }
                            if (hasFetched) {
                                for (int j = newDefSensitiveIndexSize; j < newDefSensitiveIndex.size(); j += 5) {
                                    def valueIndexSensitiveIndex = new ArrayList<String>()
                                    if (valTableColumnMap.containsKey(callerParentLocation + " " + assignName + "[" + newDefSensitiveIndex.get(j) + "]")) {
                                        def valueIndexEntry = valTableColumnMap.get(callerParentLocation + " " + assignName + "[" + newDefSensitiveIndex.get(j) + "]")
                                        valueIndexSensitiveIndex.addAll(valueIndexEntry.getValue())
                                    }
                                    if (valueIndexSensitiveIndex.contains(newDefSensitiveIndex.get(j + 4))) {
                                        continue
                                    }
                                    valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j))
                                    valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 1))
                                    valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 2))
                                    valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 3))
                                    valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 4))
                                    valTableColumnMap.put(callerParentLocation + " " + assignName + "[" + newDefSensitiveIndex.get(j) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(callerStatement, valueIndexSensitiveIndex))
                                    valTableColumnMap.put(callerParentLocation + " " + assignName + "[" + newDefSensitiveIndex.get(j + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(callerStatement, valueIndexSensitiveIndex))
                                    valTableColumnMap.put(callerParentLocation + " " + assignName + "->" + newDefSensitiveIndex.get(j + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(callerStatement, valueIndexSensitiveIndex))
                                    if (assignName.startsWith("\$_SESSION[")) {
                                        def valueSessionIndexSensitiveIndex = new ArrayList<String>()
                                        if (valTableColumnMap.containsKey(assignName + "[" + newDefSensitiveIndex.get(j) + "]")) {
                                            def valueSessionIndexEntry = valTableColumnMap.get(assignName + "[" + newDefSensitiveIndex.get(j) + "]")
                                            valueSessionIndexSensitiveIndex.addAll(valueSessionIndexEntry.getValue())
                                        }
                                        for (int k = newDefSensitiveIndexSize; k < valueIndexSensitiveIndex.size(); k += 5) {
                                            if (valueSessionIndexSensitiveIndex.contains(valueIndexSensitiveIndex.get(k + 4))) {
                                                continue
                                            }
                                            valueSessionIndexSensitiveIndex.add(valueIndexSensitiveIndex.get(k))
                                            valueSessionIndexSensitiveIndex.add(valueIndexSensitiveIndex.get(k + 1))
                                            valueSessionIndexSensitiveIndex.add(valueIndexSensitiveIndex.get(k + 2))
                                            valueSessionIndexSensitiveIndex.add(valueIndexSensitiveIndex.get(k + 3))
                                            valueSessionIndexSensitiveIndex.add(valueIndexSensitiveIndex.get(k + 4))
                                        }
                                        valTableColumnMap.put(assignName + "[" + newDefSensitiveIndex.get(j) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(callerStatement, valueSessionIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName + "[" + newDefSensitiveIndex.get(j + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(callerStatement, valueSessionIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName + "->" + newDefSensitiveIndex.get(j + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(callerStatement, valueSessionIndexSensitiveIndex))
                                    }
                                }
                            }
                        }
                    }
                    else {
                        ret.add("return caller assignName is not variable")
                        ret.add(callerParentLocation+" "+assignName)
                    }
                }
                else {
                    def callerLocation = caller.toFileAbs().next().name + ":" + caller.lineno
                    def isCallDTable = false
                    def dynamicTable = ""
                    if (callerDTableMaps.containsKey(caller)) {
                        isCallDTable = true
                        dynamicTable = callerDTableMaps.get(caller)
                    }
                    if (returnIndex0) {
                        funcName = funcName + "[0]"
                    }
                    def newDefSensitiveIndex = new ArrayList<String>()
                    if (valTableColumnMap.containsKey(callerLocation + " " + funcName)) {
                        def newDefEntry = valTableColumnMap.get(callerLocation + " " + funcName)
                        newDefSensitiveIndex.addAll(newDefEntry.getValue())
                    }
                    def newDefSensitiveIndexSize = newDefSensitiveIndex.size()
                    for (int j = 0; j < defSensitiveIndex.size(); j += 5) {
                        def hasExisted = false
                        for (int k = 0; k < newDefSensitiveIndexSize; k += 5) {
                            if (newDefSensitiveIndex.get(k).equals(defSensitiveIndex.get(j)) &&
                                    newDefSensitiveIndex.get(k + 1).equals(defSensitiveIndex.get(j + 1)) &&
                                    newDefSensitiveIndex.get(k + 2).equals(defSensitiveIndex.get(j + 2)) &&
                                    newDefSensitiveIndex.get(k + 3).equals(defSensitiveIndex.get(j + 3))
                            ) {
                                if (newDefSensitiveIndex.get(k + 4).equals(defSensitiveIndex.get(j + 4))) {
                                    hasExisted = true
                                    break
                                }
                                else {
                                    def table1 = newDefSensitiveIndex.get(k + 4).substring(newDefSensitiveIndex.get(k + 4).indexOf(" ") + 1)
                                    def table2 = defSensitiveIndex.get(j + 4).substring(defSensitiveIndex.get(j + 4).indexOf(" ") + 1)
                                    if (table1.equals(table2)) {
                                        //need = false
                                        hasExisted = true
                                        break
                                    }
                                }
                            }
                        }
                        if (!hasExisted) {
                            if (isCallDTable) {
                                if (dynamicTable.equals(defSensitiveIndex.get(j + 1))) {
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 1))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 2))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 3))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 4))
                                }
                            }
                            else {
                                newDefSensitiveIndex.add(defSensitiveIndex.get(j))
                                newDefSensitiveIndex.add(defSensitiveIndex.get(j + 1))
                                newDefSensitiveIndex.add(defSensitiveIndex.get(j + 2))
                                newDefSensitiveIndex.add(defSensitiveIndex.get(j + 3))
                                newDefSensitiveIndex.add(defSensitiveIndex.get(j + 4))
                            }
                        }
                    }
                    if (newDefSensitiveIndex.size() > newDefSensitiveIndexSize) {
                        valTableColumnMap.put(callerLocation + " " + funcName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(caller, newDefSensitiveIndex))
                        if (hasFetched) {
                            for (int j = newDefSensitiveIndexSize; j < newDefSensitiveIndex.size(); j += 5) {
                                def valueIndexSensitiveIndex = new ArrayList<String>()
                                if (valTableColumnMap.containsKey(callerLocation + " " + funcName + "[" + newDefSensitiveIndex.get(j) + "]")) {
                                    def valueIndexEntry = valTableColumnMap.get(callerLocation + " " + funcName + "[" + newDefSensitiveIndex.get(j) + "]")
                                    valueIndexSensitiveIndex.addAll(valueIndexEntry.getValue())
                                }
                                if (valueIndexSensitiveIndex.contains(newDefSensitiveIndex.get(j + 4))) {
                                    continue
                                }
                                valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j))
                                valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 1))
                                valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 2))
                                valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 3))
                                valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 4))
                                valTableColumnMap.put(callerLocation + " " + funcName + "[" + newDefSensitiveIndex.get(j) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(caller, valueIndexSensitiveIndex))
                                valTableColumnMap.put(callerLocation + " " + funcName + "[" + newDefSensitiveIndex.get(j + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(caller, valueIndexSensitiveIndex))
                                valTableColumnMap.put(callerLocation + " " + funcName + "->" + newDefSensitiveIndex.get(j + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(caller, valueIndexSensitiveIndex))
                            }
                        }
                        ret.add("return caller is not assignment")
                        ret.add(callerLocation + " " + funcName)

                        if (callerParent.type == "AST_RETURN") {
                            def callerStatement = caller.statements().next()
                            if (callerStatement.type == "AST_IF") {
                                callerStatement = callerStatement.ithChildren(0).next().ithChildren(0).next()
                            }
                            ret.add("callerParent.type == AST_RETURN")
                            ret.add(callerLocation+ " " + funcName)
                            transValTableColumnForReturn(callerParent, callerLocation, valTableColumnMap, valTableColumnQueue, sessionTables, callerStatement, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, ret)
                        }
                        else if (callerParent.type == "AST_ARG_LIST") {
                            ret.add("callerParent.type == AST_ARG_LIST")
                            ret.add(callerLocation+ " " + funcName)
                            transValTableColumnForCall(callerParent, callerLocation, valTableColumnMap, valTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, ret)
                        }
                    }
                }
            }
        }
    }
}

def transValTableColumnForCall(node, nodeLocation, valTableColumnMap, valTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, ret) {
    ret.add("trans valtable call")
    ret.add(getLocation(node))
    def count = node.numArguments().next()
    def start = new HashSet<Boolean>()
    start.add(true)
    def funcName = getFuncName(node)
    ret.add(funcName)
    if (isWP && skipWPFunc.contains(funcName)) {
        return
    }
    def funcs = []
    for (f in node.out("CALLS")) {
        funcs.add(f)
    }
    def location = node.toFileAbs().next().name + ":" + node.lineno
    if (funcs.size() > 0) {
        for (int i = 0; i < count; ++i) {
            def arg = statementToString(node.ithArguments(i).next(), start, new HashMap<>(), new HashSet<>(), sanitizations)
            def defArgVal = nodeLocation + " " + arg
            ret.add(defArgVal)
            def hasFetched = false
            def defSensitiveIndex = new ArrayList<String>()
            if (valTableColumnMap.containsKey(defArgVal)) {
                if (valTableColumnMap.containsKey(defArgVal + "[0]")) {
                    hasFetched = true
                }
                def entry = valTableColumnMap.get(defArgVal)
                defSensitiveIndex.addAll(entry.getValue())
                def argSensitiveIndex = new ArrayList<String>()
                if (valTableColumnMap.containsKey(location + " " + arg)) {
                    def argEntry = valTableColumnMap.get(location + " " + arg)
                    argSensitiveIndex.addAll(argEntry.getValue())
                }
                def argSensitiveIndexSize = argSensitiveIndex.size()
                for (int j = 0; j < defSensitiveIndex.size(); j += 5) {
                    def hasExisted = false
                    for (int k = 0; k < argSensitiveIndexSize; k += 5) {
                        if (argSensitiveIndex.get(k).equals(defSensitiveIndex.get(j)) &&
                                argSensitiveIndex.get(k + 1).equals(defSensitiveIndex.get(j + 1)) &&
                                argSensitiveIndex.get(k + 2).equals(defSensitiveIndex.get(j + 2)) &&
                                argSensitiveIndex.get(k + 3).equals(defSensitiveIndex.get(j + 3))
                        ) {
                            if (argSensitiveIndex.get(k + 4).equals(defSensitiveIndex.get(j + 4))) {
                                hasExisted = true
                                break
                            }
                            else {
                                def table1 = argSensitiveIndex.get(k + 4).substring(argSensitiveIndex.get(k + 4).indexOf(" ") + 1)
                                def table2 = defSensitiveIndex.get(j + 4).substring(defSensitiveIndex.get(j + 4).indexOf(" ") + 1)
                                if (table1.equals(table2)) {
                                    //need = false
                                    hasExisted = true
                                    break
                                }
                            }
                        }
                    }
                    if (!hasExisted) {
                        argSensitiveIndex.add(defSensitiveIndex.get(j))
                        argSensitiveIndex.add(defSensitiveIndex.get(j + 1))
                        argSensitiveIndex.add(defSensitiveIndex.get(j + 2))
                        argSensitiveIndex.add(defSensitiveIndex.get(j + 3))
                        argSensitiveIndex.add(defSensitiveIndex.get(j + 4))
                    }
                }
                if (argSensitiveIndex.size() > argSensitiveIndexSize) {
                    valTableColumnMap.put(location + " " + arg, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, argSensitiveIndex))
                    if (hasFetched) {
                        for (int j = argSensitiveIndexSize; j < argSensitiveIndex.size(); j += 5) {
                            def valueIndexSensitiveIndex = new ArrayList<String>()
                            if (valTableColumnMap.containsKey(location + " " + arg + "[" + argSensitiveIndex.get(j) + "]")) {
                                def valueIndexEntry = valTableColumnMap.get(location + " " + arg + "[" + argSensitiveIndex.get(j) + "]")
                                valueIndexSensitiveIndex.addAll(valueIndexEntry.getValue())
                            }
                            if (valueIndexSensitiveIndex.contains(argSensitiveIndex.get(j + 4))) {
                                continue
                            }
                            valueIndexSensitiveIndex.add(argSensitiveIndex.get(j))
                            valueIndexSensitiveIndex.add(argSensitiveIndex.get(j + 1))
                            valueIndexSensitiveIndex.add(argSensitiveIndex.get(j + 2))
                            valueIndexSensitiveIndex.add(argSensitiveIndex.get(j + 3))
                            valueIndexSensitiveIndex.add(argSensitiveIndex.get(j + 4))
                            valTableColumnMap.put(location + " " + arg + "[" + argSensitiveIndex.get(j) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, valueIndexSensitiveIndex))
                            valTableColumnMap.put(location + " " + arg + "[" + argSensitiveIndex.get(j + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, valueIndexSensitiveIndex))
                            valTableColumnMap.put(location + " " + arg + "->" + argSensitiveIndex.get(j + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, valueIndexSensitiveIndex))
                        }
                    }
                }
            }
            else {
                if (node.ithArguments(i).next().type == "AST_CALL" || node.ithArguments(i).next().type == "AST_METHOD_CALL" || node.ithArguments(i).next().type == "AST_STATIC_CALL") {
                    transValTableColumnForCall(node.ithArguments(i).next(), nodeLocation, valTableColumnMap, valTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, ret)
                    def retFuncName = getFuncName(node.ithArguments(i).next())
                    def callerLocation = node.ithArguments(i).next().toFileAbs().next().name + ":" + node.ithArguments(i).next().lineno
                    def defFunc = callerLocation+" "+retFuncName
                    if (valTableColumnMap.containsKey(defFunc)) {
                        if (valTableColumnMap.containsKey(defFunc + "[0]")) {
                            hasFetched = true
                        }
                        def defEntry = valTableColumnMap.get(defFunc)
                        defSensitiveIndex.addAll(defEntry.getValue())
                    }
                    else {
                        ret.add("defFunc not found in call in valtable")
                        ret.add(defFunc)
                    }
                }
                else {
                    ret.add("other type in call in valtable")
                    ret.add(getLocation(node.ithArguments(i).next()))
                }
            }

            if (defSensitiveIndex.size() > 0) {
                for (func in funcs) {
                    def paramNum = func.numParams().next()
                    if (i < paramNum) {
                        def paramNode = func.ithParams(i).next()
                        location = paramNode.toFileAbs().next().name + ":" + paramNode.lineno
                        def param = statementToString(paramNode, start, new HashMap<>(), new HashSet<>(), sanitizations)
                        if (param.startsWith("\$")) {
                            def newDefSensitiveIndex = new ArrayList<String>()
                            if (valTableColumnMap.containsKey(location + " " + param)) {
                                def newDefEntry = valTableColumnMap.get(location + " " + param)
                                newDefSensitiveIndex.addAll(newDefEntry.getValue())
                            }
                            def newDefSensitiveIndexSize = newDefSensitiveIndex.size()
                            def needOffer = false
                            for (int j = 0; j < defSensitiveIndex.size(); j += 5) {
                                def hasExisted = false
                                def need = true
                                for (int k = 0; k < newDefSensitiveIndexSize; k += 5) {
                                    if (newDefSensitiveIndex.get(k).equals(defSensitiveIndex.get(j)) &&
                                            newDefSensitiveIndex.get(k + 1).equals(defSensitiveIndex.get(j + 1)) &&
                                            newDefSensitiveIndex.get(k + 2).equals(defSensitiveIndex.get(j + 2)) &&
                                            newDefSensitiveIndex.get(k + 3).equals(defSensitiveIndex.get(j + 3))
                                    ) {
                                        if (newDefSensitiveIndex.get(k + 4).equals(defSensitiveIndex.get(j + 4))) {
                                            hasExisted = true
                                            break
                                        }
                                        else {
                                            def table1 = newDefSensitiveIndex.get(k + 4).substring(newDefSensitiveIndex.get(k + 4).indexOf(" ") + 1)
                                            def table2 = defSensitiveIndex.get(j + 4).substring(defSensitiveIndex.get(j + 4).indexOf(" ") + 1)
                                            if (table1.equals(table2)) {
                                                hasExisted = true
                                                break
                                            }
                                        }
                                    }
                                }
                                needOffer = needOffer || need
                                if (!hasExisted) {
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 1))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 2))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 3))
                                    newDefSensitiveIndex.add(defSensitiveIndex.get(j + 4))
                                }
                            }
                            if (newDefSensitiveIndex.size() > newDefSensitiveIndexSize) {
                                valTableColumnMap.put(location + " " + param, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(paramNode, newDefSensitiveIndex))
                                if (needOffer) {
                                    valTableColumnQueue.offer(location + " " + param)
                                }
                                if (hasFetched) {
                                    for (int j = newDefSensitiveIndexSize; j < newDefSensitiveIndex.size(); j += 5) {
                                        def valueIndexSensitiveIndex = new ArrayList<String>()
                                        if (valTableColumnMap.containsKey(location + " " + param + "[" + newDefSensitiveIndex.get(j) + "]")) {
                                            def valueIndexEntry = valTableColumnMap.get(location + " " + param + "[" + newDefSensitiveIndex.get(j) + "]")
                                            valueIndexSensitiveIndex.addAll(valueIndexEntry.getValue())
                                        }
                                        if (valueIndexSensitiveIndex.contains(newDefSensitiveIndex.get(j + 4))) {
                                            continue
                                        }
                                        valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j))
                                        valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 1))
                                        valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 2))
                                        valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 3))
                                        valueIndexSensitiveIndex.add(newDefSensitiveIndex.get(j + 4))
                                        valTableColumnMap.put(location + " " + param + "[" + newDefSensitiveIndex.get(j) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(paramNode, valueIndexSensitiveIndex))
                                        valTableColumnMap.put(location + " " + param + "[" + newDefSensitiveIndex.get(j + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(paramNode, valueIndexSensitiveIndex))
                                        valTableColumnMap.put(location + " " + param + "->" + newDefSensitiveIndex.get(j + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(paramNode, valueIndexSensitiveIndex))
                                    }
                                }
                            }
                        } else {
                            ret.add("param is not variable in valtable")
                            ret.add(location + " " + param)
                        }
                    }
                }
            }
        }
    }
    else {
        if (funcName == "array_push") {
            def array = getAllValName(node.ithArguments(0).next())
            array = array+"[0]"
            for (int i = 1; i < count; ++i) {
                def arg = statementToString(node.ithArguments(i).next(), start, new HashMap<>(), new HashSet<>(), sanitizations)
                def defArgVal = nodeLocation + " " + arg
                ret.add(defArgVal)
                def hasFetched = false
                def defSensitiveIndex = new ArrayList<String>()
                if (valTableColumnMap.containsKey(defArgVal)) {
                    if (valTableColumnMap.containsKey(defArgVal + "[0]")) {
                        hasFetched = true
                    }
                    def entry = valTableColumnMap.get(defArgVal)
                    defSensitiveIndex.addAll(entry.getValue())
                }
                else {
                    if (node.ithArguments(i).next().type == "AST_CALL" || node.ithArguments(i).next().type == "AST_METHOD_CALL") {
                        transValTableColumnForCall(node.ithArguments(i).next(), nodeLocation, valTableColumnMap, valTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, ret)
                        def pushFuncName = getFuncName(node.ithArguments(i).next())
                        def callerLocation = node.ithArguments(i).next().toFileAbs().next().name + ":" + node.ithArguments(i).next().lineno
                        def defFunc = callerLocation+" "+pushFuncName
                        if (valTableColumnMap.containsKey(defFunc)) {
                            if (valTableColumnMap.containsKey(defFunc + "[0]")) {
                                hasFetched = true
                            }
                            def defEntry = valTableColumnMap.get(defFunc)
                            defSensitiveIndex.addAll(defEntry.getValue())
                        }
                        else {
                            ret.add("defFunc not found in array_push in valtable")
                            ret.add(defFunc)
                        }
                    }
                    else {
                        ret.add("other type in array_push in valtable")
                        ret.add(getLocation(node.ithArguments(i).next()))
                    }
                }

                if (defSensitiveIndex.size() > 0) {
                    def arraySensitiveIndex = new ArrayList<String>()
                    if (valTableColumnMap.containsKey(location + " " + array)) {
                        def arrayEntry = valTableColumnMap.get(location + " " + array)
                        arraySensitiveIndex.addAll(arrayEntry.getValue())
                    }
                    def arraySensitiveIndexSize = arraySensitiveIndex.size()
                    def needOffer = false
                    for (int j = 0; j < defSensitiveIndex.size(); j += 5) {
                        def hasExisted = false
                        def need = true
                        for (int k = 0; k < arraySensitiveIndexSize; k += 5) {
                            if (arraySensitiveIndex.get(k).equals(defSensitiveIndex.get(j)) &&
                                    arraySensitiveIndex.get(k + 1).equals(defSensitiveIndex.get(j + 1)) &&
                                    arraySensitiveIndex.get(k + 2).equals(defSensitiveIndex.get(j + 2)) &&
                                    arraySensitiveIndex.get(k + 3).equals(defSensitiveIndex.get(j + 3))
                            ) {
                                if (arraySensitiveIndex.get(k + 4).equals(defSensitiveIndex.get(j + 4))) {
                                    hasExisted = true
                                    break
                                }
                                else {
                                    def table1 = arraySensitiveIndex.get(k + 4).substring(arraySensitiveIndex.get(k + 4).indexOf(" ") + 1)
                                    def table2 = defSensitiveIndex.get(j + 4).substring(defSensitiveIndex.get(j + 4).indexOf(" ") + 1)
                                    if (table1.equals(table2)) {
                                        hasExisted = true
                                        break
                                    }
                                }
                            }
                        }
                        needOffer = needOffer || need
                        if (!hasExisted) {
                            arraySensitiveIndex.add(defSensitiveIndex.get(j))
                            arraySensitiveIndex.add(defSensitiveIndex.get(j + 1))
                            arraySensitiveIndex.add(defSensitiveIndex.get(j + 2))
                            arraySensitiveIndex.add(defSensitiveIndex.get(j + 3))
                            arraySensitiveIndex.add(defSensitiveIndex.get(j + 4))
                        }
                    }
                    if (arraySensitiveIndex.size() > arraySensitiveIndexSize) {
                        valTableColumnMap.put(location + " " + array, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, arraySensitiveIndex))
                        if (hasFetched) {
                            for (int j = arraySensitiveIndexSize; j < arraySensitiveIndex.size(); j += 5) {
                                def valueIndexSensitiveIndex = new ArrayList<String>()
                                if (valTableColumnMap.containsKey(defArgVal + "[" + arraySensitiveIndex.get(j) + "]")) {
                                    def valueIndexEntry = valTableColumnMap.get(defArgVal + "[" + arraySensitiveIndex.get(j) + "]")
                                    valueIndexSensitiveIndex.addAll(valueIndexEntry.getValue())
                                }
                                if (valueIndexSensitiveIndex.contains(arraySensitiveIndex.get(j + 4))) {
                                    continue
                                }
                                valueIndexSensitiveIndex.add(arraySensitiveIndex.get(j))
                                valueIndexSensitiveIndex.add(arraySensitiveIndex.get(j + 1))
                                valueIndexSensitiveIndex.add(arraySensitiveIndex.get(j + 2))
                                valueIndexSensitiveIndex.add(arraySensitiveIndex.get(j + 3))
                                valueIndexSensitiveIndex.add(arraySensitiveIndex.get(j + 4))
                                valTableColumnMap.put(location + " " + array + "[" + arraySensitiveIndex.get(j) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, valueIndexSensitiveIndex))
                                valTableColumnMap.put(location + " " + array + "[" + arraySensitiveIndex.get(j + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, valueIndexSensitiveIndex))
                                valTableColumnMap.put(location + " " + array + "->" + arraySensitiveIndex.get(j + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, valueIndexSensitiveIndex))
                            }
                        }
                        if (needOffer) {
                            valTableColumnQueue.offer(location + " " + array)
                        }
                    }
                }
            }
        }
    }
}

def setValTableColumnFor(valTableColumnMap, location, assignName, assignNameSensitiveIndex, subIndex, statement, i) {
    def assignNameIndexRSensitiveIndex = new ArrayList<String>()
    if (valTableColumnMap.containsKey(location+" "+assignName+subIndex+"[" + assignNameSensitiveIndex.get(i) + "]")) {
        def assignNameIndexEntry = valTableColumnMap.get(location+" "+assignName+subIndex+"[" + assignNameSensitiveIndex.get(i) + "]")
        assignNameIndexRSensitiveIndex.addAll(assignNameIndexEntry.getValue())
    }
    if (assignNameIndexRSensitiveIndex.contains(assignNameSensitiveIndex.get(i+4))) {
        return
    }
    assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i))
    assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+1))
    assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+2))
    assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+3))
    assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+4))
    valTableColumnMap.put(location + " " + assignName + subIndex + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexRSensitiveIndex))
    valTableColumnMap.put(location + " " + assignName + subIndex + "[" + assignNameSensitiveIndex.get(i + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexRSensitiveIndex))
    valTableColumnMap.put(location + " " + assignName + subIndex + "->" + assignNameSensitiveIndex.get(i + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexRSensitiveIndex))
    if (assignName.startsWith("\$_SESSION[")) {
        valTableColumnMap.put(assignName + subIndex + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexRSensitiveIndex))
        valTableColumnMap.put(assignName + subIndex + "[" + assignNameSensitiveIndex.get(i + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexRSensitiveIndex))
        valTableColumnMap.put(assignName + subIndex + "->" + assignNameSensitiveIndex.get(i + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexRSensitiveIndex))
    }
}

def transValTableColumn(valTableColumnQueue, valTableColumnMap, sessionTables, sanitizations, nodes, sql_fetch_funcs, equal_funcs, fetchIndex, queryIndex, sql_prepare_funcs, isWP, skipWPFunc, isDAL, dal_sql_query_funcs, selectCondColumns, selectTableColumnsView, condTableColumnsMap, condTableColumns, callerDTableMaps, dynamicTableNodeMaps, valTableRet) {
    while (valTableColumnQueue.size() > 0) {
        def key = valTableColumnQueue.poll()
        System.out.println(key)
        if (valTableColumnMap.containsKey(key)) {
            def entry = valTableColumnMap.get(key)
            def valOfKey = key.substring(key.indexOf(" ")+1)
            def node = entry.getKey()
            def nodeLocation = node.toFileAbs().next().name + ":" + node.lineno
            def sensitive_index = entry.getValue()
            valTableRet.add("**************************************************")
            valTableRet.add(nodeLocation)
            for (Vertex v in node.out("REACHES")) {
                def statement = v
                def location = v.toFileAbs().next().name + ":" + v.lineno
                valTableRet.add("######"+location)
                if (nodes.contains(v)) {
                    continue
                }
                v = getInnerNode(v)
                if (v.type == "AST_ASSIGN") {
                    def assignName = getAllValName(v.ithChildren(0).next())
                    assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                    def valueNode = v.ithChildren(1).next()

                    def funcs = new HashSet<String>()
                    def start = new HashSet<Boolean>()
                    start.add(true)
                    def value = statementToString(valueNode, start, new HashMap<>(), funcs, sanitizations)
                    value = value.trim()
                    valTableRet.add(getLocation(valueNode))
                    valTableRet.add(assignName)
                    valTableRet.add(value)
                    valTableRet.add(funcs)

                    if (value.startsWith("getArrayVal")) {
                        if (valueNode.type == "AST_CALL") {
                            if (valueNode.numArguments().next() == 2) {
                                value = getAllValName(valueNode.ithArguments(0).next()) + "[" + getAllValName(valueNode.ithArguments(1).next()) + "]"
                            }
                        }
                    }

                    def inSqlFetch = false
                    def inEqual = false
                    def inFetchResult = false
                    def inSqlQuery = false
                    def inSqlPrepare = false
                    def inWpGetResults = false
                    def inWpGetRow = false
                    def inWpApplyFilters = false
                    def inDBGet = false
                    def inQ2A = false
                    def qIndex = 0
                    for (String func in funcs) {
                        if (sql_fetch_funcs.contains(func)) {
                            inSqlFetch = true
                        }
                        else if (equal_funcs.contains(func)) {
                            inEqual = true
                        }
                        else if (fetchIndex.containsKey(func)) {
                            inFetchResult = true
                        }
                        else if (queryIndex.containsKey(func)) {
                            inSqlQuery = true
                            qIndex = queryIndex.get(func)
                        }
                        else if (sql_prepare_funcs.contains(func)) {
                            inSqlPrepare = true
                        }
                    }
                    if (inEqual) {
                        value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
                    }
                    if (inSqlQuery) {
                        if (qIndex == 0) {
                            value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
                        }
                        else if (qIndex == 1) {
                            value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+)([\s,]+)([\$\w\[\]\'-]+)\))/, '$4')
                        }
                    }
                    if (inSqlPrepare) {
                        value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
                    }
                    if (inWpApplyFilters) {
                        if (valueNode.type == "AST_CALL" && getFuncName(valueNode) == "apply_filters") {
                            value = statementToString(valueNode.ithArguments(1).next(), start, new HashMap<>(), new HashSet<>(), sanitizations)
                        }
                    }

                    if (inSqlFetch || inWpGetRow || inWpGetResults || inDBGet) {
                        if (assignName.startsWith("[")) {
                            assignName = assignName.substring(1, assignName.length()-1)
                            def list = assignName.split(',')
                            for (int j = 0; j < list.size(); ++j) {
                                def item = list[j]
                                def column = item.replace("\$", "")
                                for (int i = 0; i < sensitive_index.size(); i += 5) {
                                    if (sensitive_index.get(i).equals(Integer.toString(j)) || sensitive_index.get(i+2).equals(column)) {
                                        def itemSensitiveIndex = new ArrayList<String>()
                                        if (valTableColumnMap.containsKey(location+" "+item)) {
                                            def itemEntry = valTableColumnMap.get(location+" "+item)
                                            itemSensitiveIndex.addAll(itemEntry.getValue())
                                        }
                                        def hasExisted = false
                                        def needOffer = false
                                        for (int k = 0; k < itemSensitiveIndex.size(); k += 5) {
                                            if (itemSensitiveIndex.get(k).equals(sensitive_index.get(i)) &&
                                                    itemSensitiveIndex.get(k+1).equals(sensitive_index.get(i+1)) &&
                                                    itemSensitiveIndex.get(k+2).equals(sensitive_index.get(i+2)) &&
                                                    itemSensitiveIndex.get(k+3).equals(sensitive_index.get(i+3))
                                            ) {
                                                if (itemSensitiveIndex.get(k+4).equals(sensitive_index.get(i+4))) {
                                                    hasExisted = true
                                                    break
                                                }
                                                else {
                                                    def table1 = itemSensitiveIndex.get(k+4).substring(itemSensitiveIndex.get(k+4).indexOf(" ")+1)
                                                    def table2 = sensitive_index.get(i+4).substring(sensitive_index.get(i+4).indexOf(" ")+1)
                                                    if (!table1.equals(table2)) {
                                                        needOffer = true
                                                    }
                                                }
                                            }
                                        }
                                        if (!hasExisted) {
                                            itemSensitiveIndex.add(sensitive_index.get(i))
                                            itemSensitiveIndex.add(sensitive_index.get(i+1))
                                            itemSensitiveIndex.add(sensitive_index.get(i+2))
                                            itemSensitiveIndex.add(sensitive_index.get(i+3))
                                            itemSensitiveIndex.add(sensitive_index.get(i+4))
                                            valTableColumnMap.put(location+" "+item, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, itemSensitiveIndex))
                                            if (needOffer) {
                                                valTableColumnQueue.offer(location + " " + item)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if (assignName != "") {
                            def assignNameSensitiveIndex = new ArrayList<String>()
                            if (valTableColumnMap.containsKey(location+" "+assignName)) {
                                def assignNameEntry = valTableColumnMap.get(location+" "+assignName)
                                assignNameSensitiveIndex.addAll(assignNameEntry.getValue())
                            }
                            def assignNameSensitiveIndexSize = assignNameSensitiveIndex.size()
                            def needOffer = false
                            for (int i = 0; i < sensitive_index.size(); i += 5) {
                                def hasExisted = false
                                def need = true
                                for (int j = 0; j < assignNameSensitiveIndexSize; j += 5) {
                                    if (assignNameSensitiveIndex.get(j).equals(sensitive_index.get(i)) &&
                                            assignNameSensitiveIndex.get(j+1).equals(sensitive_index.get(i+1)) &&
                                            assignNameSensitiveIndex.get(j+2).equals(sensitive_index.get(i+2)) &&
                                            assignNameSensitiveIndex.get(j+3).equals(sensitive_index.get(i+3))
                                    ) {
                                        if (assignNameSensitiveIndex.get(j+4).equals(sensitive_index.get(i+4))) {
                                            hasExisted = true
                                            break
                                        }
                                        else {
                                            def table1 = assignNameSensitiveIndex.get(j+4).substring(assignNameSensitiveIndex.get(j+4).indexOf(" ")+1)
                                            def table2 = sensitive_index.get(i+4).substring(sensitive_index.get(i+4).indexOf(" ")+1)
                                            if (table1.equals(table2)) {
                                                hasExisted = true
                                                break
                                            }
                                        }
                                    }
                                }
                                needOffer = needOffer || need
                                if (!hasExisted) {
                                    assignNameSensitiveIndex.add(sensitive_index.get(i))
                                    assignNameSensitiveIndex.add(sensitive_index.get(i+1))
                                    assignNameSensitiveIndex.add(sensitive_index.get(i+2))
                                    assignNameSensitiveIndex.add(sensitive_index.get(i+3))
                                    assignNameSensitiveIndex.add(sensitive_index.get(i+4))
                                }
                            }
                            if (assignNameSensitiveIndex.size() > assignNameSensitiveIndexSize) {
                                valTableColumnMap.put(location+" "+assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameSensitiveIndex))
                                if (assignName.startsWith("\$_SESSION[")) {
                                    setValTableColumnForSession(assignName, statement, valTableColumnMap, sessionTables, assignNameSensitiveIndex, assignNameSensitiveIndexSize)
                                }
                                for (int i = assignNameSensitiveIndexSize; i < assignNameSensitiveIndex.size(); i += 5) {
                                    def assignNameIndexSensitiveIndex = new ArrayList<String>()
                                    if (valTableColumnMap.containsKey(location+" "+assignName+"["+assignNameSensitiveIndex.get(i)+"]")) {
                                        def assignNameIndexEntry = valTableColumnMap.get(location+" "+assignName+"["+assignNameSensitiveIndex.get(i)+"]")
                                        assignNameIndexSensitiveIndex.addAll(assignNameIndexEntry.getValue())
                                    }
                                    if (assignNameIndexSensitiveIndex.contains(assignNameSensitiveIndex.get(i+4))) {
                                        continue
                                    }
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+1))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+2))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+3))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+4))
                                    valTableColumnMap.put(location+" "+assignName+"["+assignNameSensitiveIndex.get(i)+"]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    valTableColumnMap.put(location+" "+assignName+"["+assignNameSensitiveIndex.get(i+2)+"]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    valTableColumnMap.put(location+" "+assignName+"->"+assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    if (assignName.startsWith("\$_SESSION[")) {
                                        valTableColumnMap.put(assignName+"["+assignNameSensitiveIndex.get(i)+"]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName+"["+assignNameSensitiveIndex.get(i+2)+"]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName+"->"+assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    }
                                    if (inWpGetResults) {
                                        setValTableColumnFor(valTableColumnMap, location, assignName, assignNameSensitiveIndex, "[0]", statement, i)
                                    }
                                    if (inDBGet) {
                                        setValTableColumnFor(valTableColumnMap, location, assignName, assignNameSensitiveIndex, "[1]", statement, i)
                                    }
                                }
                                if (needOffer) {
                                    valTableColumnQueue.offer(location+" "+assignName)
                                }
                            }
                        }
                        else {
                        }
                    }
                    else if (inFetchResult) {
                        def result = value.replaceAll(/(.*\(([\$\w\[\]\'-]+)\s*,\s*(\d)+.*\))/, '$2')
                        def row = value.replaceAll(/(.*\(([\$\w\[\]\'-]+)\s*,\s*(\d)+.*\))/, '$3')
                        def defVal = nodeLocation+" "+result
                        if (valTableColumnMap.containsKey(defVal)) {
                            def defEntry = valTableColumnMap.get(defVal)
                            def defSensitiveIndex = defEntry.getValue()
                            if (assignName != "") {
                                def assignNameSensitiveIndex = new ArrayList<String>()
                                if (valTableColumnMap.containsKey(location+" "+assignName)) {
                                    def assignNameEntry = valTableColumnMap.get(location+" "+assignName)
                                    assignNameSensitiveIndex.addAll(assignNameEntry.getValue())
                                }
                                def assignNameSensitiveIndexSize = assignNameSensitiveIndex.size()
                                def needOffer = false
                                for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                                    def hasExisted = false
                                    def need = true
                                    for (int j = 0; j < assignNameSensitiveIndexSize; j += 5) {
                                        if (assignNameSensitiveIndex.get(j).equals(defSensitiveIndex.get(i)) &&
                                                assignNameSensitiveIndex.get(j+1).equals(defSensitiveIndex.get(i+1)) &&
                                                assignNameSensitiveIndex.get(j+2).equals(defSensitiveIndex.get(i+2)) &&
                                                assignNameSensitiveIndex.get(j+3).equals(defSensitiveIndex.get(i+3))
                                        ) {
                                            if (assignNameSensitiveIndex.get(j+4).equals(defSensitiveIndex.get(i+4))) {
                                                hasExisted = true
                                                break
                                            }
                                            else {
                                                def table1 = assignNameSensitiveIndex.get(j+4).substring(assignNameSensitiveIndex.get(j+4).indexOf(" ")+1)
                                                def table2 = defSensitiveIndex.get(i+4).substring(defSensitiveIndex.get(i+4).indexOf(" ")+1)
                                                if (table1.equals(table2)) {
                                                    hasExisted = true
                                                    break
                                                }
                                            }
                                        }
                                    }
                                    needOffer = needOffer || need
                                    if (!hasExisted) {
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i))
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i+1))
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i+2))
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i+3))
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i+4))
                                    }
                                }
                                if (assignNameSensitiveIndex.size() > assignNameSensitiveIndexSize) {
                                    valTableColumnMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameSensitiveIndex))
                                    def assignNameIndexSensitiveIndex = new ArrayList<String>()
                                    for (int i = 0; i < assignNameSensitiveIndex.size(); i += 5) {
                                        if (assignNameSensitiveIndex.get(i).equals(row)) {
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i))
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+1))
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+2))
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+3))
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+4))
                                        }
                                    }
                                    valTableColumnMap.put(location+" "+assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    if (needOffer) {
                                        valTableColumnQueue.offer(location+" "+assignName)
                                    }
                                    if (assignName.startsWith("\$_SESSION[")) {
                                        setValTableColumnForSession(assignName, statement, valTableColumnMap, sessionTables, assignNameSensitiveIndex, assignNameSensitiveIndexSize)
                                    }
                                }
                            }
                            else {
                            }
                        }
                        else {
                        }
                    }
                    else if (value.startsWith("\$")) {
                        def defVal = nodeLocation+" "+value
                        def value0 = value+"[0]"
                        if ((value.startsWith(valOfKey) && valTableColumnMap.containsKey(defVal)) || (value0.startsWith(valOfKey) && valTableColumnMap.containsKey(defVal+"[0]"))) {
                            if (!valTableColumnMap.containsKey(defVal) && value0.startsWith(valOfKey) && valTableColumnMap.containsKey(defVal+"[0]")) {
                                defVal = defVal + "[0]"
                            }
                            def hasFetched = false
                            if (valTableColumnMap.containsKey(defVal+"[0]")) {
                                hasFetched = true
                            }
                            def defEntry = valTableColumnMap.get(defVal)
                            def defSensitiveIndex = defEntry.getValue()
                            if (assignName.startsWith("[")) {
                                assignName = assignName.substring(1, assignName.length()-1)
                                list = assignName.split(',')
                                for (int j = 0; j < list.size(); ++j) {
                                    item = list[j]
                                    column = item.replace("\$", "")
                                    for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                                        if (defSensitiveIndex.get(i).equals(Integer.toString(j)) || defSensitiveIndex.get(i+2).equals(column)) {
                                            def itemSensitiveIndex = new ArrayList<String>()
                                            if (valTableColumnMap.containsKey(location+" "+item)) {
                                                def itemEntry = valTableColumnMap.get(location+" "+item)
                                                itemSensitiveIndex.addAll(itemEntry.getValue())
                                            }
                                            def hasExisted = false
                                            def needOffer = false
                                            for (int k = 0; k < itemSensitiveIndex.size(); k += 5) {
                                                if (itemSensitiveIndex.get(k).equals(defSensitiveIndex.get(i)) &&
                                                        itemSensitiveIndex.get(k+1).equals(defSensitiveIndex.get(i+1)) &&
                                                        itemSensitiveIndex.get(k+2).equals(defSensitiveIndex.get(i+2)) &&
                                                        itemSensitiveIndex.get(k+3).equals(defSensitiveIndex.get(i+3))
                                                ) {
                                                    if (itemSensitiveIndex.get(k+4).equals(defSensitiveIndex.get(i+4))) {
                                                        hasExisted = true
                                                        break
                                                    }
                                                    else {
                                                        def table1 = itemSensitiveIndex.get(k+4).substring(itemSensitiveIndex.get(k+4).indexOf(" ")+1)
                                                        def table2 = defSensitiveIndex.get(i+4).substring(defSensitiveIndex.get(i+4).indexOf(" ")+1)
                                                        if (!table1.equals(table2)) {
                                                            needOffer = true
                                                        }
                                                    }
                                                }
                                            }
                                            if (!hasExisted) {
                                                itemSensitiveIndex.add(defSensitiveIndex.get(i))
                                                itemSensitiveIndex.add(defSensitiveIndex.get(i+1))
                                                itemSensitiveIndex.add(defSensitiveIndex.get(i+2))
                                                itemSensitiveIndex.add(defSensitiveIndex.get(i+3))
                                                itemSensitiveIndex.add(defSensitiveIndex.get(i+4))
                                                valTableColumnMap.put(location+" "+item, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, itemSensitiveIndex))
                                                if (needOffer) {
                                                    valTableColumnQueue.offer(location+" "+item)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            else if (assignName != "") {
                                def assignNameSensitiveIndex = new ArrayList<String>()
                                if (valTableColumnMap.containsKey(location+" "+assignName)) {
                                    def assignNameEntry = valTableColumnMap.get(location+" "+assignName)
                                    assignNameSensitiveIndex.addAll(assignNameEntry.getValue())
                                }
                                def assignNameSensitiveIndexSize = assignNameSensitiveIndex.size()
                                def needOffer = false
                                for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                                    def hasExisted = false
                                    def need = true
                                    for (int j = 0; j < assignNameSensitiveIndexSize; j += 5) {
                                        if (assignNameSensitiveIndex.get(j).equals(defSensitiveIndex.get(i)) &&
                                                assignNameSensitiveIndex.get(j+1).equals(defSensitiveIndex.get(i+1)) &&
                                                assignNameSensitiveIndex.get(j+2).equals(defSensitiveIndex.get(i+2)) &&
                                                assignNameSensitiveIndex.get(j+3).equals(defSensitiveIndex.get(i+3))
                                        ) {
                                            if (assignNameSensitiveIndex.get(j+4).equals(defSensitiveIndex.get(i+4))) {
                                                hasExisted = true
                                                break
                                            }
                                            else {
                                                def table1 = assignNameSensitiveIndex.get(j+4).substring(assignNameSensitiveIndex.get(j+4).indexOf(" ")+1)
                                                def table2 = defSensitiveIndex.get(i+4).substring(defSensitiveIndex.get(i+4).indexOf(" ")+1)
                                                if (table1.equals(table2)) {
                                                    hasExisted = true
                                                    break
                                                }
                                            }
                                        }
                                    }
                                    needOffer = needOffer || need
                                    if (!hasExisted) {
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i))
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i+1))
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i+2))
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i+3))
                                        assignNameSensitiveIndex.add(defSensitiveIndex.get(i+4))
                                    }
                                }
                                if (assignNameSensitiveIndex.size() > assignNameSensitiveIndexSize) {
                                    valTableColumnMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameSensitiveIndex))
                                    if (needOffer) {
                                        valTableColumnQueue.offer(location+" "+assignName)
                                    }
                                    if (assignName.startsWith("\$_SESSION[")) {
                                        setValTableColumnForSession(assignName, statement, valTableColumnMap, sessionTables, assignNameSensitiveIndex, assignNameSensitiveIndexSize)
                                    }
                                    if (hasFetched) {
                                        for (int i = assignNameSensitiveIndexSize; i < assignNameSensitiveIndex.size(); i += 5) {
                                            def assignNameIndexSensitiveIndex = new ArrayList<String>()
                                            if (valTableColumnMap.containsKey(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]")) {
                                                def assignNameIndexEntry = valTableColumnMap.get(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]")
                                                assignNameIndexSensitiveIndex.addAll(assignNameIndexEntry.getValue())
                                            }
                                            if (assignNameIndexSensitiveIndex.contains(assignNameSensitiveIndex.get(i + 4))) {
                                                continue
                                            }
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i))
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i + 1))
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i + 2))
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i + 3))
                                            assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i + 4))
                                            valTableColumnMap.put(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                            valTableColumnMap.put(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                            valTableColumnMap.put(location + " " + assignName + "->" + assignNameSensitiveIndex.get(i + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                            if (assignName.startsWith("\$_SESSION[")) {
                                                valTableColumnMap.put(assignName + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                                valTableColumnMap.put(assignName + "[" + assignNameSensitiveIndex.get(i + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                                valTableColumnMap.put(assignName + "->" + assignNameSensitiveIndex.get(i + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                            }
                                        }
                                    }
                                }
                            }
                            else {
                                valTableRet.add("value assignName is empty in valtable")
                                valTableRet.add(getLocation(v.ithChildren(0).next()))
                            }
                            def valueSensitiveIndex = new ArrayList<String>()
                            if (valTableColumnMap.containsKey(location+" "+value)) {
                                def valueEntry = valTableColumnMap.get(location+" "+value)
                                valueSensitiveIndex.addAll(valueEntry.getValue())
                            }
                            def valueSensitiveIndexSize = valueSensitiveIndex.size()
                            for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                                def hasExisted = false
                                for (int j = 0; j < valueSensitiveIndexSize; j += 5) {
                                    if (valueSensitiveIndex.get(j).equals(defSensitiveIndex.get(i)) &&
                                            valueSensitiveIndex.get(j+1).equals(defSensitiveIndex.get(i+1)) &&
                                            valueSensitiveIndex.get(j+2).equals(defSensitiveIndex.get(i+2)) &&
                                            valueSensitiveIndex.get(j+3).equals(defSensitiveIndex.get(i+3))
                                    ) {
                                        if (valueSensitiveIndex.get(j+4).equals(defSensitiveIndex.get(i+4))) {
                                            hasExisted = true
                                            break
                                        }
                                        else {
                                            def table1 = valueSensitiveIndex.get(j+4).substring(valueSensitiveIndex.get(j+4).indexOf(" ")+1)
                                            def table2 = defSensitiveIndex.get(i+4).substring(defSensitiveIndex.get(i+4).indexOf(" ")+1)
                                            if (table1.equals(table2)) {
                                                hasExisted = true
                                                break
                                            }
                                        }
                                    }
                                }
                                if (!hasExisted) {
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i))
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i+1))
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i+2))
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i+3))
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i+4))
                                }
                            }
                            if (valueSensitiveIndex.size() > valueSensitiveIndexSize) {
                                valTableColumnMap.put(location+" "+value, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, valueSensitiveIndex))
                                if (hasFetched) {
                                    for (int i = valueSensitiveIndexSize; i < valueSensitiveIndex.size(); i += 5) {
                                        def valueIndexSensitiveIndex = new ArrayList<String>()
                                        if (valTableColumnMap.containsKey(location+" "+value+"["+valueSensitiveIndex.get(i)+"]")) {
                                            def valueIndexEntry = valTableColumnMap.get(location+" "+value+"["+valueSensitiveIndex.get(i)+"]")
                                            valueIndexSensitiveIndex.addAll(valueIndexEntry.getValue())
                                        }
                                        if (valueIndexSensitiveIndex.contains(valueSensitiveIndex.get(i+4))) {
                                            continue
                                        }
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i))
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i+1))
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i+2))
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i+3))
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i+4))
                                        valTableColumnMap.put(location+" "+value+"["+valueSensitiveIndex.get(i)+"]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, valueIndexSensitiveIndex))
                                        valTableColumnMap.put(location+" "+value+"["+valueSensitiveIndex.get(i+2)+"]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, valueIndexSensitiveIndex))
                                        valTableColumnMap.put(location+" "+value+"->"+valueSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, valueIndexSensitiveIndex))
                                    }
                                }
                            }
                        }
                        else {
                            valTableRet.add("defVal not found in valtable")
                            valTableRet.add(defVal)
                        }
                    }
                    else if (valueNode.type == "AST_CALL" || valueNode.type == "AST_METHOD_CALL" || valueNode.type == "AST_STATIC_CALL") {
                        if (isDAL) {
                            def callFuncName = getFuncName(valueNode)
                            if (dal_sql_query_funcs.contains(callFuncName)) {
                                continue
                            }
                        }
                        transValTableColumnForCall(valueNode, nodeLocation, valTableColumnMap, valTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, valTableRet)
                    }
                    else {
                        valTableRet.add("other type")
                        valTableRet.add(getLocation(valueNode))
                    }
                    if (v.ithChildren(0).next().type == "AST_DIM") {
                        def arrayName = getAllValName(v.ithChildren(0).next().ithChildren(0).next())
                        def arrayIndex = getAllValName(v.ithChildren(0).next().ithChildren(1).next())
                        def defArrayName = nodeLocation+" "+arrayName
                        valTableRet.add("assignName is array")
                        valTableRet.add(arrayName)
                        valTableRet.add(arrayIndex)
                        if (valTableColumnMap.containsKey(defArrayName)) {
                            def hasFetched = false
                            if (valTableColumnMap.containsKey(defArrayName + "[0]")) {
                                hasFetched = true
                            }
                            def defEntry = valTableColumnMap.get(defArrayName)
                            def defSensitiveIndex = defEntry.getValue()
                            def newSensitiveIndex = new ArrayList<String>()
                            if (valTableColumnMap.containsKey(location + " " + arrayName)) {
                                def newEntry = valTableColumnMap.get(location + " " + arrayName)
                                newSensitiveIndex.addAll(newEntry.getValue())
                            }
                            def newSensitiveIndexSize = newSensitiveIndex.size()
                            def needOffer = false
                            for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                                def hasExisted = false
                                def need = true
                                for (int j = 0; j < newSensitiveIndexSize; j += 5) {
                                    if (newSensitiveIndex.get(j).equals(defSensitiveIndex.get(i)) &&
                                            newSensitiveIndex.get(j+1).equals(defSensitiveIndex.get(i+1)) &&
                                            newSensitiveIndex.get(j+2).equals(defSensitiveIndex.get(i+2)) &&
                                            newSensitiveIndex.get(j+3).equals(defSensitiveIndex.get(i+3))
                                    ) {
                                        if (newSensitiveIndex.get(j+4).equals(defSensitiveIndex.get(i+4))) {
                                            hasExisted = true
                                            break
                                        }
                                        else {
                                            def table1 = newSensitiveIndex.get(j+4).substring(newSensitiveIndex.get(j+4).indexOf(" ")+1)
                                            def table2 = defSensitiveIndex.get(i+4).substring(defSensitiveIndex.get(i+4).indexOf(" ")+1)
                                            if (table1.equals(table2)) {
                                                hasExisted = true
                                                break
                                            }
                                        }
                                    }
                                }
                                needOffer = needOffer || need
                                if (!hasExisted) {
                                    if (assignName == value || (!defSensitiveIndex.get(i).equals(arrayIndex) && !defSensitiveIndex.get(i+2).equals(arrayIndex))) {
                                        newSensitiveIndex.add(defSensitiveIndex.get(i))
                                        newSensitiveIndex.add(defSensitiveIndex.get(i+1))
                                        newSensitiveIndex.add(defSensitiveIndex.get(i+2))
                                        newSensitiveIndex.add(defSensitiveIndex.get(i+3))
                                        newSensitiveIndex.add(defSensitiveIndex.get(i+4))
                                        if (hasFetched) {
                                            def newIndexSensitiveIndex = new ArrayList<String>()
                                            if (valTableColumnMap.containsKey(location + " " + arrayName + "[" + defSensitiveIndex.get(i) + "]")) {
                                                def newIndexEntry = valTableColumnMap.get(location + " " + arrayName + "[" + defSensitiveIndex.get(i) + "]")
                                                newIndexSensitiveIndex.addAll(newIndexEntry.getValue())
                                            }
                                            if (newIndexSensitiveIndex.contains(defSensitiveIndex.get(i + 4))) {
                                                continue
                                            }
                                            newIndexSensitiveIndex.add(defSensitiveIndex.get(i))
                                            newIndexSensitiveIndex.add(defSensitiveIndex.get(i + 1))
                                            newIndexSensitiveIndex.add(defSensitiveIndex.get(i + 2))
                                            newIndexSensitiveIndex.add(defSensitiveIndex.get(i + 3))
                                            newIndexSensitiveIndex.add(defSensitiveIndex.get(i + 4))
                                            valTableColumnMap.put(location + " " + arrayName + "[" + defSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, newIndexSensitiveIndex))
                                            valTableColumnMap.put(location + " " + arrayName + "[" + defSensitiveIndex.get(i + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, newIndexSensitiveIndex))
                                            valTableColumnMap.put(location + " " + arrayName + "->" + defSensitiveIndex.get(i + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, newIndexSensitiveIndex))
                                        }
                                    }
                                }
                            }
                            if (newSensitiveIndex.size() > newSensitiveIndexSize) {
                                valTableColumnMap.put(location + " " + arrayName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, newSensitiveIndex))
                                if (needOffer) {
                                    valTableColumnQueue.offer(location + " " + arrayName)
                                }
                            }
                        }
                        else {
                            valTableRet.add("defArrayName not found")
                            valTableRet.add(defArrayName)
                        }
                    }
                }
                else if (v.type == "AST_RETURN") {
                    transValTableColumnForReturn(v, nodeLocation, valTableColumnMap, valTableColumnQueue, sessionTables, statement, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, valTableRet)
                }
                else if (v.type == "AST_CALL" || v.type == "AST_METHOD_CALL" || v.type == "AST_STATIC_CALL") {
                    if (isDAL) {
                        def funcName = getFuncName(v)
                        if (dal_sql_query_funcs.contains(funcName)) {
                            continue
                        }
                    }
                    transValTableColumnForCall(v, nodeLocation, valTableColumnMap, valTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, isWP, skipWPFunc, valTableRet)
                }
                else if (v.type == "AST_VAR") {
                    statement = getStatement(v)
                    if (statement.type == "AST_FOREACH") {
                        def assignKeyName = getAllValName(statement.ithChildren(2).next())
                        assignKeyName = assignKeyName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                        def assignValueName = getAllValName(statement.ithChildren(1).next())
                        assignValueName = assignValueName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                        def value = getAllValName(statement.ithChildren(0).next())
                        value = value.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                        def defVal = nodeLocation+" "+value
                        if (valTableColumnMap.containsKey(defVal)) {
                            def hasFetched = false
                            if (valTableColumnMap.containsKey(defVal+"[0]")) {
                                hasFetched = true
                            }
                            def defEntry = valTableColumnMap.get(defVal)
                            def defSensitiveIndex = defEntry.getValue()
                            if (assignKeyName != "") {
                                def assignKeyNameSensitiveIndex = new ArrayList<String>()
                                if (valTableColumnMap.containsKey(location+" "+assignKeyName)) {
                                    def assignKeyNameEntry = valTableColumnMap.get(location+" "+assignKeyName)
                                    assignKeyNameSensitiveIndex.addAll(assignKeyNameEntry.getValue())
                                }
                                def assignKeyNameSensitiveIndexSize = assignKeyNameSensitiveIndex.size()
                                def needOffer = false
                                for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                                    def hasExisted = false
                                    def need = true
                                    for (int j = 0; j < assignKeyNameSensitiveIndexSize; j += 5) {
                                        if (assignKeyNameSensitiveIndex.get(j).equals(defSensitiveIndex.get(i)) &&
                                                assignKeyNameSensitiveIndex.get(j+1).equals(defSensitiveIndex.get(i+1)) &&
                                                assignKeyNameSensitiveIndex.get(j+2).equals(defSensitiveIndex.get(i+2)) &&
                                                assignKeyNameSensitiveIndex.get(j+3).equals(defSensitiveIndex.get(i+3))
                                        ) {
                                            if (assignKeyNameSensitiveIndex.get(j+4).equals(defSensitiveIndex.get(i+4))) {
                                                hasExisted = true
                                                break
                                            }
                                            else {
                                                def table1 = assignKeyNameSensitiveIndex.get(j+4).substring(assignKeyNameSensitiveIndex.get(j+4).indexOf(" ")+1)
                                                def table2 = defSensitiveIndex.get(i+4).substring(defSensitiveIndex.get(i+4).indexOf(" ")+1)
                                                if (table1.equals(table2)) {
                                                    //need = false
                                                    hasExisted = true
                                                    break
                                                }
                                            }
                                        }
                                    }
                                    needOffer = needOffer || need
                                    if (!hasExisted) {
                                        assignKeyNameSensitiveIndex.add(defSensitiveIndex.get(i))
                                        assignKeyNameSensitiveIndex.add(defSensitiveIndex.get(i+1))
                                        assignKeyNameSensitiveIndex.add(defSensitiveIndex.get(i+2))
                                        assignKeyNameSensitiveIndex.add(defSensitiveIndex.get(i+3))
                                        assignKeyNameSensitiveIndex.add(defSensitiveIndex.get(i+4))
                                    }
                                }
                                if (assignKeyNameSensitiveIndex.size() > assignKeyNameSensitiveIndexSize) {
                                    valTableColumnMap.put(location + " " + assignKeyName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(2).next(), assignKeyNameSensitiveIndex))
                                    if (needOffer) {
                                        valTableColumnQueue.offer(location + " " + assignKeyName)
                                    }
                                    if (assignKeyName.startsWith("\$_SESSION[")) {
                                        setValTableColumnForSession(assignName, statement.ithChildren(2).next(), valTableColumnMap, sessionTables, assignKeyNameSensitiveIndex, assignKeyNameSensitiveIndexSize)
                                    }
                                    if (hasFetched) {
                                        for (int i = assignKeyNameSensitiveIndexSize; i < assignKeyNameSensitiveIndex.size(); i += 5) {
                                            def assignKeyNameIndexSensitiveIndex = new ArrayList<String>()
                                            if (valTableColumnMap.containsKey(location + " " + assignKeyName + "[" + assignKeyNameSensitiveIndex.get(i) + "]")) {
                                                def assignKeyNameIndexEntry = valTableColumnMap.get(location + " " + assignKeyName + "[" + assignKeyNameSensitiveIndex.get(i) + "]")
                                                assignKeyNameIndexSensitiveIndex.addAll(assignKeyNameIndexEntry.getValue())
                                            }
                                            if (assignKeyNameIndexSensitiveIndex.contains(assignKeyNameSensitiveIndex.get(i + 4))) {
                                                continue
                                            }
                                            assignKeyNameIndexSensitiveIndex.add(assignKeyNameSensitiveIndex.get(i))
                                            assignKeyNameIndexSensitiveIndex.add(assignKeyNameSensitiveIndex.get(i + 1))
                                            assignKeyNameIndexSensitiveIndex.add(assignKeyNameSensitiveIndex.get(i + 2))
                                            assignKeyNameIndexSensitiveIndex.add(assignKeyNameSensitiveIndex.get(i + 3))
                                            assignKeyNameIndexSensitiveIndex.add(assignKeyNameSensitiveIndex.get(i + 4))
                                            valTableColumnMap.put(location + " " + assignKeyName + "[" + assignKeyNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(2).next(), assignKeyNameIndexSensitiveIndex))
                                            valTableColumnMap.put(location + " " + assignKeyName + "[" + assignKeyNameSensitiveIndex.get(i + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(2).next(), assignKeyNameIndexSensitiveIndex))
                                            valTableColumnMap.put(location + " " + assignKeyName + "->" + assignKeyNameSensitiveIndex.get(i + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(2).next(), assignKeyNameIndexSensitiveIndex))
                                        }
                                    }
                                }
                            }
                            else {
                                valTableRet.add("foreach assignKeyName is empty")
                            }
                            if (assignValueName != "") {
                                def assignValueNameSensitiveIndex = new ArrayList<String>()
                                if (valTableColumnMap.containsKey(location+" "+assignValueName)) {
                                    def assignValueNameEntry = valTableColumnMap.get(location+" "+assignValueName)
                                    assignValueNameSensitiveIndex.addAll(assignValueNameEntry.getValue())
                                }
                                def assignValueNameSensitiveIndexSize = assignValueNameSensitiveIndex.size()
                                def needOffer = false
                                for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                                    def hasExisted = false
                                    def need = true
                                    for (int j = 0; j < assignValueNameSensitiveIndexSize; j += 5) {
                                        if (assignValueNameSensitiveIndex.get(j).equals(defSensitiveIndex.get(i)) &&
                                                assignValueNameSensitiveIndex.get(j+1).equals(defSensitiveIndex.get(i+1)) &&
                                                assignValueNameSensitiveIndex.get(j+2).equals(defSensitiveIndex.get(i+2)) &&
                                                assignValueNameSensitiveIndex.get(j+3).equals(defSensitiveIndex.get(i+3))
                                        ) {
                                            if (assignValueNameSensitiveIndex.get(j+4).equals(defSensitiveIndex.get(i+4))) {
                                                hasExisted = true
                                                break
                                            }
                                            else {
                                                def table1 = assignValueNameSensitiveIndex.get(j+4).substring(assignValueNameSensitiveIndex.get(j+4).indexOf(" ")+1)
                                                def table2 = defSensitiveIndex.get(i+4).substring(defSensitiveIndex.get(i+4).indexOf(" ")+1)
                                                if (table1.equals(table2)) {
                                                    hasExisted = true
                                                    break
                                                }
                                            }
                                        }
                                    }
                                    needOffer = needOffer || need
                                    if (!hasExisted) {
                                        assignValueNameSensitiveIndex.add(defSensitiveIndex.get(i))
                                        assignValueNameSensitiveIndex.add(defSensitiveIndex.get(i+1))
                                        assignValueNameSensitiveIndex.add(defSensitiveIndex.get(i+2))
                                        assignValueNameSensitiveIndex.add(defSensitiveIndex.get(i+3))
                                        assignValueNameSensitiveIndex.add(defSensitiveIndex.get(i+4))
                                    }
                                }
                                if (assignValueNameSensitiveIndex.size() > assignValueNameSensitiveIndexSize) {
                                    valTableColumnMap.put(location + " " + assignValueName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(1).next(), assignValueNameSensitiveIndex))
                                    if (needOffer) {
                                        valTableColumnQueue.offer(location + " " + assignValueName)
                                    }
                                    if (assignValueName.startsWith("\$_SESSION[")) {
                                        setValTableColumnForSession(assignName, statement.ithChildren(1).next(), valTableColumnMap, sessionTables, assignValueNameSensitiveIndex, assignValueNameSensitiveIndexSize)
                                    }
                                    if (hasFetched) {
                                        for (int i = assignValueNameSensitiveIndexSize; i < assignValueNameSensitiveIndex.size(); i += 5) {
                                            def assignValueNameIndexSensitiveIndex = new ArrayList<String>()
                                            if (valTableColumnMap.containsKey(location + " " + assignValueName + "[" + assignValueNameSensitiveIndex.get(i) + "]")) {
                                                def assignValueNameIndexEntry = valTableColumnMap.get(location + " " + assignValueName + "[" + assignValueNameSensitiveIndex.get(i) + "]")
                                                assignValueNameIndexSensitiveIndex.addAll(assignValueNameIndexEntry.getValue())
                                            }
                                            if (assignValueNameIndexSensitiveIndex.contains(assignValueNameSensitiveIndex.get(i + 4))) {
                                                continue
                                            }
                                            assignValueNameIndexSensitiveIndex.add(assignValueNameSensitiveIndex.get(i))
                                            assignValueNameIndexSensitiveIndex.add(assignValueNameSensitiveIndex.get(i + 1))
                                            assignValueNameIndexSensitiveIndex.add(assignValueNameSensitiveIndex.get(i + 2))
                                            assignValueNameIndexSensitiveIndex.add(assignValueNameSensitiveIndex.get(i + 3))
                                            assignValueNameIndexSensitiveIndex.add(assignValueNameSensitiveIndex.get(i + 4))
                                            valTableColumnMap.put(location + " " + assignValueName + "[" + assignValueNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(1).next(), assignValueNameIndexSensitiveIndex))
                                            valTableColumnMap.put(location + " " + assignValueName + "[" + assignValueNameSensitiveIndex.get(i + 2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(1).next(), assignValueNameIndexSensitiveIndex))
                                            valTableColumnMap.put(location + " " + assignValueName + "->" + assignValueNameSensitiveIndex.get(i + 2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(1).next(), assignValueNameIndexSensitiveIndex))
                                        }
                                    }
                                }
                            }
                            else {
                                valTableRet.add("foreach assignValueName is empty")
                                valTableRet.add(getLocation(statement.ithChildren(1).next()))
                            }
                            def valueSensitiveIndex = new ArrayList<String>()
                            if (valTableColumnMap.containsKey(location+" "+value)) {
                                def valueEntry = valTableColumnMap.get(location+" "+value)
                                valueSensitiveIndex.addAll(valueEntry.getValue())
                            }
                            def valueSensitiveIndexSize = valueSensitiveIndex.size()
                            for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                                def hasExisted = false
                                for (int j = 0; j < valueSensitiveIndexSize; j += 5) {
                                    if (valueSensitiveIndex.get(j).equals(defSensitiveIndex.get(i)) &&
                                            valueSensitiveIndex.get(j+1).equals(defSensitiveIndex.get(i+1)) &&
                                            valueSensitiveIndex.get(j+2).equals(defSensitiveIndex.get(i+2)) &&
                                            valueSensitiveIndex.get(j+3).equals(defSensitiveIndex.get(i+3))
                                    ) {
                                        if (valueSensitiveIndex.get(j+4).equals(defSensitiveIndex.get(i+4))) {
                                            hasExisted = true
                                            break
                                        }
                                    }
                                }
                                if (!hasExisted) {
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i))
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i+1))
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i+2))
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i+3))
                                    valueSensitiveIndex.add(defSensitiveIndex.get(i+4))
                                }
                            }
                            if (valueSensitiveIndex.size() > valueSensitiveIndexSize) {
                                valTableColumnMap.put(location+" "+value, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(0).next(), valueSensitiveIndex))
                                if (hasFetched) {
                                    for (int i = valueSensitiveIndexSize; i < valueSensitiveIndex.size(); i += 5) {
                                        def valueIndexSensitiveIndex = new ArrayList<String>()
                                        if (valTableColumnMap.containsKey(location+" "+value+"["+valueSensitiveIndex.get(i)+"]")) {
                                            def valueIndexEntry = valTableColumnMap.get(location+" "+value+"["+valueSensitiveIndex.get(i)+"]")
                                            valueIndexSensitiveIndex.addAll(valueIndexEntry.getValue())
                                        }
                                        if (valueIndexSensitiveIndex.contains(valueSensitiveIndex.get(i+4))) {
                                            continue
                                        }
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i))
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i+1))
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i+2))
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i+3))
                                        valueIndexSensitiveIndex.add(valueSensitiveIndex.get(i+4))
                                        valTableColumnMap.put(location+" "+value+"["+valueSensitiveIndex.get(i)+"]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(0).next(), valueIndexSensitiveIndex))
                                        valTableColumnMap.put(location+" "+value+"["+valueSensitiveIndex.get(i+2)+"]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(0).next(), valueIndexSensitiveIndex))
                                        valTableColumnMap.put(location+" "+value+"->"+valueSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement.ithChildren(0).next(), valueIndexSensitiveIndex))
                                    }
                                }
                            }
                        }
                        else {
                            valTableRet.add("foreach defVal not found")
                            valTableRet.add(defVal)
                        }
                    }
                    else {
                        valTableRet.add("var other type")
                        valTableRet.add(getLocation(statement))
                        if (selectCondColumns != null) {
                            def statementParent = statement.parents().next()
                            if (statementParent.type == "AST_IF_ELEM") {
                                if (isControlViewRelated(statement, valTableRet)) {
                                    valTableRet.add("*****getSelectCondColumns begin*****")
                                    getSelectCondColumns(statement, nodeLocation, selectCondColumns, valTableColumnMap, valTableRet)
                                    valTableRet.add("*****getSelectCondColumns end*****")
                                }
                            }
                        }
                    }
                }
                else {
                    def start = new HashSet<Boolean>()
                    start.add(true)
                    valTableRet.add("not assign")
                    valTableRet.add(statementToString(statement, start, new HashMap<>(), new HashSet<>(), sanitizations))
                    valTableRet.add(getLocation(statement))
                    if (selectCondColumns != null) {
                        if (isControlViewRelated(statement, valTableRet)) {
                            valTableRet.add("*****getSelectCondColumns begin*****")
                            getSelectCondColumns(statement, nodeLocation, selectCondColumns, valTableColumnMap, valTableRet)
                            valTableRet.add("*****getSelectCondColumns end*****")
                        }
                    }
                }
                if (condTableColumnsMap != null && selectTableColumnsView != null) {
                    if (isViewRelated(statement, valTableRet)) {
                        valTableRet.add("*****condTableColumnsMap begin*****")
                        for (int i = 0; i < sensitive_index.size(); i += 5) {
                            if (sensitive_index.get(i) != "-1") {
                                def index4 = sensitive_index.get(i + 4)
                                def locationOfIndex4 = index4.substring(0, index4.indexOf(" "))
                                def sensitiveKey = sensitive_index.get(i + 1) + "." + sensitive_index.get(i + 2)
                                if (condTableColumnsMap.containsKey(locationOfIndex4)) {
                                    condTableColumns.addAll(condTableColumnsMap.get(locationOfIndex4))
                                    valTableRet.add(condTableColumnsMap.get(locationOfIndex4))
                                }
                                if (QueryProcessing.containColumn(sensitive_index.get(i + 1), sensitive_index.get(i + 2))) {
                                    def selectLocations = new HashSet<String>()
                                    if (selectTableColumnsView.containsKey(sensitiveKey)) {
                                        selectLocations.addAll(selectTableColumnsView.get(sensitiveKey))
                                    }
                                    selectLocations.add(locationOfIndex4)
                                    selectTableColumnsView.put(sensitiveKey, selectLocations)
                                }
                            }
                        }
                        valTableRet.add("*****condTableColumnsMap end*****")
                    }
                }
            }
        }
    }
    if (selectCondColumns != null) {
        valTableRet.add("*************************************valTableColumnMap***************************")
        valTableRet.add(valTableColumnMap)
    }
}

def transValDefTableColumnForCall(node, arrayIndex, columns, valDefTableColumnMap, valDefTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, callerDTables, isWP, skipWPFunc, ret) {
    ret.add("trans valdeftable call")
    ret.add(getLocation(node))
    def start = new HashSet<Boolean>()
    start.add(true)
    def hasFunc = false
    def funcName = getFuncName(node)
    if (isWP && skipWPFunc.contains(funcName)) {
        return
    }
    def statement = node.statements().next()
    statement = getStatement(statement)
    def nodeLocation = statement.toFileAbs().next().name + ":" + statement.lineno
    if (funcName == "array_diff") {
        def value = getAllValName(node.ithArguments(0).next())
        if (arrayIndex != "") {
            value = value + "[" + arrayIndex + "]"
        }
        if (value.startsWith("\$")) {
            def newDefColumns = new HashSet<String>()
            if (valDefTableColumnMap.containsKey(nodeLocation+" "+value)) {
                def newDefEntry = valDefTableColumnMap.get(nodeLocation+" "+value)
                newDefColumns.addAll(newDefEntry.getValue())
            }
            def changed = newDefColumns.addAll(columns)
            if (changed) {
                valDefTableColumnMap.put(nodeLocation + " " + value, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(statement, newDefColumns))
                valDefTableColumnQueue.offer(nodeLocation + " " + value)
            }
        }
        else {
            ret.add("array_diff value is not variable")
            ret.add(value)
        }
        return
    }
    for (func in node.out("CALLS")) {
        funcExit = func.out("EXIT").next()
        for (v in funcExit.in("FLOWS_TO")) {
            if (v.type == "AST_RETURN") {
                def retVal = getAllValName(v)
                retVal = retVal.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                ret.add(retVal)
                if (arrayIndex != "") {
                    retVal = retVal + "[" + arrayIndex + "]"
                }
                ret.add(retVal)
                location = v.toFileAbs().next().name + ":" + v.lineno
                if (retVal.startsWith("\$")) {
                    def newDefColumns = new HashSet<String>()
                    if (valDefTableColumnMap.containsKey(location+" "+retVal)) {
                        def newDefEntry = valDefTableColumnMap.get(location+" "+retVal)
                        newDefColumns.addAll(newDefEntry.getValue())
                    }
                    def changed = newDefColumns.addAll(columns)
                    if (changed) {
                        valDefTableColumnMap.put(location + " " + retVal, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(v, newDefColumns))
                        valDefTableColumnQueue.offer(location + " " + retVal)
                    }
                }
                else if (v.ithChildren(0).next().type == "AST_CALL" || v.ithChildren(0).next().type == "AST_METHOD_CALL" || v.ithChildren(0).type == "AST_STATIC_CALL") {
                    transValDefTableColumnForCall(v.ithChildren(0).next(), arrayIndex, columns, valDefTableColumnMap, valDefTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, callerDTables, isWP, skipWPFunc, ret)
                }
                else {
                    ret.add("retVal is not variable")
                    ret.add(getLocation(v.ithChildren(0).next()))
                    ret.add(retVal)
                }
            }
            else {
                ret.add("not return in funcExit")
                ret.add(getLocation(v))
                ret.add(statementToString(v, start, new HashMap<>(), new HashSet<>(), sanitizations))
            }
        }
    }
    if (!hasFunc) {
        ret.add("func def not found in valdeftable")
        ret.add(nodeLocation+" "+funcName)
    }
}

def transValDefTableColumnForParam(node, valOfKey, columns, valDefTableColumnMap, valDefTableColumnQueue, valTableColumnMap, valTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, callerDTables, isWP, skipWPFunc, ret) {
    ret.add("trans valdeftable param")
    ret.add(getLocation(node))
    def paramName = getAllValName(node)
    def isArrayAdd = paramName.indexOf("[]") != -1
    def arrayIndex = ""
    paramName = paramName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
    def location = node.toFileAbs().next().name + ":" + node.lineno
    if (paramName != valOfKey) {
        ret.add("paramName != valOfKey")
        ret.add(paramName)
        ret.add(valOfKey)
        if (valOfKey.startsWith(paramName) && valTableColumnMap.containsKey(location+" "+valOfKey)) {
            def defTableEntry = valTableColumnMap.get(location+" "+valOfKey)
            def defSensitiveIndex = defTableEntry.getValue()
            for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                if (defSensitiveIndex.get(i) == "-1" && callerDTables.contains(defSensitiveIndex.get(i+1))) {
                    continue
                }
                def sensitiveKey = defSensitiveIndex.get(i+1) + "." + defSensitiveIndex.get(i+2)
                for (column in columns) {
                    setTableRelations(sensitiveKey, column)
                    ret.add(location+" "+valOfKey)
                    ret.add("setTableRelations " + sensitiveKey + " " + column)
                    System.out.println(location+" "+valOfKey)
                    System.out.println("setTableRelations " + sensitiveKey + " " + column)
                }
            }
            ret.add("defSensitiveIndex")
            ret.add(defSensitiveIndex)
        }
        def paramNameArray = paramName
        if (paramName.indexOf("[") != -1) {
            paramNameArray = paramName.substring(0, paramName.indexOf("["))
        }
        def valOfKeyArray = valOfKey
        if (valOfKey.indexOf("[") != -1) {
            valOfKeyArray = valOfKey.substring(0, valOfKey.indexOf("["))
        }
        if (paramNameArray == valOfKeyArray) {
            ret.add("paramNameArray == valOfKeyArray")
            ret.add(paramNameArray)
            ret.add(valOfKeyArray)
            if (paramName != paramNameArray && !isArrayAdd) {
                def defVal = location + " " + valOfKey
                def defColumns = new HashSet<String>()
                if (valDefTableColumnMap.containsKey(defVal)) {
                    def defEntry = valDefTableColumnMap.get(defVal)
                    defColumns.addAll(defEntry.getValue())
                }
                def changed = defColumns.addAll(columns)
                if (changed) {
                    valDefTableColumnMap.put(defVal, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(node, defColumns))
                    valDefTableColumnQueue.offer(defVal)
                }
                return
            }
            else {
                paramName = valOfKey
                if (valOfKey.indexOf("[") != -1) {
                    arrayIndex = valOfKey.substring(valOfKey.indexOf("[")+1, valOfKey.indexOf("]"))
                }
                else {
                    ret.add("valOfKey is not array in param")
                }
            }
        }
        else {
            return
        }
    }
    def defParamName = location+" "+paramName

    if (valTableColumnMap.containsKey(defParamName)) {
        def defTableEntry = valTableColumnMap.get(defParamName)
        def defSensitiveIndex = defTableEntry.getValue()
        for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
            if (defSensitiveIndex.get(i) == "-1" && callerDTables.contains(defSensitiveIndex.get(i+1))) {
                continue
            }
            def sensitiveKey = defSensitiveIndex.get(i+1) + "." + defSensitiveIndex.get(i+2)
            for (column in columns) {
                setTableRelations(sensitiveKey, column)
                ret.add(location+" "+paramName)
                ret.add("setTableRelations " + sensitiveKey + " " + column)
                System.out.println(location+" "+paramName)
                System.out.println("setTableRelations " + sensitiveKey + " " + column)
            }
        }
        ret.add("defSensitiveIndex")
        ret.add(defSensitiveIndex)
    }

    ret.add(defParamName)
    def start = new HashSet<Boolean>()
    start.add(true)
    if (node.parents().next().parents().next().type == "AST_CLOSURE") {
        ret.add("trans param in closure")
        return
    }
    def className = node.classname
    def func = node.functions().next()
    def funcName = func.name
    def ithChild = node.childnum
    def callers = []
    for (v in func.in("CALLS")) {
        callers.add(v)
    }
    def defColumns = new HashSet<String>()
    if (valDefTableColumnMap.containsKey(defParamName)) {
        def defEntry = valDefTableColumnMap.get(defParamName)
        defColumns.addAll(defEntry.getValue())
    }
    def changed = defColumns.addAll(columns)
    if (changed) {
        valDefTableColumnMap.put(defParamName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(node, defColumns))
        def sensitiveIndex = new ArrayList<String>()
        if (valTableColumnMap.containsKey(defParamName)) {
            def defTableEntry = valTableColumnMap.get(defParamName)
            sensitiveIndex.addAll(defTableEntry.getValue())
        }
        def sensitiveIndexSize = sensitiveIndex.size()
        for (defColumn in defColumns) {
            defTable = defColumn.substring(0, defColumn.indexOf("."))
            defColumn = defColumn.substring(defColumn.indexOf(".")+1)
            hasExisted = false
            for (int i = 0; i < sensitiveIndexSize; i += 5) {
                if (sensitiveIndex.get(i).equals("-1") &&
                        sensitiveIndex.get(i + 1).equals(defTable) &&
                        sensitiveIndex.get(i + 2).equals(defColumn) &&
                        sensitiveIndex.get(i + 3).equals("true") &&
                        sensitiveIndex.get(i + 4).equals("ref")
                ) {
                    hasExisted = true
                    break
                }
            }
            if (!hasExisted) {
                sensitiveIndex.add("-1")
                sensitiveIndex.add(defTable)
                sensitiveIndex.add(defColumn)
                sensitiveIndex.add("true")
                sensitiveIndex.add("ref")
            }
        }
        if (sensitiveIndex.size() > sensitiveIndexSize) {
            valTableColumnMap.put(defParamName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, sensitiveIndex))
            valTableColumnQueue.offer(defParamName)
        }
        for (caller in callers) {
            if (isCallExpression(caller)) {
                funcName = getFuncName(caller)
                if (isWP && skipWPFunc.contains(funcName)) {
                    continue
                }
                if (isWithinFunction(caller)) {
                    def callerFunc = caller.functions().next()
                    if (callerFunc != null) {
                        def callerFuncName = callerFunc.name
                        if (isWP && skipWPFunc.contains(callerFuncName)) {
                            continue
                        }
                    }
                }
                def callerStatement = getStatement(caller)
                def isCallDTable = false
                def dynamicTable = ""
                if (callerDTableMaps.containsKey(callerStatement)) {
                    isCallDTable = true
                    dynamicTable = callerDTableMaps.get(callerStatement)
                }
                def callerLocation = callerStatement.toFileAbs().next().name + ":" + callerStatement.lineno
                def argsNum = caller.numArguments().next()
                if (ithChild >= argsNum) {
                    ret.add("ithChild >= argsNum")
                    ret.add(ithChild)
                    ret.add(argsNum)
                    continue
                }
                def arg = statementToString(caller.ithArguments(ithChild).next(), start, new HashMap<>(), new HashSet<>(), sanitizations)
                if (arg.startsWith("\$")) {
                    if (arrayIndex != "") {
                        arg = arg + "[" + arrayIndex + "]"
                    }
                    def newDefColumns = new HashSet<String>()
                    if (valDefTableColumnMap.containsKey(callerLocation+" "+arg)) {
                        def newDefEntry = valDefTableColumnMap.get(callerLocation+" "+arg)
                        newDefColumns.addAll(newDefEntry.getValue())
                    }
                    def newChanged = false
                    if (isCallDTable) {
                        def newDefColumnsSize = newDefColumns.size()
                        for (column in columns) {
                            def columnTable = column.substring(0, column.indexOf("."))
                            if (dynamicTable != columnTable && callerDTables.contains(columnTable)) {
                                continue
                            }
                            newDefColumns.add(column)
                        }
                        if (newDefColumns.size() > newDefColumnsSize) {
                            newChanged = true
                        }
                    }
                    else {
                        newChanged = newDefColumns.addAll(columns)
                    }
                    if (newChanged) {
                        valDefTableColumnMap.put(callerLocation + " " + arg, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(callerStatement, newDefColumns))
                        valDefTableColumnQueue.offer(callerLocation + " " + arg)
                    }
                }
                else {
                    ret.add("arg is not variable")
                    ret.add(arg)
                }
            }
        }
    }
    else {
    }
}

def transValDefTableColumn(valDefTableColumnQueue, valDefTableColumnMap, sessionTables, sanitizations, nodes, sql_fetch_funcs, equal_funcs, fetchIndex, queryIndex, sql_prepare_funcs, isWP, skipWPFunc, isDAL, dal_sql_query_funcs, valTableColumnMap, callerDTableMaps, dynamicTableNodeMaps, valDefTableRet) {
    def valTableColumnQueue = new LinkedList<String>()
    while (valDefTableColumnQueue.size() > 0) {
        def key = valDefTableColumnQueue.poll()
        System.out.println(key)
        if (valDefTableColumnMap.containsKey(key)) {
            def entry = valDefTableColumnMap.get(key)
            def valOfKey = key.substring(key.indexOf(" ")+1)
            def node = entry.getKey()
            def nodeLocation = node.toFileAbs().next().name + ":" + node.lineno
            def columns = entry.getValue()
            valDefTableRet.add("**************************************************")
            valDefTableRet.add(key)
            def hasReaches = false
            def callerDTables = new HashSet<String>()
            if (dynamicTableNodeMaps.containsKey(node)) {
                callerDTables = dynamicTableNodeMaps.get(node)
            }
            for (Vertex v in node.in("REACHES")) {
                hasReaches = true
                def statement = v
                def location = v.toFileAbs().next().name + ":" + v.lineno
                valDefTableRet.add("######"+location)
                if (nodes.contains(v)) {
                    valDefTableRet.add("already")
                    if (valTableColumnMap.containsKey(location+" "+valOfKey)) {
                        def defTableEntry = valTableColumnMap.get(location+" "+valOfKey)
                        def defSensitiveIndex = defTableEntry.getValue()
                        for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                            if (defSensitiveIndex.get(i) == "-1" && callerDTables.contains(defSensitiveIndex.get(i+1))) {
                                continue
                            }
                            def sensitiveKey = defSensitiveIndex.get(i+1) + "." + defSensitiveIndex.get(i+2)
                            for (column in columns) {
                                setTableRelations(sensitiveKey, column)
                                valDefTableRet.add(location+" "+valOfKey)
                                valDefTableRet.add("setTableRelations " + sensitiveKey + " " + column)
                                System.out.println(location+" "+valOfKey)
                                System.out.println("setTableRelations " + sensitiveKey + " " + column)
                            }
                        }
                        valDefTableRet.add("defSensitiveIndex")
                        valDefTableRet.add(defSensitiveIndex)
                    }
                    continue
                }
                v = getInnerNode(v)
                if (v.type == "AST_ASSIGN") {
                    def assignName = getAllValName(v.ithChildren(0).next())
                    def isArrayAdd = assignName.indexOf("[]") != -1
                    def arrayIndex = ""
                    assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                    def valueNode = v.ithChildren(1).next()

                    if (assignName != valOfKey) {
                        valDefTableRet.add("assignName != valOfKey")
                        valDefTableRet.add(assignName)
                        valDefTableRet.add(valOfKey)
                        if (valOfKey.startsWith(assignName) && valTableColumnMap.containsKey(location+" "+valOfKey)) {
                            def defTableEntry = valTableColumnMap.get(location+" "+valOfKey)
                            def defSensitiveIndex = defTableEntry.getValue()
                            for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                                if (defSensitiveIndex.get(i) == "-1" && callerDTables.contains(defSensitiveIndex.get(i+1))) {
                                    continue
                                }
                                def sensitiveKey = defSensitiveIndex.get(i+1) + "." + defSensitiveIndex.get(i+2)
                                for (column in columns) {
                                    setTableRelations(sensitiveKey, column)
                                    valDefTableRet.add(location+" "+valOfKey)
                                    valDefTableRet.add("setTableRelations " + sensitiveKey + " " + column)
                                    System.out.println(location+" "+valOfKey)
                                    System.out.println("setTableRelations " + sensitiveKey + " " + column)
                                }
                            }
                            valDefTableRet.add("defSensitiveIndex")
                            valDefTableRet.add(defSensitiveIndex)
                        }
                        def assignNameArray = assignName
                        if (assignName.indexOf("[") != -1) {
                            assignNameArray = assignName.substring(0, assignName.indexOf("["))
                        }
                        def valOfKeyArray = valOfKey
                        if (valOfKey.indexOf("[") != -1) {
                            valOfKeyArray = valOfKey.substring(0, valOfKey.indexOf("["))
                        }
                        if (assignNameArray == valOfKeyArray) {
                            valDefTableRet.add("assignNameArray = valOfKeyArray")
                            valDefTableRet.add(assignNameArray)
                            valDefTableRet.add(valOfKeyArray)
                            if (assignName != assignNameArray && !isArrayAdd) {
                                    defVal = location + " " + valOfKey
                                    def defColumns = new HashSet<String>()
                                    if (valDefTableColumnMap.containsKey(defVal)) {
                                        def defEntry = valDefTableColumnMap.get(defVal)
                                        defColumns.addAll(defEntry.getValue())
                                    }
                                    def changed = defColumns.addAll(columns)
                                    if (changed) {
                                        valDefTableColumnMap.put(defVal, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(statement, defColumns))
                                        valDefTableColumnQueue.offer(defVal)
                                    }
                                    continue
                                }
                            else {
                                assignName = valOfKey
                                if (valOfKey.indexOf("[") != -1) {
                                    arrayIndex = valOfKey.substring(valOfKey.indexOf("[")+1, valOfKey.indexOf("]"))
                                }
                                else {
                                    valDefTableRet.add("valOfKey is not array")
                                }
                            }
                        }
                        else {
                            continue
                        }
                    }

                    def funcs = new HashSet<String>()
                    def start = new HashSet<Boolean>()
                    start.add(true)
                    def value = statementToString(valueNode, start, new HashMap<>(), funcs, sanitizations)
                    value = value.trim()

                    if (valTableColumnMap.containsKey(location+" "+valOfKey)) {
                        def defTableEntry = valTableColumnMap.get(location+" "+valOfKey)
                        def defSensitiveIndex = defTableEntry.getValue()
                        for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                            if (defSensitiveIndex.get(i) == "-1" && callerDTables.contains(defSensitiveIndex.get(i+1))) {
                                continue
                            }
                            def sensitiveKey = defSensitiveIndex.get(i+1) + "." + defSensitiveIndex.get(i+2)
                            for (column in columns) {
                                setTableRelations(sensitiveKey, column)
                                valDefTableRet.add(location+" "+valOfKey)
                                valDefTableRet.add("setTableRelations " + sensitiveKey + " " + column)
                                System.out.println(location+" "+valOfKey)
                                System.out.println("setTableRelations " + sensitiveKey + " " + column)
                            }
                        }
                        valDefTableRet.add("defSensitiveIndex")
                        valDefTableRet.add(defSensitiveIndex)
                    }

                    def inSqlFetch = false
                    def inEqual = false
                    def inFetchResult = false
                    for (String func in funcs) {
                        if (sql_fetch_funcs.contains(func)) {
                            inSqlFetch = true
                        }
                        else if (equal_funcs.contains(func)) {
                            inEqual = true
                        }
                        else if (fetchIndex.containsKey(func)) {
                            inFetchResult = true
                        }
                    }
                    if (inSqlFetch || inFetchResult) {
                        continue
                    }
                    if (inEqual) {
                        value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
                    }
                    if (value.startsWith("\$")) {
                        if (arrayIndex != "") {
                            value = value + "[" + arrayIndex + "]"
                        }
                        def defVal = location + " " + value
                        def defColumns = new HashSet<String>()
                        if (valDefTableColumnMap.containsKey(defVal)) {
                            def defEntry = valDefTableColumnMap.get(defVal)
                            defColumns.addAll(defEntry.getValue())
                        }
                        def changed = defColumns.addAll(columns)
                        if (changed) {
                            valDefTableColumnMap.put(defVal, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(statement, defColumns))
                            valDefTableColumnMap.put(location+" "+assignName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(statement, defColumns))
                            valDefTableColumnQueue.offer(defVal)
                            def sensitiveIndex = new ArrayList<String>()
                            if (valTableColumnMap.containsKey(location+" "+assignName)) {
                                def defTableEntry = valTableColumnMap.get(location + " " + assignName)
                                sensitiveIndex.addAll(defTableEntry.getValue())
                            }
                            def sensitiveIndexSize = sensitiveIndex.size()
                            for (defColumn in defColumns) {
                                defTable = defColumn.substring(0, defColumn.indexOf("."))
                                defColumn = defColumn.substring(defColumn.indexOf(".")+1)
                                hasExisted = false
                                for (int i = 0; i < sensitiveIndexSize; i += 5) {
                                    if (sensitiveIndex.get(i).equals("-1") &&
                                            sensitiveIndex.get(i + 1).equals(defTable) &&
                                            sensitiveIndex.get(i + 2).equals(defColumn) &&
                                            sensitiveIndex.get(i + 3).equals("true") &&
                                            sensitiveIndex.get(i + 4).equals("ref")
                                    ) {
                                        hasExisted = true
                                        break
                                    }
                                }
                                if (!hasExisted) {
                                    sensitiveIndex.add("-1")
                                    sensitiveIndex.add(defTable)
                                    sensitiveIndex.add(defColumn)
                                    sensitiveIndex.add("true")
                                    sensitiveIndex.add("ref")
                                }
                            }
                            if (sensitiveIndex.size() > sensitiveIndexSize) {
                                valTableColumnMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, sensitiveIndex))
                                valTableColumnQueue.offer(location + " " + assignName)
                            }
                        }
                        else {
                        }
                    }
                    else if (!inEqual) {
                        valDefTableRet.add("other type in deftable")
                        valDefTableRet.add(value)
                        if (valueNode.type == "AST_CALL" || valueNode.type == "AST_METHOD_CALL" || valueNode.type == "AST_STATIC_CALL") {
                            transValDefTableColumnForCall(valueNode, arrayIndex, columns, valDefTableColumnMap, valDefTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, callerDTables, isWP, skipWPFunc, valDefTableRet)
                        }
                        def defColumns = new HashSet<String>()
                        if (valDefTableColumnMap.containsKey(location+" "+assignName)) {
                            def defEntry = valDefTableColumnMap.get(location+" "+assignName)
                            defColumns.addAll(defEntry.getValue())
                        }
                        def changed = defColumns.addAll(columns)
                        if (changed) {
                            valDefTableColumnMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(statement, defColumns))
                            def sensitiveIndex = new ArrayList<String>()
                            if (valTableColumnMap.containsKey(location+" "+assignName)) {
                                def defTableEntry = valTableColumnMap.get(location + " " + assignName)
                                sensitiveIndex.addAll(defTableEntry.getValue())
                            }
                            def sensitiveIndexSize = sensitiveIndex.size()
                            for (defColumn in defColumns) {
                                def defTable = defColumn.substring(0, defColumn.indexOf("."))
                                defColumn = defColumn.substring(defColumn.indexOf(".")+1)
                                def hasExisted = false
                                for (int i = 0; i < sensitiveIndexSize; i += 5) {
                                    if (sensitiveIndex.get(i).equals("-1") &&
                                            sensitiveIndex.get(i + 1).equals(defTable) &&
                                            sensitiveIndex.get(i + 2).equals(defColumn) &&
                                            sensitiveIndex.get(i + 3).equals("true") &&
                                            sensitiveIndex.get(i + 4).equals("ref")
                                    ) {
                                        hasExisted = true
                                        break
                                    }
                                }
                                if (!hasExisted) {
                                    sensitiveIndex.add("-1")
                                    sensitiveIndex.add(defTable)
                                    sensitiveIndex.add(defColumn)
                                    sensitiveIndex.add("true")
                                    sensitiveIndex.add("ref")
                                }
                            }
                            if (sensitiveIndex.size() > sensitiveIndexSize) {
                                valTableColumnMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, sensitiveIndex))
                                valTableColumnQueue.offer(location + " " + assignName)
                            }
                        }
                    }
                }
                else if (v.type == "AST_GLOBAL") {
                    def globalVal = getAllValName(v)
                    if (globalVal != valOfKey) {
                        valDefTableRet.add("globalVal != valOfKey")
                        valDefTableRet.add(globalVal)
                        valDefTableRet.add(valOfKey)
                        def globalValArray = globalVal
                        if (globalVal.indexOf("[") != -1) {
                            globalValArray = globalVal.substring(0, globalVal.indexOf("["))
                        }
                        def valOfKeyArray = valOfKey
                        if (valOfKey.indexOf("[") != -1) {
                            valOfKeyArray = valOfKey.substring(0, valOfKey.indexOf("["))
                        }
                        if (globalValArray == valOfKeyArray) {
                            globalVal = valOfKey
                            valDefTableRet.add("globalValArray = valOfKeyArray")
                            valDefTableRet.add(globalValArray)
                            valDefTableRet.add(valOfKeyArray)
                        }
                        else {
                            continue
                        }
                    }
                    if (!valDefTableColumnMap.containsKey(nodeLocation+" "+globalVal)) {
                        valDefTableRet.add(nodeLocation+" "+globalVal)
                        valDefTableRet.add("global not in")
                        continue
                    }
                    valDefTableRet.add("valdeftable global")
                    valDefTableRet.add(globalVal)

                    def defGlobalVal = location+" "+globalVal
                    def defColumns = new HashSet<String>()
                    if (valDefTableColumnMap.containsKey(defGlobalVal)) {
                        def defEntry = valDefTableColumnMap.get(defGlobalVal)
                        defColumns.addAll(defEntry.getValue())
                    }
                    def changed = defColumns.addAll(columns)
                    if (changed) {
                        valDefTableColumnMap.put(defGlobalVal, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(statement, defColumns))
                        def sensitiveIndex = new ArrayList<String>()
                        if (valTableColumnMap.containsKey(location+" "+globalVal)) {
                            def defTableEntry = valTableColumnMap.get(location + " " + globalVal)
                            sensitiveIndex.addAll(defTableEntry.getValue())
                        }
                        def sensitiveIndexSize = sensitiveIndex.size()
                        for (defColumn in defColumns) {
                            def defTable = defColumn.substring(0, defColumn.indexOf("."))
                            defColumn = defColumn.substring(defColumn.indexOf(".")+1)
                            def hasExisted = false
                            for (int i = 0; i < sensitiveIndexSize; i += 5) {
                                if (sensitiveIndex.get(i).equals("-1") &&
                                        sensitiveIndex.get(i + 1).equals(defTable) &&
                                        sensitiveIndex.get(i + 2).equals(defColumn) &&
                                        sensitiveIndex.get(i + 3).equals("true") &&
                                        sensitiveIndex.get(i + 4).equals("ref")
                                ) {
                                    hasExisted = true
                                    break
                                }
                            }
                            if (!hasExisted) {
                                sensitiveIndex.add("-1")
                                sensitiveIndex.add(defTable)
                                sensitiveIndex.add(defColumn)
                                sensitiveIndex.add("true")
                                sensitiveIndex.add("ref")
                            }
                        }
                        if (sensitiveIndex.size() > sensitiveIndexSize) {
                            valTableColumnMap.put(location + " " + globalVal, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, sensitiveIndex))
                            valTableColumnQueue.offer(location + " " + globalVal)
                        }
                    }
                }
                else if (v.type == "AST_PARAM") {
                    transValDefTableColumnForParam(v, valOfKey, columns, valDefTableColumnMap, valDefTableColumnQueue, valTableColumnMap, valTableColumnQueue, sanitizations, callerDTableMaps, dynamicTableNodeMaps, callerDTables, isWP, skipWPFunc, valDefTableRet)
                }
                else {
                    valDefTableRet.add("other type in deftable")
                    valDefTableRet.add(getLocation(v))
                    def start = new HashSet<Boolean>()
                    start.add(true)
                    valDefTableRet.add(statementToString(v, start, new HashMap<>(), new HashSet<>(), sanitizations))
                }
            }
            if (!hasReaches && node.type != "AST_PARAM") {
                def newColumns = new HashSet<String>()
                if (isWithinFunction(node)) {
                    def func = node.functions().next()
                    def funcLocation = func.toFileAbs().next().name + "_" + func.name + ":" + func.lineno
                    if (valDefTableColumnMap.containsKey(funcLocation + " " + valOfKey)) {
                        def newEntry = valDefTableColumnMap.get(funcLocation + " " + valOfKey)
                        newColumns.addAll(newEntry.getValue())
                    }
                    newColumns.addAll(columns)
                    valDefTableColumnMap.put(funcLocation + " " + valOfKey, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(node, newColumns))
                    valDefTableRet.add("global value in function")
                    valDefTableRet.add(funcLocation + " " + valOfKey)
                }
                else {
                    if (valDefTableColumnMap.containsKey(node.toFileAbs().next().name+" "+valOfKey)) {
                        def newEntry = valDefTableColumnMap.get(node.toFileAbs().next().name+" "+valOfKey)
                        newColumns.addAll(newEntry.getValue())
                    }
                    newColumns.addAll(columns)
                    valDefTableColumnMap.put(node.toFileAbs().next().name + " " + valOfKey, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(node, newColumns))
                    valDefTableRet.add("global value")
                    valDefTableRet.add(node.toFileAbs().next().name + " " + valOfKey)
                }
                valDefTableRet.add(getLocation(node))
                valDefTableRet.add(columns)
            }
        }
    }

    valDefTableRet.add("*************************************valDefTableColumnMap***************************")
    valDefTableRet.add(valDefTableColumnMap)

    valDefTableRet.add("*************************************valTableColumnQueue***************************")
    transValTableColumn(valTableColumnQueue, valTableColumnMap, sessionTables, sanitizations, nodes, sql_fetch_funcs, equal_funcs, fetchIndex, queryIndex, sql_prepare_funcs, isWP, skipWPFunc, isDAL, dal_sql_query_funcs, null, null, null, null, callerDTableMaps, dynamicTableNodeMaps, valDefTableRet)
}

def getDefPathsForValForCall(node, nodes, arrayIndex, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, defVals, sanitizations, instack, isWP, skipWPFunc, ret) {
    def hasFunc = false
    def funcName = getFuncName(node)
    if (isWP && skipWPFunc.contains(funcName)) {
        return
    }
    def statement = node.statements().next()
    if (statement.type == "AST_IF") {
        statement = statement.ithChildren(0).next().ithChildren(0).next()
    }
    def nodeLocation = statement.toFileAbs().next().name + ":" + statement.lineno
    if (funcName == "str_replace") {
        def value = getAllValName(node.ithArguments(2).next())
        if (value.startsWith("\$")) {
            if (arrayIndex != "" && value.indexOf(arrayIndex) == -1) {
                value = value + arrayIndex
                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "array_equal")))
            }
            else {
                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "equal")))
            }
            getDefPathsForVal(statement, nodes, value, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
        }
        else {
            ret.add("not val in str_replace in defpath")
            ret.add(nodeLocation+" "+value)
        }
        return
    }
    if (funcName == "substr_replace") {
        def value = getAllValName(node.ithArguments(0).next())
        if (value.startsWith("\$")) {
            if (arrayIndex != "" && value.indexOf(arrayIndex) == -1) {
                value = value+arrayIndex
                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "array_equal")))
            }
            else {
                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "equal")))
            }
            getDefPathsForVal(statement, nodes, value, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
        }
        else {
            ret.add("not val in substr_replace in defpath")
            ret.add(nodeLocation+" "+value)
        }
        return
    }
    if (funcName == "array_diff") {
        def value = getAllValName(node.ithArguments(0).next())
        if (value.startsWith("\$")) {
            if (arrayIndex != "" && value.indexOf(arrayIndex) == -1) {
                value = value+arrayIndex
                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "array_equal")))
            }
            else {
                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "equal")))
            }
            getDefPathsForVal(statement, nodes, value, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
        }
        else {
            ret.add("not val in array_diff in defpath")
            ret.add(nodeLocation+" "+value)
        }
        return
    }
    for (func in node.out("CALLS")) {
        hasFunc = true
        def funcExit = func.out("EXIT").next()
        for (v in funcExit.in("FLOWS_TO")) {
            def location = v.toFileAbs().next().name + ":" + v.lineno
            if (v.type == "AST_RETURN") {
                def retVal = getAllValName(v)
                if (arrayIndex != "" && retVal.indexOf(arrayIndex) == -1) {
                    retVal = retVal+arrayIndex
                }
                if (retVal.startsWith("\$")) {
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location+" "+retVal, new AbstractMap.SimpleEntry<Vertex, String>(v, "return")))
                    getDefPathsForVal(v, nodes, retVal, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
                }
                else {
                    if (v.ithChildren(0).next().type == "AST_CALL" || v.ithChildren(0).next().type == "AST_METHOD_CALL" || v.ithChildren(0).next().type == "AST_STATIC_CALL") {
                        getDefPathsForValForCall(v.ithChildren(0).next(), nodes, arrayIndex, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, defVals, sanitizations, instack, isWP, skipWPFunc, ret)
                    }
                    else if (v.ithChildren(0).next().type == "string" || v.ithChildren(0).next().type == "integer" || v.ithChildren(0).next().type == "AST_CONST") {
                        if (retVal == "") {
                            retVal = "''"
                        }
                        defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location+" "+retVal, new AbstractMap.SimpleEntry<Vertex, String>(v, "return_const")))
                    }
                    else {
                        ret.add("return is not val in defpath")
                        ret.add(location + " " + retVal)
                        ret.add(getLocation(v.ithChildren(0).next()))
                    }
                }
            }
            else {
                ret.add("not return in defpath")
                ret.add(getLocation(v))
            }
        }
    }
    if (!hasFunc) {
        ret.add("func def not found in defpath")
        ret.add(nodeLocation+" "+funcName)
    }
}

def getDefPathsForValForArray(node, nodes, arrayIndex, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, defVals, sanitizations, instack, isWP, skipWPFunc, ret) {
    def count = node.numChildren().next()
    def statement = node.statements().next()
    if (statement.type == "AST_IF") {
        statement = statement.ithChildren(0).next().ithChildren(0).next()
    }
    def nodeLocation = statement.toFileAbs().next().name + ":" + statement.lineno
    for (int i = 0; i < count; i++) {
        def arrayElem = node.ithChildren(i).next()
        def key = getAllValName(arrayElem.ithChildren(1).next())
        def value = getAllValName(arrayElem.ithChildren(0).next())
        if (value.startsWith("\$")) {
            if (arrayIndex != "") {
                if (arrayIndex.indexOf("["+Integer.toString(i)+"]") != -1) {
                    ret.add("arrayIndex.indexOf(["+Integer.toString(i)+"]) != -1 in defpath")
                    ret.add(nodeLocation+" "+value)
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "equal")))
                }
                else if (arrayIndex.indexOf("["+key+"]") != -1) {
                    ret.add("arrayIndex.indexOf(["+key+"]) != -1 in defpath")
                    ret.add(nodeLocation+" "+value)
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "equal")))
                }
                else {
                }
                getDefPathsForVal(statement, nodes, value, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
            }
            else {
                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation + " " + value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "array_contain")))
                getDefPathsForVal(statement, nodes, value, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
            }
        }
        else if (arrayElem.ithChildren(0).next().type == "string" || arrayElem.ithChildren(0).next().type == "integer" || arrayElem.ithChildren(0).next().type == "AST_CONST") {
            if (value == "") {
                value = "''"
            }
            if (arrayIndex != "") {
                if (arrayIndex.indexOf("[" + Integer.toString(i) + "]") != -1) {
                    ret.add("arrayIndex.indexOf([" + Integer.toString(i) + "]) != -1 in defpath")
                    ret.add(nodeLocation + " " + value)
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation + " " + value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "const")))
                }
                else if (arrayIndex.indexOf("[" + key + "]") != -1) {
                    ret.add("arrayIndex.indexOf([" + key + "]) != -1 in defpath")
                    ret.add(nodeLocation + " " + value)
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation + " " + value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "const")))
                }
                else {

                }
            }
            else {
                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation + " " + value, new AbstractMap.SimpleEntry<Vertex, String>(statement, "array_contain_const")))
            }
        }
        else {
            ret.add("not val in array in defpath")
            ret.add(nodeLocation+" "+value)
            ret.add(getLocation(arrayElem.ithChildren(0).next()))
        }
    }
}

def getDefPathsForValForParam(node, nodes, val, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, defVals, sanitizations, instack, isWP, skipWPFunc, ret) {
    def paramName = getAllValName(node)
    def nodeLocation = node.toFileAbs().next().name + ":" + node.lineno
    def scopeLocation = node.toFileAbs().next().name +"_" + node.functions.next().name + ":" + node.functions().next().lineno
    def indexOfVal = ""
    if (paramName != val) {
        if (val.startsWith(paramName)) {
            if (valTableColumnMap.containsKey(nodeLocation+" "+val)) {
                def isSql = true
                def defTableEntry = valTableColumnMap.get(nodeLocation+" "+val)
                def defSensitiveIndex = defTableEntry.getValue()
                for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                    if (defSensitiveIndex.get(i) == "-1") {
                        isSql = false
                        break
                    }
                }
                if (isSql) {
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(node, "sql")))
                    return
                }
                else {
                    indexOfVal = val.substring(paramName.length())
                }
            }
            else {
                indexOfVal = val.substring(paramName.length())
            }
        }
        else {
            return
        }
    }

    if (valTableColumnMap.containsKey(nodeLocation+" "+paramName+indexOfVal)) {
        def isSql = true
        def defTableEntry = valTableColumnMap.get(nodeLocation+" "+paramName+indexOfVal)
        def defSensitiveIndex = defTableEntry.getValue()
        for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
            if (defSensitiveIndex.get(i) == "-1") {
                isSql = false
                break
            }
        }
        if (isSql) {
            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation + " " + paramName+indexOfVal, new AbstractMap.SimpleEntry<Vertex, String>(node, "sql")))
            return
        }
    }
    if (sessionMap.containsKey(nodeLocation+" "+paramName+indexOfVal) || sessionMap.containsKey(scopeLocation+" "+paramName+indexOfVal)) {
        defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+paramName+indexOfVal, new AbstractMap.SimpleEntry<Vertex, String>(node, "session")))
        return
    }


    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(nodeLocation+" "+paramName+indexOfVal, new AbstractMap.SimpleEntry<Vertex, String>(node, "param")))
    if (defPaths.containsKey(nodeLocation+" "+paramName+indexOfVal)) {
        return
    }
    def func = node.functions().next()
    def ithChild = node.childnum
    def defValsOfParam = new HashSet<AbstractMap.SimpleEntry<String,AbstractMap.SimpleEntry<Vertex,String>>>()
    for (caller in func.in("CALLS")) {
        if (isCallExpression(caller)) {
            def funcName = getFuncName(caller)
            if (isWP && skipWPFunc.contains(funcName)) {
                continue
            }
            if (isWithinFunction(caller)) {
                def callerFunc = caller.functions().next()
                if (callerFunc != null) {
                    def callerFuncName = callerFunc.name
                    if (isWP && skipWPFunc.contains(callerFuncName)) {
                        continue
                    }
                }
            }
            def callerStatement = caller.statements().next()
            if (callerStatement.type == "AST_IF") {
                callerStatement = callerStatement.ithChildren(0).next().ithChildren(0).next()
            }
            def callerLocation = callerStatement.toFileAbs().next().name + ":" + callerStatement.lineno
            def argsNum = caller.numArguments().next()
            if (ithChild < argsNum) {
                def arg = getAllValName(caller.ithArguments(ithChild).next())
                if (indexOfVal != "" && arg.indexOf(indexOfVal) == -1) {
                    arg = arg+indexOfVal
                }
                if (arg.startsWith("\$")) {
                    defValsOfParam.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(callerLocation+" "+arg, new AbstractMap.SimpleEntry<Vertex, String>(callerStatement, "arg")))
                    getDefPathsForVal(callerStatement, nodes, arg, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
                }
                else if (caller.ithArguments(ithChild).next().type == "string" || caller.ithArguments(ithChild).next().type == "integer" || caller.ithArguments(ithChild).next().type == "AST_CONST") {
                    if (arg == "") {
                        arg = "''"
                    }
                    defValsOfParam.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(callerLocation+" "+arg, new AbstractMap.SimpleEntry<Vertex, String>(callerStatement, "arg_const")))
                }
                else {
                    ret.add("arg is not val in defpath")
                    ret.add(callerLocation)
                    ret.add(caller.ithArguments(ithChild).next())
                }
            }
            else {
                ret.add("ithChild >= argsNum in defpath")
                ret.add(callerLocation)
                ret.add(func)
            }
        }
    }

    defPaths.put(nodeLocation+" "+paramName+indexOfVal, defValsOfParam)
}

def getDefPathsForVal(node, nodes, val, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret) {
    def sum = 0
    for (int index = 0; index < val.length(); ++index) {
        if (val[index] == '[') {
            sum++
        }
    }
    if (sum >= 3) {
        return
    }
    def defVals = new HashSet<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
    def nodeLocation = node.toFileAbs().next().name + ":" + node.lineno
    if (instack.contains(nodeLocation+" "+val)) {
        return
    }
    if (defPaths.containsKey(nodeLocation + " " + val)) {
        return
    }
    instack.add(nodeLocation+" "+val)
    System.out.println(nodeLocation+" "+val)
    for (v in node.in("REACHES")) {
        def location = v.toFileAbs().next().name + ":" + v.lineno
        def scopeLocation = v.toFileAbs().next().name
        if (isWithinFunction(v)) {
            scopeLocation = scopeLocation +"_" + v.functions.next().name + ":" + v.functions().next().lineno
        }
        def statementOfV = v

        if (nodes.contains(v)) {
            if (valTableColumnMap.containsKey(location+" "+val)) {
                def isSql = true
                def defTableEntry = valTableColumnMap.get(location+" "+val)
                def defSensitiveIndex = defTableEntry.getValue()
                for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                    if (defSensitiveIndex.get(i) == "-1") {
                        isSql = false
                        break
                    }
                }
                if (isSql) {
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(v, "sql")))
                }
            }
            continue
        }

        v = getInnerNode(v)
        if (v.type == "AST_ASSIGN" || (v.type == "AST_ASSIGN_OP" && (isWithinForeach(v) || isWithinFor(v)))) {
            def assignName = getAllValName(v.ithChildren(0).next())
            def isArrayAdd = assignName.indexOf("[]") != -1
            def arrayIndex = ""
            assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')

            if (assignName != val) {
                if (val.startsWith(assignName) && valTableColumnMap.containsKey(location+" "+val)) {
                    def isSql = true
                    def defTableEntry = valTableColumnMap.get(location+" "+val)
                    def defSensitiveIndex = defTableEntry.getValue()
                    for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                        if (defSensitiveIndex.get(i) == "-1") {
                            isSql = false
                            break
                        }
                    }
                    if (isSql) {
                        defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "sql")))
                        continue
                    }
                }
                def assignNameArray = assignName
                if (assignName.indexOf("[") != -1) {
                    assignNameArray = assignName.substring(0, assignName.indexOf("["))
                }
                def valArray = val
                if (val.indexOf("[") != -1) {
                    valArray = val.substring(0, val.indexOf("["))
                }
                if (assignNameArray == valArray) {
                    if (assignName != assignNameArray && !isArrayAdd) {
                        defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "array_trans")))
                        getDefPathsForVal(statementOfV, nodes, val, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
                        continue
                    }
                    else {
                        if (val.indexOf("[") != -1) {
                            arrayIndex = val.substring(val.lastIndexOf("["))
                        }
                    }
                }
                else {
                    continue
                }
            }

            def funcs = new HashSet<String>()
            def start = new HashSet<Boolean>()
            start.add(true)
            def value = statementToString(v.ithChildren(1).next(), start, new HashMap<>(), funcs, sanitizations)
            value = value.trim()

            if (valTableColumnMap.containsKey(location+" "+val)) {
                def isSql = true
                def defTableEntry = valTableColumnMap.get(location+" "+val)
                def defSensitiveIndex = defTableEntry.getValue()
                for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                    if (defSensitiveIndex.get(i) == "-1") {
                        isSql = false
                        break
                    }
                }
                if (isSql) {
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "sql")))
                    continue
                }
            }
            if (sessionMap.containsKey(location+" "+val) || sessionMap.containsKey(scopeLocation+" "+val)) {
                if (sessionMap.containsKey(location+" "+val)) {
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "session")))
                }
                else {
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(scopeLocation + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "session")))
                }
                continue
            }

            def inEqual = false
            for (String func in funcs) {
                if (equal_funcs.contains(func)) {
                    inEqual = true
                }
            }
            if (inEqual) {
                value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
            }
            if (value.startsWith("\$")) {
                if (arrayIndex != "" && value.indexOf(arrayIndex) == -1) {
                    value = value + arrayIndex
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "array_equal")))
                }
                else {
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "equal")))
                }
                getDefPathsForVal(statementOfV, nodes, value, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
            }
            else if (!inEqual) {
                if (v.ithChildren(1).next().type == "AST_CALL" || v.ithChildren(1).next().type == "AST_METHOD_CALL" || v.ithChildren(1).next().type == "AST_STATIC_CALL") {
                    getDefPathsForValForCall(v.ithChildren(1).next(), nodes, arrayIndex, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, defVals, sanitizations, instack, isWP, skipWPFunc, ret)
                }
                else if (v.ithChildren(1).next().type == "AST_ARRAY") {
                    getDefPathsForValForArray(v.ithChildren(1).next(), nodes, arrayIndex, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, defVals, sanitizations, instack, isWP, skipWPFunc, ret)
                }
                else if (v.ithChildren(1).next().type == "string" || v.ithChildren(1).next().type == "integer" || v.ithChildren(1).next().type == "AST_CONST") {
                    if (value == "") {
                        value = "''"
                    }
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location+" "+value, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "const")))
                }
                else {
                    ret.add("value is not val in assign in defpath")
                    ret.add(location+" "+value)
                    ret.add(getLocation(v.ithChildren(1).next()))
                }
            }
        }
        else if (v.type == "AST_GLOBAL") {
            def globalVal = getAllValName(v)
            if (globalVal != val) {
                def globalValArray = globalVal
                if (globalVal.indexOf("[") != -1) {
                    globalValArray = globalVal.substring(0, globalVal.indexOf("["))
                }
                def valArray = val
                if (val.indexOf("[") != -1) {
                    valArray = val.substring(0, val.indexOf("["))
                }
                if (globalValArray == valArray) {
                    globalVal = val
                }
                else {
                    continue
                }
            }
            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + globalVal, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "global")))
        }
        else if (v.type == "AST_PARAM") {
            getDefPathsForValForParam(v, nodes, val, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, defVals, sanitizations, instack, isWP, skipWPFunc, ret)
        }
        else if (v.type == "AST_VAR") {
            def statement = getStatement(v.statements().next())
            if (statement.type == "AST_FOREACH") {
                def assignName = getAllValName(v)
                def isKey = v.childnum == 2
                def hasKey = true
                if (statement.ithChildren(2).next().type == "NULL") {
                    hasKey = false
                }
                def valueNode = statement.ithChildren(0).next()
                def value = getAllValName(valueNode)
                if (!hasKey) {
                    value = value+"[0]"
                }
                else {
                    if (isKey) {
                        value = value+"[KEY]"
                    }
                    else {
                        value = value+"[VALUE]"
                    }
                }
                location = valueNode.toFileAbs().next().name + ":" + valueNode.lineno
                if (assignName != val) {
                    if (val.startsWith(assignName) && valTableColumnMap.containsKey(location+" "+val)) {
                        def isSql = true
                        def defTableEntry = valTableColumnMap.get(location+" "+val)
                        def defSensitiveIndex = defTableEntry.getValue()
                        for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                            if (defSensitiveIndex.get(i) == "-1") {
                                isSql = false
                                break
                            }
                        }
                        if (isSql) {
                            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(v, "sql")))
                            continue
                        }
                    }
                    if (val.indexOf(assignName) != -1) {
                        ret.add("val contains assignName in foreach in defpath")
                        ret.add(location+" "+assignName)
                        ret.add(location+" "+val)
                        ret.add(getLocation(v))
                    }
                    else {
                        ret.add("assignName != val in foreach in defpath")
                        ret.add(location+" "+assignName)
                        ret.add(location+" "+val)
                        ret.add(getLocation(v))
                        continue
                    }
                }

                if (valTableColumnMap.containsKey(location+" "+val)) {
                    def isSql = true
                    def defTableEntry = valTableColumnMap.get(location+" "+val)
                    def defSensitiveIndex = defTableEntry.getValue()
                    for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                        if (defSensitiveIndex.get(i) == "-1") {
                            isSql = false
                            break
                        }
                    }
                    if (isSql) {
                        defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(v, "sql")))
                        continue
                    }
                }
                if (sessionMap.containsKey(location+" "+val) || sessionMap.containsKey(scopeLocation+" "+val)) {
                    if (sessionMap.containsKey(location+" "+val)) {
                        defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(v, "session")))
                    }
                    else {
                        defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(scopeLocation + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(v, "session")))
                    }
                    continue
                }

                if (value.startsWith("\$")) {
                    defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex, String>>(location + " " + value, new AbstractMap.SimpleEntry<Vertex, String>(v, "array_equal")))
                    getDefPathsForVal(valueNode, nodes, value, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
                }
                else {
                    ret.add("not val in foreach in defpath")
                    ret.add(location+" "+value)
                    ret.add(getLocation(valueNode))
                }
            }
            else {
                ret.add("other var type in getDefPath")
                ret.add(location)
                ret.add(getLocation(statement))
            }
        }
        else if (v.type == "AST_CALL" || v.type == "AST_METHOD_CALL" || v.type == "AST_STATIC_CALL") {
            def funcName = getFuncName(v)
            def count = v.numArguments().next()
            if (funcName == "array_push") {
                def assignName = getAllValName(v.ithArguments(0).next())
                def arrayIndex = ""
                if (assignName != val) {
                    if (val.startsWith(assignName) && valTableColumnMap.containsKey(location+" "+val)) {
                        def isSql = true
                        def defTableEntry = valTableColumnMap.get(location+" "+val)
                        def defSensitiveIndex = defTableEntry.getValue()
                        for (int i = 0; i < defSensitiveIndex.size(); i += 5) {
                            if (defSensitiveIndex.get(i) == "-1") {
                                isSql = false
                                break
                            }
                        }
                        if (isSql) {
                            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "sql")))
                            continue
                        }
                    }
                    def assignNameArray = assignName
                    if (assignName.indexOf("[") != -1) {
                        assignNameArray = assignName.substring(0, assignName.indexOf("["))
                    }
                    def valArray = val
                    if (val.indexOf("[") != -1) {
                        valArray = val.substring(0, val.indexOf("["))
                    }
                    if (assignNameArray == valArray) {
                        if (assignName != assignNameArray) {
                            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "array_trans")))
                            getDefPathsForVal(statementOfV, nodes, val, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
                        }
                        else {
                            assignName = val
                            if (val.indexOf("[") != -1) {
                                arrayIndex = val.substring(val.lastIndexOf("["))
                            }
                        }
                    }
                    else {
                        continue
                    }
                }

                def funcs = new HashSet<String>()
                def start = new HashSet<Boolean>()
                start.add(true)
                for (int i = 1; i < count; i++) {
                    def argNode = v.ithArguments(i).next()
                    def value = statementToString(argNode, start, new HashMap<>(), funcs, sanitizations)
                    value = value.trim()

                    if (valTableColumnMap.containsKey(location+" "+val)) {
                        def isSql = true
                        def defTableEntry = valTableColumnMap.get(location+" "+val)
                        def defSensitiveIndex = defTableEntry.getValue()
                        for (int j = 0; j < defSensitiveIndex.size(); j += 5) {
                            if (defSensitiveIndex.get(j) == "-1") {
                                isSql = false
                                break
                            }
                        }
                        if (isSql) {
                            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "sql")))
                            continue
                        }
                    }
                    if (sessionMap.containsKey(location+" "+val) || sessionMap.containsKey(scopeLocation+" "+val)) {
                        if (sessionMap.containsKey(location+" "+val)) {
                            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "session")))
                        }
                        else {
                            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(scopeLocation + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "session")))
                        }
                        continue
                    }

                    def inEqual = false
                    for (String func in funcs) {
                        if (equal_funcs.contains(func)) {
                            inEqual = true
                        }
                    }
                    if (inEqual) {
                        value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
                    }
                    if (value.startsWith("\$")) {
                        if (arrayIndex != "" && value.indexOf(arrayIndex) == -1) {
                            value = value + arrayIndex
                            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + value, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "array_equal")))
                        }
                        else {
                            defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(location + " " + value, new AbstractMap.SimpleEntry<Vertex, String>(statementOfV, "equal")))
                        }
                        getDefPathsForVal(statementOfV, nodes, value, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, sanitizations, instack, isWP, skipWPFunc, ret)
                    }
                    else if (!inEqual) {
                        if (argNode.type == "AST_CALL" || argNode.type == "AST_METHOD_CALL" || argNode.type == "AST_STATIC_CALL") {
                            getDefPathsForValForCall(argNode, nodes, arrayIndex, valTableColumnMap, valDefTableColumnMap, sessionMap, equal_funcs, defPaths, defVals, sanitizations, instack, isWP, skipWPFunc, ret)
                        }
                        else {
                            ret.add("value is not val in array_push in defpath")
                            ret.add(location + " " + value)
                            ret.add(getLocation(argNode))
                        }
                    }
                }
            }
            else {
                ret.add("other call type in getDefPath")
                ret.add(location+" "+funcName)
                ret.add(getLocation(v))
            }
        }
        else {
            ret.add("other type in getDefPath")
            ret.add(location)
            ret.add(getLocation(v))
        }
    }

    if (sessionMap.containsKey(val)) {
        def sessionEntry = sessionMap.get(val)
        def sessionNode = sessionEntry.getKey()
        def sessionNodeLocation = sessionNode.toFileAbs().next().name + ":" + sessionNode.lineno
        defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex, String>>(sessionNodeLocation + " " + val, new AbstractMap.SimpleEntry<Vertex, String>(sessionNode, "session_equal")))
        def sessionVal = sessionEntry.getValue()
        for (sval in sessionVal) {
            if (valDefTableColumnMap.containsKey(sval)) {
                def defEntry = valDefTableColumnMap.get(sval)
                def defNode = defEntry.getKey()
                defVals.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex, String>>(sval, new AbstractMap.SimpleEntry<Vertex, String>(defNode, "session_equal")))
            }
        }
    }

    defPaths.put(nodeLocation + " " + val, defVals)
    instack.remove(nodeLocation+" "+val)
}

def constructDefPaths(val, defPaths, path, paths, valPathsMap, table, callerDTableMaps, visited) {
    if (valPathsMap.containsKey(val)) {
        paths.addAll(valPathsMap.get(val))
        return
    }
    if (defPaths.containsKey(val)) {
        def defVals = defPaths.get(val)
        if (defVals.size() > 0) {
            for (entry in defVals) {
                def defVal = entry.getKey()
                def nodeFlagEntry = entry.getValue()
                def node = nodeFlagEntry.getKey()
                def flag = nodeFlagEntry.getValue()
                def newPath = new ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>()
                def newPaths = new HashSet<ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>>()
                def newVisited = new HashSet<String>(visited)
                if (!newVisited.contains(defVal)) {
                    newVisited.add(defVal)
                    if (flag != "array_trans") {
                        if (callerDTableMaps.containsKey(node) && callerDTableMaps.get(node) != table) {
                            continue
                        }
                        newPath.add(new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>(defVal, new AbstractMap.SimpleEntry<Vertex, String>(node, flag)))
                    }
                    constructDefPaths(defVal, defPaths, newPath, newPaths, valPathsMap, table, callerDTableMaps, newVisited)
                    if (newPaths.size() > 0) {
                        for (nPath in newPaths) {
                            def pathCopy = new ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>(path)
                            pathCopy.addAll(nPath)
                            paths.add(pathCopy)
                        }
                    }
                    else {
                        def pathCopy = new ArrayList<AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<Vertex,String>>>(path)
                        pathCopy.addAll(newPath)
                        paths.add(pathCopy)
                    }
                }
            }
        }
        else {
            if (path.size() > 0) {
                paths.add(path)
            }
        }
    }
    else {
        if (path.size() > 0) {
            paths.add(path)
        }
    }
    valPathsMap.put(val, paths)
}

def constructFlowPaths(path, skip_func, exit_funcs, exit_blocks, may_exit_blocks, path_records, ret) {
    def length = path.size()
    for (int i = length-1; i > 0; --i) {
        def source = path.get(i).getValue().getKey()
        def sourceFlag = path.get(i).getValue().getValue()
        def target = path.get(i-1).getValue().getKey()
        if (sourceFlag != "arg") {
            if (path_records.containsKey(new AbstractMap.SimpleEntry<Vertex, Vertex>(source, target))) {
                ret.add("#############@@@@@@@@@@@##############")
                ret.add("source and target in path_records in constructFlowPaths")
                ret.add("source:" + getLocation(source))
                ret.add("target:" + getLocation(target))
                continue
            }
            def controlNodesOfTarget = getControlNodes(target, ret)
            def controlNodesOfExit = new HashSet<Vertex>()
            def visited = new HashSet<String>()
            def flowPaths = new ArrayList<ArrayList<Vertex>>()
            def stack = new ArrayList<Vertex>()
            def fPath = new ArrayList<Vertex>()
            fPath.add(source)
            ret.add("#############@@@@@@@@@@@##############")
            ret.add("source:" + getLocation(source))
            ret.add("target:" + getLocation(target))
            ret.add("@@@@@@@@@@@@@getFlowPathFromSourceToTarget@@@@@@@@@@@@@")
            getFlowPathFromSourceToTarget(source, target, fPath, flowPaths, visited, stack, skip_func, exit_funcs, exit_blocks, may_exit_blocks, controlNodesOfTarget, controlNodesOfExit, ret)
            path_records.put(new AbstractMap.SimpleEntry<Vertex, Vertex>(source, target), [fPath, controlNodesOfTarget, controlNodesOfExit])

            ret.add("@@@@@@@@@@@@@flowNodes@@@@@@@@@@@@@")
            for (flowNode in fPath) {
                ret.add(getLocation(flowNode))
            }

            ret.add("@@@@@@@@@@@@@controlNodesOfTarget@@@@@@@@@@@@@")
            for (controlNodeOfTarget in controlNodesOfTarget.keySet()) {
                ret.add("****@@@@****")
                def controlEdge = controlNodesOfTarget.get(controlNodeOfTarget)
                def controlVar = ""
                if (controlEdge.getProperty("var")) {
                    controlVar = controlEdge.getProperty("var")
                }
                ret.add(getLocation(controlNodeOfTarget) + " " + controlVar)
            }

            ret.add("@@@@@@@@@@@@@controlNodesOfExit@@@@@@@@@@@@@")
            for (controlNodeOfExit in controlNodesOfExit) {
                ret.add("****@@@@****")
                ret.add(getLocation(controlNodeOfExit))
                def controlPaths = exit_blocks.get(controlNodeOfExit)
                printControlPaths(controlPaths, ret)
            }
        }
    }
}

def getFlie(node) {
    def file = ""
    if (!(node.type == "CFG_FUNC_ENTRY" || node.type == "CFG_FUNC_EXIT" || node.type == "AST_TOPLEVEL" || node.type == "Directory" || node.type == "File")) {
        file = node.toFileAbs().next().name
    }
    return file
}

def getLocation(node) {
    def location = ""
    if (node.type == "CFG_FUNC_ENTRY" || node.type == "CFG_FUNC_EXIT") {
        location = node.type + " " + node.id
    }
    else if (node.type == "AST_TOPLEVEL") {
        location = node.type + " " + node.name
    }
    else {
        if (node.flags != null) {
            location = node.toFileAbs().next().name + ":" + node.lineno + " " + node.type + " " + node.flags + " " + node.id
        }
        else {
            location = node.toFileAbs().next().name + ":" + node.lineno + " " + node.type + " " + node.id
        }
    }
    return location
}

def getStatement(node) {
    def statement = node.statements().next()
    if (statement.type == "AST_IF") {
        statement = statement.ithChildren(0).next().ithChildren(0).next()
    }
    else if (statement.type == "AST_WHILE") {
        statement = statement.ithChildren(0).next()
    }
    return statement
}

def getFlowPathFromSourceToSinkForCall(source, sink, path, paths, visited, stack, skip_func, error_funcs, ret) {
    def hasFunc = false
    def count = source.numArguments().next()
    def funcName = getFuncName(source)

    for (int i = 0; i < count; ++i) {
        def arg = source.ithArguments(i).next()
        if (arg.type == "AST_CALL" || arg.type == "AST_METHOD_CALL" || arg.type == "AST_STATIC_CALL") {
            if (stack.contains(arg)) {
                continue
            }
            getFlowPathFromSourceToSinkForCall(arg, sink, path, paths, visited, stack, skip_func, error_funcs, ret)
        }
    }

    if (!skip_func.contains(funcName)) {
        for (func in source.out("CALLS")) {
            hasFunc = true
            def funcEntry = func.out("ENTRY").next()
            path.add(funcEntry)
            visited.add(funcEntry)
            getFlowPathFromSourceToSink(funcEntry, sink, path, paths, visited, stack, skip_func, error_funcs, ret)
            path.remove(funcEntry)
            visited.remove(funcEntry)
        }
    }

    if (!hasFunc) {
        ret.add("no func in call in flowpath "+funcName)
        def parent = source.parents().next()
        if (parent.type != "AST_ARG_LIST") {
            stack.remove(stack.size() - 1)
            def statement = getStatement(source)
            path.add(statement)
            visited.add(statement)
            getFlowPathFromSourceToSink(statement, sink, path, paths, visited, stack, skip_func, error_funcs, ret)
            path.remove(statement)
            visited.remove(statement)
        }
    }
}

def getFlowPathFromSourceToSinkForExit(source, sink, path, paths, visited, stack, skip_func, error_funcs, ret) {
    def func = source.in("EXIT").next()
    for (caller in func.in("CALLS")) {
        if (isCallExpression(caller)) {
            if (stack.size() > 0 && caller == stack.get(stack.size() - 1)) {
                def callerParent = caller.parents().next()
                if (callerParent.type != "AST_ARG_LIST") {
                    stack.remove(stack.size() - 1)
                    def callerStatement = getStatement(caller)
                    path.add(callerStatement)
                    visited.add(callerStatement)
                    getFlowPathFromSourceToSink(callerStatement, sink, path, paths, visited, stack, skip_func, error_funcs, ret)
                    path.remove(callerStatement)
                    visited.remove(callerStatement)
                }
            }
        }
    }
}

def getFlowPathFromSourceToSink(source, sink, path, paths, visited, stack, skip_func, error_funcs, ret) {
    if (source == sink) {
        if (path.size() > 0) {
            def newPath = new ArrayList<Vertex>(path)
            paths.add(newPath)
            return
        }
    }
    ret.add("source is "+source.type +" "+source.id)
    for (v in source.out("FLOWS_TO")) {
        if (visited.contains(v)) {
            continue
        }
        if (v.type == "CFG_FUNC_EXIT") {
            System.out.println(v.type +" "+v.id)
            ret.add(v.type +" "+v.id)
        }
        else {
            System.out.println(v.toFileAbs().next().name + ":" + v.lineno + " " + v.type +" "+v.id)
            ret.add(v.toFileAbs().next().name + ":" + v.lineno + " " + v.type +" "+v.id)
        }
        if (isExit(v)) {
            continue
        }
        if (v.type == "AST_ASSIGN") {
            if (v.ithChildren(1).next().type == "AST_CALL" || v.ithChildren(1).next().type == "AST_METHOD_CALL" || v.ithChildren(1).next().type == "AST_STATIC_CALL") {
                if (isErrorFunc(error_funcs, v.ithChildren(1).next())) {
                    continue
                }
                if (stack.contains(v.ithChildren(1).next())) {
                    continue
                }
                stack.add(v.ithChildren(1).next())
                getFlowPathFromSourceToSinkForCall(v.ithChildren(1).next(), sink, path, paths, visited, stack, skip_func, error_funcs, ret)
            }
            else {
                path.add(v)
                visited.add(v)
                getFlowPathFromSourceToSink(v, sink, path, paths, visited, stack, skip_func, error_funcs, ret)
                path.remove(v)
                visited.remove(v)
            }
        }
        else if (v.type == "AST_CALL" || v.type == "AST_METHOD_CALL" || v.type == "AST_STATIC_CALL") {
            if (isErrorFunc(error_funcs, v)) {
                continue
            }
            if (stack.contains(v)) {
                continue
            }
            stack.add(v)
            getFlowPathFromSourceToSinkForCall(v, sink, path, paths, visited, stack, skip_func, error_funcs, ret)
        }
        else if (v.type == "AST_RETURN") {
            if (v.ithChildren(0).next().type == "AST_CALL" || v.ithChildren(0).next().type == "AST_METHOD_CALL" || v.ithChildren(0).next().type == "AST_STATIC_CALL") {
                if (isErrorFunc(error_funcs, v.ithChildren(0).next())) {
                    continue
                }
                if (stack.contains(v.ithChildren(0).next())) {
                    continue
                }
                stack.add(v.ithChildren(0).next())
                getFlowPathFromSourceToSinkForCall(v.ithChildren(0).next(), sink, path, paths, visited, stack, skip_func, error_funcs, ret)
            }
            else {
                path.add(v)
                visited.add(v)
                getFlowPathFromSourceToSink(v, sink, path, paths, visited, stack, skip_func, error_funcs, ret)
                path.remove(v)
                visited.remove(v)
            }
        }
        else if (v.type == "CFG_FUNC_EXIT") {
            path.add(v)
            visited.add(v)
            getFlowPathFromSourceToSinkForExit(v, sink, path, paths, visited, stack, skip_func, error_funcs, ret)
            path.remove(v)
            visited.remove(v)
        }
        else {
            path.add(v)
            visited.add(v)
            getFlowPathFromSourceToSink(v, sink, path, paths, visited, stack, skip_func, error_funcs, ret)
            path.remove(v)
            visited.remove(v)
        }
    }
}

def getFlowPathFromSourceToTarget(source, target, path, paths, visited, stack, skip_func, exit_funcs, exit_blocks, may_exit_blocks, controlNodesOfTarget, controlNodesOfExit, ret) {
    if (source == target) {
        if (path.size() > 0) {
            def newPath = new ArrayList<Vertex>(path)
            paths.add(newPath)
            return
        }
    }

    for (v in source.out("FLOWS_TO")) {
        def location = getLocation(source)
        if (source.out("FLOWS_TO").count() > 1) {
            def flowEdges = source.outE("FLOWS_TO").toList()
            def flowEdge = null
            def flowVar = ""
            for (edge in flowEdges) {
                if (edge.inV().next().id == v.id) {
                    flowEdge = edge
                    break
                }
            }
            if (flowEdge && flowEdge.getProperty("var")) {
                flowVar = flowEdge.getProperty("var")
            }
            if (visited.contains(location+" "+flowVar)) {
                continue
            }
            if (controlNodesOfTarget.containsKey(source)) {
                def controlEdge = controlNodesOfTarget.get(source)
                def controlVar = ""
                if (controlEdge.getProperty("var")) {
                    controlVar = controlEdge.getProperty("var")
                }
                if (flowVar != controlVar) {
                    continue
                }
            }
            if (!controlNodesOfTarget.containsKey(source) && exit_blocks.containsKey(source)) {
                def controlPaths = exit_blocks.get(source)
                def isFlowToExit = false
                for (controlPath in controlPaths) {
                    def controlEdge = controlPath.get(0).getValue()
                    def controlVar = ""
                    if (controlEdge && controlEdge.getProperty("var")) {
                        controlVar = controlEdge.getProperty("var")
                    }
                    if (flowVar == controlVar) {
                        isFlowToExit = true
                    }
                }
                if (isFlowToExit) {
                    controlNodesOfExit.add(source)
                    continue
                }
            }
            if (!controlNodesOfTarget.containsKey(source) && may_exit_blocks.containsKey(source)) {
                def controlPaths = may_exit_blocks.get(source)
                def isMayFlowToExit = false
                for (controlPath in controlPaths) {
                    def controlEdge = controlPath.get(0).getValue()
                    def controlVar = ""
                    if (controlEdge && controlEdge.getProperty("var")) {
                        controlVar = controlEdge.getProperty("var")
                    }
                    if (flowVar == controlVar) {
                        def controlNodeOfExit = controlPath.get(controlPath.size() - 1).getKey()
                        controlNodesOfExit.add(controlNodeOfExit)
                        isMayFlowToExit = true
                    }
                }
                if (isMayFlowToExit) {
                    continue
                }
            }

            System.out.println(location+" "+flowVar)
            ret.add(location+" "+flowVar)
            path.add(v)
            visited.add(location+" "+flowVar)
            getFlowPathFromSourceToTarget(v, target, path, paths, visited, stack, skip_func, exit_funcs, exit_blocks, may_exit_blocks, controlNodesOfTarget, controlNodesOfExit, ret)
        }
        else {
            if (visited.contains(location)) {
                continue
            }
            if (isExit(v)) {
                continue
            }
            if (may_exit_blocks.containsKey(source)) {
                ret.add("may exit in flowpath")
                def controlPaths = may_exit_blocks.get(source)
                for (controlPath in controlPaths) {
                    def controlNodeOfExit = controlPath.get(controlPath.size() - 1).getKey()
                    controlNodesOfExit.add(controlNodeOfExit)
                }
            }
            System.out.println(location)
            ret.add(location)
            path.add(v)
            visited.add(location)
            getFlowPathFromSourceToTarget(v, target, path, paths, visited, stack, skip_func, exit_funcs, exit_blocks, may_exit_blocks, controlNodesOfTarget, controlNodesOfExit, ret)
        }
    }
}

def printControlPaths(controlPaths, ret) {
    for (controlPath in controlPaths) {
        def path = ""
        for (entry in controlPath) {
            def target = entry.getKey()
            def edge = entry.getValue()
            def var = ""
            if (edge && edge.getProperty("var")) {
                var = edge.getProperty("var")
            }
            path = path + "controls(" + var +") " + getLocation(target) + " "
        }
        ret.add(path)
    }
}

def hasCycle(callerStatement, controlPathsOfCaller) {
    for (controlPath in controlPathsOfCaller) {
        for (pathPair in controlPath) {
            def node = pathPair.getKey()
            if (node == callerStatement) {
                return true
            }
        }
    }
    return false
}

def findExit(exit_blocks, exit_funcs, header_statements, may_exit_blocks, hasTypeNodes, ret) {
    System.out.println("*************************findExit*************************")
    def exit_funcs_queue = new LinkedList<Vertex>()
    def may_exit_blocks_queue = new LinkedList<Vertex>()
    def exit_statements = []
    for (hasTypeNode in hasTypeNodes) {
        def type = hasTypeNode.type
        if (type == "AST_EXIT") {
            exit_statements.add(getStatement(hasTypeNode))
        }
        if (type == "AST_CALL" && getFuncName(hasTypeNode) == "header" && hasTypeNode.numArguments().next() >= 1 && getAllValName(hasTypeNode.ithArguments(0).next()).toUpperCase().startsWith("LOCATION:")) {
            header_statements.add(getStatement(hasTypeNode))
        }
    }

    for (exit_statement in exit_statements) {
        if (exit_statement.in("CONTROLS").count() == 0) {
            ret.add("exit is not within control")
            ret.add(getLocation(exit_statement))
            continue
        }
        def controlNodeOfExit = exit_statement.in("CONTROLS").next()
        def controlEdgeOfExit = exit_statement.inE("CONTROLS").next()
        if (exit_statement.type == "AST_EXIT" || exit_statement.type == "AST_ASSIGN" || exit_statement.type == "AST_CALL") {
            if (controlNodeOfExit.type == "CFG_FUNC_ENTRY") {
                if (isWithinFunction(exit_statement)) {
                    def exit_func = exit_statement.functions().next()
                    exit_funcs.add(exit_func)
                    exit_funcs_queue.offer(exit_func)
                }
                else {
                    ret.add("exit is not within function")
                    ret.add(getLocation(exit_statement))
                }
            }
            else {
                def controlPaths = new HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>()
                if (exit_blocks.containsKey(controlNodeOfExit)) {
                    controlPaths.addAll(exit_blocks.get(controlNodeOfExit))
                }
                def controlPath = new ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>()
                controlPath.add(new AbstractMap.SimpleEntry<Vertex, Edge>(exit_statement, controlEdgeOfExit))
                if (controlPaths.add(controlPath)) {
                    exit_blocks.put(controlNodeOfExit, controlPaths)
                    if (!may_exit_blocks_queue.contains(controlNodeOfExit)) {
                        may_exit_blocks_queue.offer(controlNodeOfExit)
                    }
                }
            }
        }
        else if (exit_statement.type == "AST_BINARY_OP" && exit_statement.flags != null) {
            if (exit_statement.flags.contains("BINARY_BOOL_OR")) {
                ret.add("binary bool or contains exit")
                ret.add(getLocation(exit_statement.ithChildren(0).next()))
                def controlPaths = new HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>()
                def hasExisted = false
                if (may_exit_blocks.containsKey(exit_statement)) {
                    controlPaths.addAll(may_exit_blocks.get(exit_statement))
                    hasExisted = true
                }
                def controlPath = new ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>()
                controlPath.add(new AbstractMap.SimpleEntry<Vertex, Edge>(exit_statement.ithChildren(0).next(), null))
                if (controlPaths.add(controlPath)) {
                    may_exit_blocks.put(exit_statement, controlPaths)
                    if (!hasExisted) {
                        may_exit_blocks_queue.offer(exit_statement)
                    }
                }
            }
            else {
                ret.add("other binary type contains exit")
                ret.add(getLocation(exit_statement))
            }
        }
        else {
            ret.add("other type contains exit")
            ret.add(getLocation(exit_statement))
        }
    }

    for (header_statement in header_statements) {
        if (header_statement.in("CONTROLS").count() == 0) {
            ret.add("header is not within control")
            ret.add(getLocation(header_statement))
            continue
        }
        def controlNodeOfHeader = header_statement.in("CONTROLS").next()
        def controlEdgeOfHeader = header_statement.inE("CONTROLS").next()
        if (header_statement.type == "AST_CALL" && getFuncName(header_statement) == "header") {
            if (controlNodeOfHeader.type == "CFG_FUNC_ENTRY") {
                if (isWithinFunction(header_statement)) {
                    def exit_func = header_statement.functions().next()
                    exit_funcs.add(exit_func)
                    exit_funcs_queue.offer(exit_func)
                }
                else {
                    ret.add("header is not within function")
                    ret.add(getLocation(header_statement))
                }
            }
            else {
                def controlPaths = new HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>()
                if (exit_blocks.containsKey(controlNodeOfHeader)) {
                    controlPaths.addAll(exit_blocks.get(controlNodeOfHeader))
                }
                def controlPath = new ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>()
                controlPath.add(new AbstractMap.SimpleEntry<Vertex, Edge>(header_statement, controlEdgeOfHeader))
                if (controlPaths.add(controlPath)) {
                    exit_blocks.put(controlNodeOfHeader, controlPaths)
                    if (!may_exit_blocks_queue.contains(controlNodeOfHeader)) {
                        may_exit_blocks_queue.offer(controlNodeOfHeader)
                    }
                }
            }
        }
        else {
            ret.add("other type contains header")
            ret.add(getLocation(header_statement))
        }
    }

    System.out.println("exit_funcs_queue begin")
    while (exit_funcs_queue.size() > 0) {
        def exit_func = exit_funcs_queue.poll()
        for (caller in exit_func.in("CALLS")) {
            if (isCallExpression(caller)) {
                def callerStatement = getStatement(caller)
                if (callerStatement.in("CONTROLS").count() == 0) {
                    ret.add("caller is not within control")
                    ret.add(getLocation(callerStatement))
                    continue
                }
                def controlNodeOfCaller = callerStatement.in("CONTROLS").next()
                def controlEdgeOfCaller = callerStatement.inE("CONTROLS").next()
                if (callerStatement.type == "AST_CALL" || callerStatement.type == "AST_METHOD_CALL" || callerStatement.type == "AST_STATIC_CALL" || callerStatement.type == "AST_ECHO") {
                    if (controlNodeOfCaller.type == "CFG_FUNC_ENTRY") {
                        if (isWithinFunction(callerStatement)) {
                            def caller_func = callerStatement.functions().next()
                            if (!exit_funcs.contains(caller_func)) {
                                exit_funcs.add(caller_func)
                                exit_funcs_queue.offer(caller_func)
                            }
                        }
                        else {
                            ret.add("caller is not within function")
                            ret.add(getLocation(callerStatement))
                        }
                    }
                    else {
                        def controlPaths = new HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>()
                        if (exit_blocks.containsKey(controlNodeOfCaller)) {
                            controlPaths.addAll(exit_blocks.get(controlNodeOfCaller))
                        }
                        def controlPath = new ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>()
                        controlPath.add(new AbstractMap.SimpleEntry<Vertex, Edge>(callerStatement, controlEdgeOfCaller))
                        if (controlPaths.add(controlPath)) {
                            exit_blocks.put(controlNodeOfCaller, controlPaths)
                            if (!may_exit_blocks_queue.contains(controlNodeOfCaller)) {
                                may_exit_blocks_queue.offer(controlNodeOfCaller)
                            }
                        }
                    }
                }
                else if (callerStatement.type == "AST_BINARY_OP" && callerStatement.flags != null) {
                    if (callerStatement.flags.contains("BINARY_BOOL_OR")) {
                        ret.add("binary bool or contains exit_func")
                        ret.add(getLocation(callerStatement.ithChildren(0).next()))
                        def controlPaths = new HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>()
                        def hasExisted = false
                        if (may_exit_blocks.containsKey(callerStatement)) {
                            controlPaths.addAll(may_exit_blocks.get(callerStatement))
                            hasExisted = true
                        }
                        def controlPath = new ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>()
                        controlPath.add(new AbstractMap.SimpleEntry<Vertex, Edge>(callerStatement.ithChildren(0).next(), null))
                        if (controlPaths.add(controlPath)) {
                            may_exit_blocks.put(callerStatement, controlPaths)
                            if (hasExisted) {
                                may_exit_blocks_queue.offer(callerStatement)
                            }
                        }
                    }
                    else {
                        ret.add("other binary type contains exit_func")
                        ret.add(getLocation(callerStatement))
                    }
                }
                else {
                    ret.add("other type contains exit_func")
                    ret.add(getLocation(callerStatement))
                }
            }
        }
    }

    System.out.println("may_exit_blocks_queue begin")
    while (may_exit_blocks_queue.size() > 0) {
        def controlNode = may_exit_blocks_queue.poll()
        System.out.println(getLocation(controlNode))
        def controlPaths = new HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>()
        if (may_exit_blocks.containsKey(controlNode)) {
            controlPaths.addAll(may_exit_blocks.get(controlNode))
        }
        if (controlNode.in("CONTROLS").count() == 0) {
            ret.add("controlNode is not within control")
            ret.add(getLocation(controlNode))
            continue
        }
        def controlNodeOfControlNode = controlNode.in("CONTROLS").next()
        def controlEdgeOfControlNode = controlNode.inE("CONTROLS").next()
        if (controlNodeOfControlNode.type == "CFG_FUNC_ENTRY") {
            if (isWithinFunction(controlNode)) {
                def control_func = controlNode.functions().next()
                if (exit_funcs.contains(control_func)) {
                   ret.add("control_func "+control_func.name+" is exit_func")
                }
                else {
                    def controlPathsOfFunc = new HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>()
                    def changed = false
                    if (may_exit_blocks.containsKey(control_func)) {
                        controlPathsOfFunc.addAll(may_exit_blocks.get(control_func))
                    }
                    for (controlPath in controlPaths) {
                        def newControlPath = new ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>(controlPath)
                        newControlPath.add(0, new AbstractMap.SimpleEntry<Vertex, Edge>(controlNode, controlEdgeOfControlNode))
                        changed = controlPathsOfFunc.add(newControlPath)
                    }
                    if (controlPaths.size() == 0) {
                        def controlPath = new ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>()
                        controlPath.add(new AbstractMap.SimpleEntry<Vertex, Edge>(controlNode, controlEdgeOfControlNode))
                        changed = controlPathsOfFunc.add(controlPath)
                    }
                    if (changed) {
                        may_exit_blocks.put(control_func, controlPathsOfFunc)
                        for (caller in control_func.in("CALLS")) {
                            if (isCallExpression(caller)) {
                                def callerStatement = getStatement(caller)
                                def controlPathsOfCaller = new HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>()
                                if (may_exit_blocks.containsKey(callerStatement)) {
                                    controlPathsOfCaller.addAll(may_exit_blocks.get(callerStatement))
                                }
                                changed = controlPathsOfCaller.addAll(controlPathsOfFunc)
                                if (changed) {
                                    if (hasCycle(callerStatement, controlPathsOfCaller)) {
                                        ret.add("has cycle")
                                        ret.add(getLocation(callerStatement))
                                        continue
                                    }
                                    may_exit_blocks.put(callerStatement, controlPathsOfCaller)
                                    may_exit_blocks_queue.offer(callerStatement)
                                }
                            }
                        }
                    }
                }
            }
            else {
                ret.add("controlNode is not within function")
                ret.add(getLocation(controlNode))
            }
        }
        else {
            def controlPathsOfControlNode = new HashSet<ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>>()
            def changed = false
            if (may_exit_blocks.containsKey(controlNodeOfControlNode)) {
                controlPathsOfControlNode.addAll(may_exit_blocks.get(controlNodeOfControlNode))
            }
            for (controlPath in controlPaths) {
                def newControlPath = new ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>(controlPath)
                newControlPath.add(0, new AbstractMap.SimpleEntry<Vertex, Edge>(controlNode, controlEdgeOfControlNode))
                changed = controlPathsOfControlNode.add(newControlPath)
            }
            if (controlPaths.size() == 0) {
                def controlPath = new ArrayList<AbstractMap.SimpleEntry<Vertex, Edge>>()
                controlPath.add(new AbstractMap.SimpleEntry<Vertex, Edge>(controlNode, controlEdgeOfControlNode))
                changed = controlPathsOfControlNode.add(controlPath)
            }
            if (changed) {
                may_exit_blocks.put(controlNodeOfControlNode, controlPathsOfControlNode)
                may_exit_blocks_queue.offer(controlNodeOfControlNode)
            }
        }
    }

    System.out.println("may_exit_blocks_queue end")
    ret.add("*****************************exit_funcs*****************************")
    for (exit_func in exit_funcs) {
        ret.add(getLocation(exit_func)+" "+exit_func.name)
    }

    ret.add("*****************************header_statements*****************************")
    for (header_statement in header_statements) {
        ret.add(getLocation(header_statement))
    }

    ret.add("*****************************exit_blocks*****************************")
    for (controlNodeOfExit in exit_blocks.keySet()) {
        ret.add("####****####")
        ret.add(getLocation(controlNodeOfExit))
        def controlPaths = exit_blocks.get(controlNodeOfExit)
    }

    System.out.println("print exit_blocks end")

    ret.add("*****************************may_exit_blocks*****************************")
    for (controlNodeOfMayExit in may_exit_blocks.keySet()) {
        ret.add("****####****")
        ret.add(getLocation(controlNodeOfMayExit))
        def controlPaths = may_exit_blocks.get(controlNodeOfMayExit)
    }

    System.out.println("print may_exit_blocks end")
}

def getValForDynamicTable(node, dynamicTable, ret) {
    def callerDTableMap = new HashMap<Vertex, String>()
    if (isWithinFunction(node)) {
        def func = node.functions().next()
        def count = func.numParams().next()
        def ithIndex = -1
        for (int i = 0; i < count; ++i) {
            def paramsNum = func.numParams().next()
            if (i < paramsNum) {
                def paramNode = func.ithParams(i).next()
                def param = getAllValName(paramNode)
                ret.add(param + " " + dynamicTable)
                if (param == dynamicTable) {
                    ithIndex = i
                    break
                }
            }
        }
        if (ithIndex != -1) {
            for (caller in func.in("CALLS")) {
                if (isCallExpression(caller)) {
                    def callerStatement = getStatement(caller)
                    def argsNum = caller.numArguments().next()
                    if (argsNum > ithIndex) {
                        def arg = caller.ithArguments(ithIndex).next()
                        def argVal = getAllValName(arg)
                        if (argVal != "") {
                            callerDTableMap.put(callerStatement, argVal)
                        }
                    }
                }
            }
        }
    }
    return callerDTableMap
}

def findAllBindArray(bindArrayNode, bindParam, originalSql, query_nodes, query_sqls, combine_index, combineNodes, node, table_prefix, table_prefix_func, table_prefix_array, sanitizations, visited, ret) {
    if (visited.contains(bindArrayNode)) {
        return
    }
    visited.add(bindArrayNode)
    if (bindArrayNode.type == "AST_ASSIGN") {
        def assignName = getAllValName(bindArrayNode.ithChildren(0).next())

        def valueNode = bindArrayNode.ithChildren(1).next()

        if (assignName == bindParam+"[]") {
            if (valueNode.type == "AST_ARRAY") {
                def paramNum = valueNode.numChildren().next()
                if (paramNum < 2) {
                    ret.add("paramNum < 2")
                    ret.add(getLocation(bindArrayNode))
                }
                else {
                    def keyElem = valueNode.ithChildren(0).next()
                    def key = getAllValName(keyElem.ithChildren(0).next())
                    def valueElem = valueNode.ithChildren(1).next()
                    def start = new HashSet<Boolean>()
                    start.add(true)
                    def value = statementToString(valueElem.ithChildren(0).next(), start, new HashMap<String, Integer>(), new HashSet<String>(), sanitizations)
                    if (value == "") {
                        value = "''"
                    }
                    if (valueElem.ithChildren(0).next().type == "string") {
                        value = "\"" + value + "\""
                    }
                    ret.add(key)
                    ret.add(value)
                    def bindSql = originalSql.replace(key, value)
                    if (bindSql != originalSql) {
                        bindSql = patchSql(bindSql, table_prefix, table_prefix_func, table_prefix_array)
                        query_nodes.add(bindArrayNode)
                        query_sqls.add(bindSql)
                        combine_index.add(true)
                        combineNodes.add(bindArrayNode)
                        query_nodes.add(node)
                        query_sqls.add(bindSql)
                        combine_index.add(true)
                        ret.add("new bindSql")
                        ret.add(bindSql)
                        System.out.println("new bindSql")
                        System.out.println(bindSql)
                    }
                    else {
                        ret.add("originalSql")
                        ret.add(bindSql)
                    }
                }
            }
            for (v in bindArrayNode.in("REACHES")) {
                findAllBindArray(v, bindParam, originalSql, query_nodes, query_sqls, combine_index, combineNodes, node, table_prefix, table_prefix_func, table_prefix_array, sanitizations, visited, ret)
            }
        }
    }
}

def getColumnValuesFromArray(columnNode, sanitizations) {
    def columnValuesList = new ArrayList<AbstractMap.SimpleEntry<String, String>>()
    def paramNum = columnNode.numChildren().next()
    for (int i = 0; i < paramNum; ++i) {
        def elem = columnNode.ithChildren(i).next()
        def start = new HashSet<Boolean>()
        start.add(true)
        def value = statementToString(elem.ithChildren(0).next(), start, new HashMap<String, Integer>(), new HashSet<String>(), sanitizations)
        if (value == "") {
            value = "''"
        }
        if (elem.ithChildren(0).next().type == "string") {
            value = "\"" + value + "\""
        }
        if (isCallExpression(elem.ithChildren(0).next())) {
            value = value.replaceAll(/(([^'"\/])(\$[\w]+\[[\w]+\])([^'"\/]))/, '$2\'$3\'$4')
            value = value.replaceAll(/(([^'"\/])(\%\$[\w]+\%)([^'"\/]))/, '$2\'$3\'$4')
            value = value.replaceAll(/(([^'"\/])(\$[\w]+->[\w]+)([^'"\/]))/, '$2\'$3\'$4')
            value = "\"" + value + "\""
        }
        def key = getAllValName(elem.ithChildren(1).next())
        columnValuesList.add(new AbstractMap.SimpleEntry<String, String>(key, value))
    }
    return columnValuesList
}

def getColumnValuesFromCall(columnNode, sanitizations) {
    def columnValuesList = new ArrayList<AbstractMap.SimpleEntry<String, String>>()
    def argsNum = columnNode.numArguments().next()
    for (int i = 0; i < argsNum; ++i) {
        def arg = columnNode.ithArguments(i).next()
        def start = new HashSet<Boolean>()
        start.add(true)
        def value = statementToString(arg, start, new HashMap<String, Integer>(), new HashSet<String>(), sanitizations)
        if (value == "") {
            value = "''"
        }
        columnValuesList.add(new AbstractMap.SimpleEntry<String, String>(value, "\$"+value))
    }
    return columnValuesList
}

def findClassAndKey(node, obj, classKeyMap, sanitizations, ret) {
    def start = new HashSet<Boolean>()
    start.add(true)
    for (v in node.in("REACHES")) {
        if (v.type == "AST_ASSIGN") {
            def assignName = getAllValName(v.ithChildren(0).next())
            if (assignName == obj) {
                def valueNode = v.ithChildren(1).next()
                if (valueNode.type == "AST_NEW") {
                    def className = getAllValName(valueNode.ithChildren(0).next())
                    def count = valueNode.numArguments().next()
                    def hasKey = false
                    for (u in v.out("REACHES")) {
                        if (u.type == "AST_METHOD_CALL") {
                            def methodName = getFuncName(u)
                        }
                    }
                    if (!hasKey && count == 2) {
                        def key = getAllValName(valueNode.ithArguments(1).next())
                        def keyNodes = new HashSet()
                        keyNodes.add(v)
                        classKeyMap.put(className + " " + key, keyNodes)
                    }
                    else if (!hasKey && count == 1) {
                        def keyNodes = new HashSet()
                        keyNodes.add(v)
                        classKeyMap.put(className + " 0", keyNodes)
                    }
                }
            }
        }
    }
}

def getTableForAdmidio(className) {
    def table = className
    if (table.startsWith("Table")) {
        table = table.substring(5)
    }
    def tables = table.split("(?<!^)(?=[A-Z])")
    table = "TBL"
    for (t in tables) {
        table += "_"+t.toUpperCase()
    }
    if (QueryProcessing.tables.containsKey(table) || QueryProcessing.tables.containsKey(table+"S") || QueryProcessing.tables.containsKey(table.substring(0, table.length()-1)+"IES")) {
        if (QueryProcessing.tables.containsKey(table + "S")) {
            table = table + "S"
        }
        else if (QueryProcessing.tables.containsKey(table.substring(0, table.length()-1)+"IES")) {
            table = table.substring(0, table.length()-1)+"IES"
        }
        return table
    }
    return ""
}

def parseQuery(create_table_items, hasCodeNodes, hasTypeNodes, sql_prepare_funcs, sql_bind_funcs, sql_execute_funcs, queryIndex, sanitizations, nodes, funcsOfNodes, sql_querys, combine_sql_index, combineNodeMap, table_prefix, table_prefix_func, table_prefix_array, excludeDirs, excludeFiles, callerDTableMaps, dynamicTableNodeMaps, isWP, isDAL, dal_sql_query_funcs, dal_sql_fetch_funcs, dal_sql_bind_funcs, dal_sql_execute_funcs, ret) {
    def query_index = 0

    if (create_table_items != '') {
        def create_table_items_file = new File(create_table_items)
        create_table_items_file.eachLine {
            QueryProcessing.ParseQuery(patchSql(it, table_prefix, table_prefix_func, table_prefix_array))
            if (QueryProcessing.querys.size() > query_index) {
                query_index = QueryProcessing.querys.size()
                nodes.add(it)
                funcsOfNodes.add(new HashSet<>())
                sql_querys.add(it)
                combine_sql_index.add(false)
            }
            else {
                ret.add("parse create_table_items error")
                ret.add(it)
            }
        }
    }

    def queryNodes = new HashMap<String, ArrayList<Vertex>>()

    def sqlKeywords = new HashMap<String, String>()
    sqlKeywords.put("create", "CREATE TABLE")
    sqlKeywords.put("select", "SELECT ")
    sqlKeywords.put("insert", "INSERT INTO ")
    sqlKeywords.put("delete", "DELETE FROM ")
    sqlKeywords.put("update", "UPDATE ")

    for (hasCodeNode in hasCodeNodes) {
        def code = hasCodeNode.code
        if (code.startsWith("\\n")) {
            code = code.substring(2)
        }
        code = code.replaceAll("^\\s+", "")
        def first15code = code.substring(0, Math.min(code.length(), 15)).toUpperCase()
        for (sqlType in sqlKeywords.keySet()) {
            def statementNodes = new ArrayList<Vertex>()
            if (queryNodes.containsKey(sqlType)) {
                statementNodes = queryNodes.get(sqlType)
            }
            def keyword = sqlKeywords.get(sqlType)
            if (first15code.startsWith(keyword)) {
                statementNodes.add(hasCodeNode.statements().next())
            }
            queryNodes.put(sqlType, statementNodes)
        }
    }

    def sqlTypes = ["create", "select", "insert", "delete", "update"]

    for (sqlType in sqlTypes) {
        def sql_query_statements = queryNodes.get(sqlType)
        for (node in sql_query_statements) {
            def nodeLocation = node.toFileAbs().next().name + ":" + node.lineno
            def isExclude = false
            if (sqlType != "create") {
                for (excludeDir in excludeDirs) {
                    if (nodeLocation.indexOf('/' + excludeDir + '/') != -1) {
                        isExclude = true
                    }
                }
                for (excludeFile in excludeFiles) {
                    if (nodeLocation.indexOf(excludeFile + ':') != -1) {
                        isExclude = true
                    }
                }
                if (isExclude) {
                    continue
                }
            }
            def funcs = new HashSet<>()
            def originalSql = statementToString(node, new HashSet<>(), queryIndex, funcs, sanitizations)
            def sql = originalSql
            def query_nodes = []
            def query_sqls = []
            def combine_index = []
            def combineNodes = new HashSet<>()
            combineNodes.add(node)


            System.out.println("isStringLikeNode begin "+getLocation(node))
            if (node.type == "AST_ASSIGN") {
                def assignName = getAllValName(node.ithChildren(0).next())
                if (assignName != "") {
                    def valueNode = node.ithChildren(1).next()
                    if (isStringLikeNode(valueNode)) {
                        def value = statementToString(valueNode, new HashSet<>(), queryIndex, new HashSet<>(), sanitizations)
                        def useValMap = new HashMap<String, ArrayList<AbstractMap.SimpleEntry<Vertex, String>>>()
                        def nodeUseValMap = new HashMap<Vertex, HashMap<String, ArrayList<AbstractMap.SimpleEntry<Vertex, String>>>>()
                        if (value != "") {
                            useValMap.put(assignName, new ArrayList<AbstractMap.SimpleEntry<Vertex, String>>())
                            useValMap.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(node, value))
                        }
                        getAllUseValue(node, assignName, useValMap, nodeUseValMap, sanitizations, new HashSet<>(), ret)
                        def postValue = ""
                        for (elem in useValMap.get(assignName)) {
                            def vNode = elem.getKey()
                            if (vNode != node) {
                                postValue = elem.getValue()
                            }
                        }
                        if (postValue != "") {
                            useValMap.get(assignName).add(new AbstractMap.SimpleEntry<Vertex, String>(node, postValue))
                            ret.add("valueNode_op_post:  " + getLocation(valueNode) + "  " + postValue)
                        }
                        def useVals = useValMap.get(assignName)
                        def nodeSql = originalSql
                        for (useVal in useVals) {
                            def useNode = useVal.getKey()
                            def useSql = useVal.getValue()
                            if (useSql != nodeSql) {
                                useSql = patchSql(useSql, table_prefix, table_prefix_func, table_prefix_array)
                                query_nodes.add(useNode)
                                query_sqls.add(useSql)
                                combine_index.add(true)
                                combineNodes.add(useNode)
                                if (useNode == node) {
                                    originalSql = useSql
                                    sql = originalSql
                                }
                            }
                        }
                    }
                }
            }
            System.out.println("isStringLikeNode end")

            def upperSql = originalSql.toUpperCase()
            if (sqlType == "select") {
                if (upperSql.indexOf("FROM ") == -1 && upperSql.indexOf("FROM\\") == -1 && !upperSql.startsWith("AST_")) {
                    continue
                }
            }
            if (sqlType == "insert") {
                if (upperSql.indexOf("VALUES ") == -1 && upperSql.indexOf("VALUES(") == -1 && upperSql.indexOf("VALUES\\") == -1 && upperSql.indexOf("SET ") == -1 && upperSql.indexOf("SET\\") == -1 && !upperSql.startsWith("AST_")) {
                    continue
                }
            }
            if (sqlType == "update") {
                if (upperSql.indexOf("SET ") == -1 && upperSql.indexOf("SET\\") == -1 && !upperSql.startsWith("AST_")) {
                    continue
                }
            }
            if (upperSql.startsWith("ARRAY(")) {
                continue
            }

            def defValMap = new HashMap<String, ArrayList<AbstractMap.SimpleEntry<Vertex, String>>>()
            System.out.println("getAllDefValue begin")
            getAllDefValue(node, "", defValMap, sanitizations, new HashSet<>(), ret)
            System.out.println("getAllDefValue end")

            for (key in defValMap.keySet()) {
                def defVals = defValMap.get(key)
                for (defVal in defVals) {
                    def defNode = defVal.getKey()
                    def defValue = defVal.getValue()
                    def combineSql = originalSql.replace(key, defValue)
                    sql = sql.replace(key, ' ')
                    if (combineSql != originalSql) {
                        combineSql = patchSql(combineSql, table_prefix, table_prefix_func, table_prefix_array)
                        combineNodes.add(defNode)
                        query_nodes.add(node)
                        query_sqls.add(combineSql)
                        combine_index.add(true)
                    }
                }
            }
            if (sql != originalSql) {
                query_nodes.add(node)
                query_sqls.add(patchSql(sql, table_prefix, table_prefix_func, table_prefix_array))
                combine_index.add(true)
            }

            def prePareNodes = []
            def dalBindNodes = []
            def dalExecuteNodes = []
            def inSqlPrepare = false
            for (func in funcs) {
                if (sql_prepare_funcs.contains(func)) {
                    inSqlPrepare = true
                    prePareNodes.add(node)
                }
            }
            if (!inSqlPrepare) {
                for (v in node.out("REACHES")) {
                    if (v.type == "AST_ASSIGN") {
                        def newFuncs = new HashSet<>()
                        statementToString(v, new HashSet<>(), queryIndex, newFuncs, sanitizations)
                        for (func in newFuncs) {
                            if (sql_prepare_funcs.contains(func)) {
                                inSqlPrepare = true
                                prePareNodes.add(v)
                            }
                            if (isDAL && dal_sql_execute_funcs.contains(func)) {
                                dalExecuteNodes.add(v)
                            }
                        }
                    }
                    else if (v.type == "AST_METHOD_CALL") {
                        def funcName = getFuncName(v)
                        if (isDAL && dal_sql_bind_funcs.contains(funcName)) {
                            dalBindNodes.add(v)
                        }
                        if (isDAL && dal_sql_execute_funcs.contains(funcName)) {
                            dalExecuteNodes.add(v)
                        }
                    }
                }
            }
            System.out.println("prePareNode begin")
            for (prePareNode in prePareNodes) {
                for (v in prePareNode.out("REACHES")) {
                    def newFuncs = new HashSet<>()
                    statementToString(v, new HashSet<>(), queryIndex, newFuncs, sanitizations)
                    for (func in newFuncs) {
                        if (sql_bind_funcs.contains(func)) {
                            if (v.type == "AST_METHOD_CALL") {
                                ret.add("sql_bind_funcs")
                                ret.add(getLocation(v))
                                argsNum = v.numArguments().next()
                                def firstarg = getAllValName(v.ithArguments(0).next())
                                if (firstarg.startsWith(":")) {
                                    if (argsNum >= 2) {
                                        key = getAllValName(v.ithArguments(0).next())
                                        value = getAllValName(v.ithArguments(1).next())
                                        if (value == "") {
                                            value = "''"
                                        }
                                        def bindSql = originalSql.replace(key, value)
                                        bindSql = patchSql(bindSql, table_prefix, table_prefix_func, table_prefix_array)
                                        query_nodes.add(v)
                                        query_sqls.add(bindSql)
                                        combine_index.add(true)
                                        combineNodes.add(v)
                                        query_nodes.add(node)
                                        query_sqls.add(bindSql)
                                        combine_index.add(true)
                                        ret.add(bindSql)
                                    }
                                    else {
                                        ret.add("argsNum < 2")
                                        ret.add(getLocation(v))
                                    }
                                }
                                else {
                                    def indexOfPlaceholder = -1
                                    def bindSql = originalSql
                                    for (int i = 1; i < argsNum; ++i) {
                                        def param = v.ithArguments(i).next()
                                        def value = getAllValName(param)
                                        if (value == "") {
                                            value = "''"
                                        }
                                        indexOfPlaceholder = bindSql.indexOf('?', indexOfPlaceholder + 1)
                                        if (indexOfPlaceholder != -1) {
                                            bindSql = bindSql.substring(0, indexOfPlaceholder) + value + bindSql.substring(indexOfPlaceholder + 1)
                                        }
                                        else {
                                            System.out.println("indexOfPlaceholder == -1")
                                            System.out.println(originalSql)
                                        }
                                    }
                                    if (bindSql != originalSql) {
                                        bindSql = patchSql(bindSql, table_prefix, table_prefix_func, table_prefix_array)
                                        query_nodes.add(v)
                                        query_sqls.add(bindSql)
                                        combine_index.add(true)
                                        combineNodes.add(v)
                                        query_nodes.add(node)
                                        query_sqls.add(bindSql)
                                        combine_index.add(true)
                                        ret.add(bindSql)
                                    }
                                    else {
                                        ret.add("originalSql")
                                        ret.add(bindSql)
                                    }
                                }
                            }
                            else {
                                ret.add("bind_funcs not method call")
                                ret.add(getLocation(v))
                            }
                        }
                        else if (sql_execute_funcs.contains(func)) {
                            def statementOfExecute = v
                            if (v.type == "AST_RETURN") {
                                v = v.ithChildren(0).next()
                            }
                            if (v.type == "AST_ASSIGN") {
                                v = v.ithChildren(1).next()
                            }
                            if (v.type == "AST_METHOD_CALL") {
                                ret.add("sql_execute_funcs")
                                ret.add(getLocation(v))
                                def argsNum = v.numArguments().next()
                                if (argsNum > 0) {
                                    def param = v.ithArguments(0).next()
                                    if (param.type == "AST_ARRAY") {
                                        def childrenNum = param.numChildren().next()
                                        def indexOfPlaceholder = -1
                                        def bindSql = originalSql
                                        for (int i = 0; i < childrenNum; ++i) {
                                            def arrayElem = param.ithChildren(i).next()
                                            def key = getAllValName(arrayElem.ithChildren(1).next())
                                            def value = getAllValName(arrayElem.ithChildren(0).next())
                                            if (value == "") {
                                                value = "''"
                                            }
                                            if (key != "") {
                                                bindSql = bindSql.replace(key, value)
                                            }
                                            else {
                                                indexOfPlaceholder = bindSql.indexOf('?', indexOfPlaceholder + 1)
                                                if (indexOfPlaceholder != -1) {
                                                    bindSql = bindSql.substring(0, indexOfPlaceholder) + value + bindSql.substring(indexOfPlaceholder + 1)
                                                }
                                                else {
                                                    System.out.println("indexOfPlaceholder == -1")
                                                    System.out.println(originalSql)
                                                }
                                            }
                                        }
                                        if (bindSql != originalSql) {
                                            bindSql = patchSql(bindSql, table_prefix, table_prefix_func, table_prefix_array)
                                            query_nodes.add(statementOfExecute)
                                            query_sqls.add(bindSql)
                                            combine_index.add(true)
                                            combineNodes.add(statementOfExecute)
                                            query_nodes.add(node)
                                            query_sqls.add(bindSql)
                                            combine_index.add(true)
                                            ret.add("new bindSql")
                                            ret.add(bindSql)
                                            System.out.println("new bindSql")
                                            System.out.println(bindSql)
                                        }
                                        else {
                                            ret.add("originalSql")
                                            ret.add(bindSql)
                                        }
                                    }
                                    else {
                                        ret.add("param is not array")
                                        ret.add(getLocation(v))
                                    }
                                }
                                else {
                                    ret.add("argsNum < 1")
                                    ret.add(getLocation(v))
                                }
                            }
                            else {
                                ret.add("execute_funcs not method call")
                                ret.add(getLocation(v))
                            }
                        }
                        else {

                        }
                    }
                }
            }
            System.out.println("prePareNode end")

            for (dalBindNode in dalBindNodes) {
                def argsNum = dalBindNode.numArguments().next()
                if (argsNum < 2) {
                    ret.add("argsNum < 2")
                    ret.add(getLocation(dalBindNode))
                    continue
                }
                def bindParam = getAllValName(dalBindNode.ithArguments(1).next())
                if (bindParam.startsWith("\$")) {
                    for (v in dalBindNode.in("REACHES")) {
                        if (v.type == "AST_ASSIGN") {
                            def assignName = getAllValName(v.ithChildren(0).next())

                            def valueNode = v.ithChildren(1).next()

                            if (assignName == bindParam) {
                                if (valueNode.type == "AST_ARRAY") {
                                    def paramNum = valueNode.numChildren().next()
                                    if (paramNum == 0) {
                                        ret.add("paramNum == 0")
                                        ret.add(getLocation(valueNode))
                                    }
                                    else {
                                        def bindSql = originalSql
                                        for (int i = 0; i < paramNum; ++i) {
                                            def paramElem = valueNode.ithChildren(i).next().ithChildren(0).next()
                                            if (paramElem.type == "AST_ARRAY") {
                                                if (paramElem.numChildren().next() < 2) {
                                                    ret.add("paramElem.numChildren().next() < 2")
                                                    ret.add(getLocation(paramElem))
                                                }
                                                else {
                                                    def keyElem = paramElem.ithChildren(0).next()
                                                    def key = getAllValName(keyElem.ithChildren(0).next())
                                                    def valueElem = paramElem.ithChildren(1).next()
                                                    def start = new HashSet<Boolean>()
                                                    start.add(true)
                                                    def value = statementToString(valueElem.ithChildren(0).next(), start, new HashMap<String, Integer>(), new HashSet<String>(), sanitizations)
                                                    if (value == "") {
                                                        value = "''"
                                                    }
                                                    if (valueElem.ithChildren(0).next().type == "string") {
                                                        value = "\"" + value + "\""
                                                    }
                                                    ret.add(key)
                                                    ret.add(value)
                                                    bindSql = bindSql.replace(key, value)
                                                }
                                            }
                                        }
                                        if (bindSql != originalSql) {
                                            bindSql = patchSql(bindSql, table_prefix, table_prefix_func, table_prefix_array)
                                            query_nodes.add(v)
                                            query_sqls.add(bindSql)
                                            combine_index.add(true)
                                            combineNodes.add(v)
                                            query_nodes.add(node)
                                            query_sqls.add(bindSql)
                                            combine_index.add(true)
                                            ret.add("new bindSql")
                                            ret.add(bindSql)
                                            System.out.println("new bindSql")
                                            System.out.println(bindSql)
                                        }
                                        else {
                                            ret.add("originalSql")
                                            ret.add(bindSql)
                                        }
                                        if (sql != originalSql) {
                                            bindSql = sql
                                            for (int i = 0; i < paramNum; ++i) {
                                                def paramElem = valueNode.ithChildren(i).next().ithChildren(0).next()
                                                if (paramElem.type == "AST_ARRAY") {
                                                    if (paramElem.numChildren().next() < 2) {
                                                        ret.add("paramElem.numChildren().next() < 2")
                                                        ret.add(getLocation(paramElem))
                                                    } else {
                                                        def keyElem = paramElem.ithChildren(0).next()
                                                        def key = getAllValName(keyElem.ithChildren(0).next())
                                                        def valueElem = paramElem.ithChildren(1).next()
                                                        def start = new HashSet<Boolean>()
                                                        start.add(true)
                                                        def value = statementToString(valueElem.ithChildren(0).next(), start, new HashMap<String, Integer>(), new HashSet<String>(), sanitizations)
                                                        if (value == "") {
                                                            value = "''"
                                                        }
                                                        if (valueElem.ithChildren(0).next().type == "string") {
                                                            value = "\"" + value + "\""
                                                        }
                                                        ret.add(key)
                                                        ret.add(value)
                                                        bindSql = bindSql.replace(key, value)
                                                    }
                                                }
                                            }
                                            if (bindSql != sql) {
                                                bindSql = patchSql(bindSql, table_prefix, table_prefix_func, table_prefix_array)
                                                query_nodes.add(v)
                                                query_sqls.add(bindSql)
                                                combine_index.add(true)
                                                combineNodes.add(v)
                                                query_nodes.add(node)
                                                query_sqls.add(bindSql)
                                                combine_index.add(true)
                                                ret.add("new bindSql")
                                                ret.add(bindSql)
                                                System.out.println("new bindSql")
                                                System.out.println(bindSql)
                                            }
                                            else {
                                                ret.add("sql")
                                                ret.add(sql)
                                            }
                                        }
                                    }
                                }
                            }
                            else if (assignName == bindParam + "[]") {
                                if (valueNode.type == "AST_ARRAY") {
                                    findAllBindArray(v, bindParam, originalSql, query_nodes, query_sqls, combine_index, combineNodes, node, table_prefix, table_prefix_func, table_prefix_array, sanitizations, new HashSet<>(), ret)
                                }
                            }
                        }
                    }
                }
                else {

                }
            }

            System.out.println("dalBindNode end")

            for (dalExecuteNode in dalExecuteNodes) {
                def dalExecuteStatement = dalExecuteNode
                if (dalExecuteNode.type == "AST_ASSIGN") {
                    dalExecuteNode = dalExecuteNode.ithChildren(1).next()
                }
                if (dalExecuteNode.type == "AST_METHOD_CALL") {
                    ret.add("dalExecuteNode")
                    ret.add(getLocation(dalExecuteNode))
                    def argsNum = dalExecuteNode.numArguments().next()
                    if (argsNum > 1) {
                        def param = dalExecuteNode.ithArguments(1).next()
                        if (param.type == "AST_ARRAY") {
                            def childrenNum = param.numChildren().next()
                            def indexOfPlaceholder = -1
                            def bindSql = originalSql
                            for (int i = 0; i < childrenNum; ++i) {
                                def arrayElem = param.ithChildren(i).next()
                                def start = new HashSet<Boolean>()
                                start.add(true)
                                def value = statementToString(arrayElem.ithChildren(0).next(), start, new HashMap<String, Integer>(), new HashSet<String>(), sanitizations)
                                if (value == "") {
                                    value = "''"
                                }
                                if (arrayElem.ithChildren(0).next().type == "string") {
                                    value = "\"" + value + "\""
                                }

                                indexOfPlaceholder = bindSql.indexOf('?', indexOfPlaceholder + 1)
                                if (indexOfPlaceholder != -1) {
                                    bindSql = bindSql.substring(0, indexOfPlaceholder) + value + bindSql.substring(indexOfPlaceholder + 1)
                                }
                                else {
                                    System.out.println("indexOfPlaceholder == -1")
                                    System.out.println(originalSql)
                                }
                            }
                            if (bindSql != originalSql) {
                                bindSql = patchSql(bindSql, table_prefix, table_prefix_func, table_prefix_array)
                                query_nodes.add(dalExecuteStatement)
                                query_sqls.add(bindSql)
                                combine_index.add(true)
                                combineNodes.add(dalExecuteStatement)
                                query_nodes.add(node)
                                query_sqls.add(bindSql)
                                combine_index.add(true)
                                ret.add("new bindSql")
                                ret.add(bindSql)
                                System.out.println("new bindSql")
                                System.out.println(bindSql)
                            }
                            else {
                                ret.add("originalSql")
                                ret.add(bindSql)
                            }
                        }
                        else {
                            ret.add("param is not array")
                            ret.add(getLocation(dalExecuteNode))
                        }
                    }
                    else {
                        ret.add("argsNum < 2")
                        ret.add(getLocation(dalExecuteNode))
                    }
                }
            }

            System.out.println("dalExecuteNode end")

            if (originalSql.contains("?")) {
                for (v in node.out("REACHES")) {
                    if (v.type == "AST_CALL" || v.type == "AST_METHOD_CALL") {
                        def funcName = getFuncName(v)
                    }
                }
            }

            originalSql = patchSql(originalSql, table_prefix, table_prefix_func, table_prefix_array)
            query_nodes.add(node)
            query_sqls.add(originalSql)
            combine_index.add(false)
            combineNodeMap.put(node.id, combineNodes)

            def isDynamicTable = false
            def dynamicTable = ""
            for (int i = 0; i < query_sqls.size(); ++i) {
                sql = query_sqls[i]
                def sql_node = query_nodes[i]
                try {
                    QueryProcessing.ParseQuery(sql)
                }
                catch (e) {
                    ret.add(sql)
                    ret.add(e)
                }

                if (QueryProcessing.querys.size() > query_index) {
                    def query_info = QueryProcessing.querys.get(query_index)
                    def tables = query_info.getTNames()
                    if (tables.size() == 1) {
                        if (tables[0].startsWith("\$")) {
                            isDynamicTable = true
                            ret.add("table "+ tables[0] + " is dynamic in "+sql)
                            ret.add(getLocation(sql_node))
                            dynamicTable = tables[0]
                            break
                        }
                    }
                    query_index = QueryProcessing.querys.size()
                    sql_node = getStatement(sql_node)
                    nodes.add(sql_node)
                    funcsOfNodes.add(funcs)
                    sql_querys.add(sql.replaceAll("^\\s+", ""))
                    combine_sql_index.add(combine_index[i])
                }
                else {
                    if (sql.toUpperCase().startsWith("CREATE TABLE")) {
                        System.out.println("create same table")
                        ret.add("create same table")
                        ret.add(sql)
                    }
                    else {
                        System.out.println("parse error at " + getLocation(sql_node))
                        ret.add("parse error at " + getLocation(sql_node))
                        ret.add("sql is " + sql)
                    }
                }
            }

            System.out.println("dynamicTable is "+dynamicTable)

            if (isDynamicTable) {
                QueryProcessing.querys.remove(query_index)
                ret.add("******************isDynamicTable******************")
                ret.add(getLocation(node))
                ret.add(dynamicTable)
                if (!isWP) {
                    def callerDTableMap = getValForDynamicTable(node, dynamicTable, ret)
                    def callerDTables = new HashSet<String>()
                    for (caller in callerDTableMap.keySet()) {
                        callerDTables.add(callerDTableMap.get(caller))
                    }
                    for (caller in callerDTableMap.keySet()) {
                        def callerDTable = callerDTableMap.get(caller)
                        callerDTableMaps.put(caller, callerDTable)
                        ret.add(callerDTable)
                        for (i = 0; i < query_sqls.size(); ++i) {
                            sql = query_sqls[i]
                            def sql_node = query_nodes[i]
                            sql = sql.replace(dynamicTable, callerDTable)
                            sql = patchSql(sql, table_prefix, table_prefix_func, table_prefix_array)
                            ret.add(sql)
                            try {
                                QueryProcessing.ParseQuery(sql)
                            }
                            catch (e) {
                                ret.add(sql)
                                ret.add(e)
                            }

                            if (QueryProcessing.querys.size() > query_index) {
                                query_index = QueryProcessing.querys.size()
                                sql_node = getStatement(sql_node)
                                nodes.add(sql_node)
                                dynamicTableNodeMaps.put(sql_node, callerDTables)
                                funcsOfNodes.add(funcs)
                                sql_querys.add(sql.replaceAll("^\\s+", ""))
                                combine_sql_index.add(combine_index[i])
                            }
                            else {
                                System.out.println("parse error at " + getLocation(sql_node))
                                ret.add("parse error at " + getLocation(sql_node))
                            }
                        }
                    }
                }
            }
        }
    }

    if (isDAL) {
        for (hasTypeNode in hasTypeNodes) {
            def nodeLocation = hasTypeNode.toFileAbs().next().name + ":" + hasTypeNode.lineno
            def isExclude = false
            for (excludeDir in excludeDirs) {
                if (nodeLocation.indexOf('/' + excludeDir + '/') != -1) {
                    isExclude = true
                }
            }
            for (excludeFile in excludeFiles) {
                if (nodeLocation.indexOf(excludeFile + ':') != -1) {
                    isExclude = true
                }
            }
            if (isExclude) {
                continue
            }
            def type = hasTypeNode.type
            def query_nodes = []
            def query_sqls = []
            def combine_index = []
            def funcs = new HashSet<>()

            if (type == "AST_METHOD_CALL") {
                def statement = getStatement(hasTypeNode)
                if (statement.type == "AST_ASSIGN") {
                    def valueNode = statement.ithChildren(1).next()
                    if (valueNode.type == "AST_METHOD_CALL") {
                        def obj = getAllValName(valueNode.ithChildren(0).next())
                        def funcName = getFuncName(valueNode)
                        ret.add("funcName is "+funcName)
                    }
                }
                def obj = getAllValName(hasTypeNode.ithChildren(0).next())
                def funcName = getFuncName(hasTypeNode)
            }

            for (int i = 0; i < query_sqls.size(); ++i) {
                def sql = query_sqls[i]
                def sql_node = query_nodes[i]
                try {
                    QueryProcessing.ParseQuery(sql)
                }
                catch (e) {
                    ret.add(sql)
                    ret.add(e)
                }

                if (QueryProcessing.querys.size() > query_index) {
                    def query_info = QueryProcessing.querys.get(query_index)
                    query_index = QueryProcessing.querys.size()
                    sql_node = getStatement(sql_node)
                    nodes.add(sql_node)
                    funcsOfNodes.add(funcs)
                    sql_querys.add(sql.replaceAll("^\\s+", ""))
                    combine_sql_index.add(combine_index[i])
                }
                else {
                    System.out.println("parse error at " + getLocation(sql_node))
                    ret.add("parse error at " + getLocation(sql_node))
                    ret.add("sql is " + sql)
                }
            }
        }
    }

    for (hasTypeNode in hasTypeNodes) {
        def nodeLocation = hasTypeNode.toFileAbs().next().name + ":" + hasTypeNode.lineno
        def isExclude = false
        for (excludeDir in excludeDirs) {
            if (nodeLocation.indexOf('/' + excludeDir + '/') != -1) {
                isExclude = true
            }
        }
        for (excludeFile in excludeFiles) {
            if (nodeLocation.indexOf(excludeFile + ':') != -1) {
                isExclude = true
            }
        }
        if (isExclude) {
            continue
        }
        def type = hasTypeNode.type
        def query_nodes = []
        def query_sqls = []
        def combine_index = []
        def funcs = new HashSet<>()

        if (type == "AST_METHOD_CALL") {
            def statement = getStatement(hasTypeNode)
            def obj = getAllValName(hasTypeNode.ithChildren(0).next())
        }
        else if (type == "AST_STATIC_CALL") {
            def className = getAllValName(hasTypeNode.ithChildren(0).next())
        }
        else if (type == "AST_CALL") {
            def funcName = getFuncName(hasTypeNode)
        }

        for (int i = 0; i < query_sqls.size(); ++i) {
            def sql = query_sqls[i]
            def sql_node = query_nodes[i]
            try {
                QueryProcessing.ParseQuery(sql)
            }
            catch (e) {
                ret.add(sql)
                ret.add(e)
            }

            if (QueryProcessing.querys.size() > query_index) {
                def query_info = QueryProcessing.querys.get(query_index)
                query_index = QueryProcessing.querys.size()
                sql_node = getStatement(sql_node)
                nodes.add(sql_node)
                funcsOfNodes.add(funcs)
                sql_querys.add(sql.replaceAll("^\\s+", ""))
                combine_sql_index.add(combine_index[i])
            }
            else {
                System.out.println("parse error at " + getLocation(sql_node))
                ret.add("parse error at " + getLocation(sql_node))
                ret.add("sql is " + sql)
            }
        }
    }
}

def setSqlNumRows(node, nodes, index, sql_num_rows_funcs, sqlNumRowsMap, controlNodes, visitedNodes, ret) {
    if (visitedNodes.contains(node)) {
        return
    }
    visitedNodes.add(node)
    for (v in node.out("REACHES")) {
        if (nodes.contains(v)) {
            ret.add("nodes contains v in setSqlNumRows")
            continue
        }
        def location = v.toFileAbs().next().name + ":" + v.lineno
        if (v.type == "AST_ASSIGN") {
            if (v.ithChildren(1).next().type == "AST_CALL" || v.ithChildren(1).next().type == "AST_METHOD_CALL") {
                def funcName = getFuncName(v.ithChildren(1).next())
                if (sql_num_rows_funcs.contains(funcName)) {
                    def assignName = getAllValName(v.ithChildren(0).next())
                    assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                    if (assignName.startsWith("\$")) {
                        def sqlNumRowsIndex = new HashSet<Integer>()
                        if (sqlNumRowsMap.containsKey(location + " " + assignName)) {
                            sqlNumRowsIndex.addAll(sqlNumRowsMap.get(location + " " + assignName))
                        }
                        sqlNumRowsIndex.add(index)
                        sqlNumRowsMap.put(location + " " + assignName, sqlNumRowsIndex)
                    }
                    else {
                        ret.add("assignName is not val in setSqlNumRows")
                        ret.add(location + " " + assignName)
                    }
                }
            }
        }
        else if (v.type == "AST_BINARY_OP" && v.flags != null) {
            if (v.get_calls()) {
                def caller = v.get_calls().next()
                if (caller != null) {
                    def funcName = getFuncName(caller)
                    if (sql_num_rows_funcs.contains(funcName)) {
                        def sqlNumRowsIndex = new HashSet<Integer>()
                        if (sqlNumRowsMap.containsKey(location + " " + funcName)) {
                            sqlNumRowsIndex.addAll(sqlNumRowsMap.get(location + " " + funcName))
                        }
                        sqlNumRowsIndex.add(index)
                        sqlNumRowsMap.put(location + " " + funcName, sqlNumRowsIndex)
                    }
                }
            }
        }
        if (v.lineno > node.lineno) {
            setSqlNumRows(v, nodes, index, sql_num_rows_funcs, sqlNumRowsMap, controlNodes, visitedNodes, ret)
        }
    }
}

def setDalFetchAndNumRows(node, nodes, index, sensitive_index, dal_sql_fetch_funcs, dalFetchColumn, dal_sql_num_rows_funcs, sqlNumRowsMap, valTableColumnMap, valTableColumnQueue, sessionTables, controlNodes, visitedNodes, ret) {
    if (visitedNodes.contains(node)) {
        return
    }
    visitedNodes.add(node)
    for (v in node.out("FLOWS_TO")) {
        if (nodes.contains(v)) {
            ret.add("nodes contains v in setDalFetchAndNumRows")
            continue
        }
        def controlNodesOfV = getControlNodes(v, ret)
        def withinSameControl = true
        for (controlNode in controlNodes.keySet()) {
            if (!controlNodesOfV.containsKey(controlNode)) {
                withinSameControl = false
                break
            }
        }
        if (!withinSameControl) {
            ret.add("not withinSameControl in setDalFetchAndNumRows")
            continue
        }
        if (v.type == "CFG_FUNC_EXIT") {
            continue
        }
        def statement = v
        v = getInnerNode(v)
        if (v.type == "AST_ASSIGN") {
            if (v.ithChildren(1).next().type == "AST_CALL" || v.ithChildren(1).next().type == "AST_METHOD_CALL") {
                def funcName = getFuncName(v.ithChildren(1).next())
                def location = v.toFileAbs().next().name + ":" + v.lineno
                if (dal_sql_fetch_funcs.contains(funcName)) {
                    def assignName = getAllValName(v.ithChildren(0).next())

                    def inSqlFetch = true

                    if (assignName.startsWith("\$")) {
                        def assignNameSensitiveIndex = new ArrayList<String>()
                        if (valTableColumnMap.containsKey(location + " " + assignName)) {
                            def newEntry = valTableColumnMap.get(location + " " + assignName)
                            assignNameSensitiveIndex.addAll(newEntry.getValue())
                        }
                        def assignNameSensitiveIndexSize = assignNameSensitiveIndex.size()
                        def needOffer = false
                        for (int i = 0; i < sensitive_index.size(); i += 5) {
                            def hasExisted = false
                            def need = true
                            for (int j = 0; j < assignNameSensitiveIndexSize; j += 5) {
                                if (assignNameSensitiveIndex.get(j).equals(sensitive_index.get(i)) &&
                                        assignNameSensitiveIndex.get(j+1).equals(sensitive_index.get(i+1)) &&
                                        assignNameSensitiveIndex.get(j+2).equals(sensitive_index.get(i+2)) &&
                                        assignNameSensitiveIndex.get(j+3).equals(sensitive_index.get(i+3))
                                ) {
                                    if (assignNameSensitiveIndex.get(j+4).equals(sensitive_index.get(i+4))) {
                                        hasExisted = true
                                        break
                                    }
                                    else {
                                        def table1 = assignNameSensitiveIndex.get(j+4).substring(assignNameSensitiveIndex.get(j+4).indexOf(" ")+1)
                                        def table2 = sensitive_index.get(i+4).substring(sensitive_index.get(i+4).indexOf(" ")+1)
                                        if (table1.equals(table2)) {
                                            hasExisted = true
                                            break
                                        }
                                    }
                                }
                            }
                            needOffer = needOffer || need
                            if (!hasExisted) {
                                assignNameSensitiveIndex.add(sensitive_index.get(i))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+1))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+2))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+3))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+4))
                            }
                        }
                        if (assignNameSensitiveIndex.size() > assignNameSensitiveIndexSize) {
                            valTableColumnMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameSensitiveIndex))
                            if (needOffer) {
                                valTableColumnQueue.offer(location + " " + assignName)
                            }
                            if (assignName.startsWith("\$_SESSION[")) {
                                setValTableColumnForSession(assignName, statement, valTableColumnMap, sessionTables, assignNameSensitiveIndex, assignNameSensitiveIndexSize)
                            }
                            if (inSqlFetch) {
                                for (int i = assignNameSensitiveIndexSize; i < assignNameSensitiveIndex.size(); i += 5) {
                                    def assignNameIndexSensitiveIndex = new ArrayList<String>()
                                    if (valTableColumnMap.containsKey(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]")) {
                                        def newEntry = valTableColumnMap.get(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]")
                                        assignNameIndexSensitiveIndex.addAll(newEntry.getValue())
                                    }
                                    if (assignNameIndexSensitiveIndex.contains(assignNameSensitiveIndex.get(i+4))) {
                                        continue
                                    }
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+1))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+2))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+3))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+4))
                                    valTableColumnMap.put(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    valTableColumnMap.put(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    valTableColumnMap.put(location + " " + assignName + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    if (assignName.startsWith("\$_SESSION[")) {
                                        valTableColumnMap.put(assignName + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    }
                                }
                            }
                        }
                    }
                    else {
                        ret.add("assignName is not val in setDalFetchAndNumRows")
                        ret.add(location + " " + assignName)
                    }
                }
                if (dalFetchColumn.containsKey(funcName)) {
                    def columnIndex = dalFetchColumn.get(funcName)
                    def argsNum = v.ithChildren(1).next().numArguments().next()
                    def columnName = ""
                    if (argsNum > columnIndex) {
                        columnName = getAllValName(v.ithChildren(1).next().ithArguments(columnIndex).next())
                    }
                    def assignName = getAllValName(v.ithChildren(0).next())

                    def inSqlFetch = true
                    if (columnName != "") {
                        inSqlFetch = false
                    }

                    if (assignName.startsWith("\$")) {
                        def assignNameSensitiveIndex = new ArrayList<String>()
                        if (valTableColumnMap.containsKey(location + " " + assignName)) {
                            def newEntry = valTableColumnMap.get(location + " " + assignName)
                            assignNameSensitiveIndex.addAll(newEntry.getValue())
                        }
                        def assignNameSensitiveIndexSize = assignNameSensitiveIndex.size()
                        def needOffer = false
                        for (int i = 0; i < sensitive_index.size(); i += 5) {
                            if (columnName != "" && columnName != sensitive_index.get(i+2)) {
                                continue
                            }
                            def hasExisted = false
                            def need = true
                            for (int j = 0; j < assignNameSensitiveIndexSize; j += 5) {
                                if (assignNameSensitiveIndex.get(j).equals(sensitive_index.get(i)) &&
                                        assignNameSensitiveIndex.get(j+1).equals(sensitive_index.get(i+1)) &&
                                        assignNameSensitiveIndex.get(j+2).equals(sensitive_index.get(i+2)) &&
                                        assignNameSensitiveIndex.get(j+3).equals(sensitive_index.get(i+3))
                                ) {
                                    if (assignNameSensitiveIndex.get(j+4).equals(sensitive_index.get(i+4))) {
                                        hasExisted = true
                                        break
                                    }
                                    else {
                                        def table1 = assignNameSensitiveIndex.get(j+4).substring(assignNameSensitiveIndex.get(j+4).indexOf(" ")+1)
                                        def table2 = sensitive_index.get(i+4).substring(sensitive_index.get(i+4).indexOf(" ")+1)
                                        if (table1.equals(table2)) {
                                            hasExisted = true
                                            break
                                        }
                                    }
                                }
                            }
                            needOffer = needOffer || need
                            if (!hasExisted) {
                                assignNameSensitiveIndex.add(sensitive_index.get(i))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+1))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+2))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+3))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+4))
                            }
                        }
                        if (assignNameSensitiveIndex.size() > assignNameSensitiveIndexSize) {
                            valTableColumnMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameSensitiveIndex))
                            if (needOffer) {
                                valTableColumnQueue.offer(location + " " + assignName)
                            }
                            if (assignName.startsWith("\$_SESSION[")) {
                                setValTableColumnForSession(assignName, statement, valTableColumnMap, sessionTables, assignNameSensitiveIndex, assignNameSensitiveIndexSize)
                            }
                            if (inSqlFetch) {
                                for (int i = assignNameSensitiveIndexSize; i < assignNameSensitiveIndex.size(); i += 5) {
                                    def assignNameIndexSensitiveIndex = new ArrayList<String>()
                                    if (valTableColumnMap.containsKey(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]")) {
                                        def newEntry = valTableColumnMap.get(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]")
                                        assignNameIndexSensitiveIndex.addAll(newEntry.getValue())
                                    }
                                    if (assignNameIndexSensitiveIndex.contains(assignNameSensitiveIndex.get(i+4))) {
                                        continue
                                    }
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+1))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+2))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+3))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+4))
                                    valTableColumnMap.put(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    valTableColumnMap.put(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    valTableColumnMap.put(location + " " + assignName + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    if (assignName.startsWith("\$_SESSION[")) {
                                        valTableColumnMap.put(assignName + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, assignNameIndexSensitiveIndex))
                                    }
                                }
                            }
                        }
                    }
                    else {
                        ret.add("assignName is not val in setDalFetchAndNumRows")
                        ret.add(location + " " + assignName)
                    }
                }
                if (dal_sql_num_rows_funcs.contains(funcName)) {
                    def assignName = getAllValName(v.ithChildren(0).next())

                    if (assignName.startsWith("\$")) {
                        def sqlNumRowsIndex = new HashSet<Integer>()
                        if (sqlNumRowsMap.containsKey(location + " " + assignName)) {
                            sqlNumRowsIndex.addAll(sqlNumRowsMap.get(location + " " + assignName))
                        }
                        sqlNumRowsIndex.add(index)
                        sqlNumRowsMap.put(location + " " + assignName, sqlNumRowsIndex)
                    }
                    else {
                        ret.add("assignName is not val in setDalFetchAndNumRows")
                        ret.add(location + " " + assignName)
                    }
                }
            }
        }
        else if (v.type == "AST_BINARY_OP" && v.flags != null) {
            if (v.get_calls()) {
                def caller = v.get_calls().next()
                def location = v.toFileAbs().next().name + ":" + v.lineno
                if (caller != null) {
                    def funcName = getFuncName(caller)
                    if (dal_sql_num_rows_funcs.contains(funcName)) {
                        def sqlNumRowsIndex = new HashSet<Integer>()
                        if (sqlNumRowsMap.containsKey(location + " " + funcName)) {
                            sqlNumRowsIndex.addAll(sqlNumRowsMap.get(location + " " + funcName))
                        }
                        sqlNumRowsIndex.add(index)
                        sqlNumRowsMap.put(location + " " + funcName, sqlNumRowsIndex)
                    }
                }
            }
        }
        if (v.lineno > node.lineno) {
            setDalFetchAndNumRows(v, nodes, index, sensitive_index, dal_sql_fetch_funcs, dalFetchColumn, dal_sql_num_rows_funcs, sqlNumRowsMap, valTableColumnMap, valTableColumnQueue, sessionTables, controlNodes, visitedNodes, ret)
        }
    }
}

def setDalQuery(node, nodes, index, sensitive_index, dal_sql_query_funcs, dal_sql_fetch_funcs, dalFetchColumn, dal_sql_num_rows_funcs, sqlNumRowsMap, valTableColumnMap, valTableColumnQueue, sessionTables, ret) {
    def dalQueryNodes = new HashSet<Vertex>()
    for (v in node.out("REACHES")) {
        if (v.type == "AST_METHOD_CALL") {
            def funcName = getFuncName(v)
            if (dal_sql_query_funcs.contains(funcName)) {
                dalQueryNodes.add(v)
            }
        }
    }
    for (dalQueryNode in dalQueryNodes) {
        def controlNodes = getControlNodes(dalQueryNode, ret)
        setDalFetchAndNumRows(dalQueryNode, nodes, index, sensitive_index, dal_sql_fetch_funcs, dalFetchColumn, dal_sql_num_rows_funcs, sqlNumRowsMap, valTableColumnMap, valTableColumnQueue, sessionTables, controlNodes, new HashSet<>(), ret)
    }
}

def setInsertId(node, nodes, nodeLocation, sql_insert_id_funcs, table, primaryKey, sessionTables, valTableColumnMap, valTableColumnQueue, controlNodes, visitedNodes, ret) {
    if (visitedNodes.contains(node)) {
        return
    }
    visitedNodes.add(node)
    for (v in node.out("FLOWS_TO")) {
        if (nodes.contains(v)) {
            ret.add("nodes contains v in setInsertId")
            ret.add(getLocation(v))
            continue
        }
        def controlNodesOfV = getControlNodes(v, ret)
        def withinSameControl = true
        for (controlNode in controlNodes.keySet()) {
            if (!controlNodesOfV.containsKey(controlNode)) {
                withinSameControl = false
                break
            }
        }
        if (!withinSameControl) {
            ret.add("not withinSameControl in setInsertId")
            ret.add(getLocation(v))
            continue
        }
        def statement = v
        v = getInnerNode(v)
        if (v.type == "AST_ASSIGN") {
            if (v.ithChildren(1).next().type == "AST_CALL" || v.ithChildren(1).next().type == "AST_METHOD_CALL" || v.ithChildren(1).next().type == "AST_STATIC_CALL") {
                def funcName = getFuncName(v.ithChildren(1).next())
                def location = v.toFileAbs().next().name + ":" + v.lineno
                if (sql_insert_id_funcs.contains(funcName)) {
                    def assignName = getAllValName(v.ithChildren(0).next())
                    assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                    if (assignName.startsWith("\$")) {
                        valTableColumnMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(statement, ["0", table, primaryKey, "true", nodeLocation+" "+table]))
                        valTableColumnQueue.offer(location + " " + assignName)
                        if (assignName.startsWith("\$_SESSION[")) {
                            def assignNameSessionSensitiveIndex = new ArrayList<String>()
                            if (valTableColumnMap.containsKey(assignName)) {
                                def newEntry = valTableColumnMap.get(assignName)
                                assignNameSessionSensitiveIndex.addAll(newEntry.getValue())
                            }
                            if (assignNameSessionSensitiveIndex.contains(nodeLocation+" "+table)) {
                                continue
                            }
                            assignNameSessionSensitiveIndex.add("0")
                            assignNameSessionSensitiveIndex.add(table)
                            assignNameSessionSensitiveIndex.add(primaryKey)
                            assignNameSessionSensitiveIndex.add("true")
                            assignNameSessionSensitiveIndex.add(nodeLocation+" "+table)
                            valTableColumnMap.put(assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameSessionSensitiveIndex))
                            sessionTables.add(table)
                        }
                        ret.add("insertId is " + location + " " + assignName)
                    }
                    else {
                        ret.add("assignName is not val in setInsertId")
                        ret.add(location + " " + assignName)
                    }
                }
            }
        }
        if (v.id > node.id) {
            setInsertId(v, nodes, nodeLocation, sql_insert_id_funcs, table, primaryKey, sessionTables, valTableColumnMap, valTableColumnQueue, controlNodes, visitedNodes, ret)
        }
    }
}

def getColumnMap(nodes, funcsOfNodes, sql_querys, userTables, primaryKeys, PrimaryKeysMap, sessionTables, statusColumns, updateColumns, condTableColumnsMap, condTableColumns, sensitive_sql_index, useValue_sql_index, sql_fetch_funcs, sql_insert_id_funcs, sql_num_rows_funcs, isWP, isDAL, dal_sql_query_funcs, dal_sql_fetch_funcs, dalFetchColumn, dal_sql_insert_id_funcs, dal_sql_num_rows_funcs, dalQueryNodes, valTableColumnMap, valTableColumnQueue, valDefTableColumnMap, valDefTableColumnQueue, sqlNumRowsMap, sql_source_map, ret) {
    for (int index = 0; index < nodes.size(); ++index) {
        def query_info = QueryProcessing.querys.get(index)
        def node = nodes[index]
        def funcs = funcsOfNodes[index]
        ret.add(sql_querys[index])
        if (query_info instanceof CreateTableInfo) {
            CreateTableInfo createTableInfo = (CreateTableInfo) query_info
            String tableName = createTableInfo.getTableName()
            String tablePrimaryKey = createTableInfo.getPrimaryKey()
            if (createTableInfo.isUserTable()) {
                def tableKeys = new HashSet<String>()
                tableKeys.add(tablePrimaryKey)
                for (key in createTableInfo.getUniqueKeys()) {
                    tableKeys.add(key)
                }
                userTables.put(tableName, tableKeys)
            }
            primaryKeys.add(tableName+"."+tablePrimaryKey)
            PrimaryKeysMap.put(tableName, tablePrimaryKey)
            if (tablePrimaryKey.contains(",")) {
                ArrayList<String> tablePrimaryKeys = tablePrimaryKey.split(',')
                for (key in tablePrimaryKeys) {
                    primaryKeys.add(tableName+"."+key)
                }
            }
            for (column in createTableInfo.getStatusCols()) {
                statusColumns.add(createTableInfo.getTableName()+"."+column)
            }
            useValue_sql_index.add(false)
        }
        else if (query_info instanceof SelectInfo) {
            def selectInfo = (SelectInfo)query_info
            def tables = selectInfo.getTNames()
            def selectItemList = selectInfo.getSelectItemList()
            def conditionCols = selectInfo.getConditionCols()
            def conditionVals = selectInfo.getConditionVals()

            def condUseValue = false
            def sensitive_sql = false

            def sensitive_index = new ArrayList<String>()

            def location = node.toFileAbs().next().name + ":" + node.lineno

            for (int i = 0; i < selectItemList.size(); ++i) {
                def table = selectItemList.get(i).getKey()
                def column = selectItemList.get(i).getValue()
                if (userTables.containsKey(table) && userTables.get(table).contains(column)) {
                    sensitive_index.add(Integer.toString(i))
                    sensitive_index.add(table)
                    sensitive_index.add(column)
                    sensitive_index.add("true")
                    sensitive_index.add(location+" "+table)
                    sensitive_sql = true
                }
                else if (primaryKeys.contains(table+"."+column)) {
                    sensitive_index.add(Integer.toString(i))
                    sensitive_index.add(table)
                    sensitive_index.add(column)
                    sensitive_index.add("true")
                    sensitive_index.add(location+" "+table)
                    sensitive_sql = true
                }
                else if (statusColumns.contains(table+"."+column)) {
                    sensitive_index.add(Integer.toString(i))
                    sensitive_index.add(table)
                    sensitive_index.add(column)
                    sensitive_index.add("true")
                    sensitive_index.add(location+" "+table)
                    sensitive_sql = true
                }
                else {
                    sensitive_index.add(Integer.toString(i))
                    sensitive_index.add(table)
                    sensitive_index.add(column)
                    sensitive_index.add("false")
                    sensitive_index.add(location+" "+table)
                }
            }

            def controlNodes = getControlNodes(node, ret)

            if (sensitive_index.size() > 0) {

                def query = node
                location = query.toFileAbs().next().name + ":" + query.lineno

                def inSqlFetch = false
                def inWpGetRow = false
                def inWpGetResults = false
                def inDBGet = false
                def inQ2A = false

                for (String func in funcs) {
                    if (sql_fetch_funcs.contains(func)) {
                        inSqlFetch = true
                    }
                }

                query = getInnerNode(query)
                if (query.type == "AST_ASSIGN") {
                    def assignName = getAllValName(query.ithChildren(0).next())
                    if (assignName != "" && !inQ2A) {
                        def assignNameSensitiveIndex = new ArrayList<String>()
                        if (valTableColumnMap.containsKey(location + " " + assignName)) {
                            def newEntry = valTableColumnMap.get(location + " " + assignName)
                            assignNameSensitiveIndex.addAll(newEntry.getValue())
                        }
                        def assignNameSensitiveIndexSize = assignNameSensitiveIndex.size()
                        def needOffer = false
                        for (int i = 0; i < sensitive_index.size(); i += 5) {
                            def hasExisted = false
                            def need = true
                            for (int j = 0; j < assignNameSensitiveIndexSize; j += 5) {
                                if (assignNameSensitiveIndex.get(j).equals(sensitive_index.get(i)) &&
                                        assignNameSensitiveIndex.get(j+1).equals(sensitive_index.get(i+1)) &&
                                        assignNameSensitiveIndex.get(j+2).equals(sensitive_index.get(i+2)) &&
                                        assignNameSensitiveIndex.get(j+3).equals(sensitive_index.get(i+3))
                                ) {
                                    if (assignNameSensitiveIndex.get(j+4).equals(sensitive_index.get(i+4))) {
                                        hasExisted = true
                                        break
                                    }
                                    else {
                                        def table1 = assignNameSensitiveIndex.get(j+4).substring(assignNameSensitiveIndex.get(j+4).indexOf(" ")+1)
                                        def table2 = sensitive_index.get(i+4).substring(sensitive_index.get(i+4).indexOf(" ")+1)
                                        if (table1.equals(table2)) {
                                            hasExisted = true
                                            break
                                        }
                                    }
                                }
                            }
                            needOffer = needOffer || need
                            if (!hasExisted) {
                                assignNameSensitiveIndex.add(sensitive_index.get(i))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+1))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+2))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+3))
                                assignNameSensitiveIndex.add(sensitive_index.get(i+4))
                            }
                        }
                        if (assignNameSensitiveIndex.size() > assignNameSensitiveIndexSize) {
                            valTableColumnMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameSensitiveIndex))
                            if (needOffer) {
                                valTableColumnQueue.offer(location + " " + assignName)
                            }
                            if (assignName.startsWith("\$_SESSION[")) {
                                setValTableColumnForSession(assignName, node, valTableColumnMap, sessionTables, assignNameSensitiveIndex, assignNameSensitiveIndexSize)
                            }
                            if (inSqlFetch || inWpGetRow || inWpGetResults || inDBGet) {
                                for (int i = assignNameSensitiveIndexSize; i < assignNameSensitiveIndex.size(); i += 5) {
                                    def assignNameIndexSensitiveIndex = new ArrayList<String>()
                                    if (valTableColumnMap.containsKey(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]")) {
                                        def newEntry = valTableColumnMap.get(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]")
                                        assignNameIndexSensitiveIndex.addAll(newEntry.getValue())
                                    }
                                    if (assignNameIndexSensitiveIndex.contains(assignNameSensitiveIndex.get(i+4))) {
                                        continue
                                    }
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+1))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+2))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+3))
                                    assignNameIndexSensitiveIndex.add(assignNameSensitiveIndex.get(i+4))
                                    valTableColumnMap.put(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexSensitiveIndex))
                                    valTableColumnMap.put(location + " " + assignName + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexSensitiveIndex))
                                    valTableColumnMap.put(location + " " + assignName + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexSensitiveIndex))

                                    if (assignName.startsWith("\$_SESSION[")) {
                                        valTableColumnMap.put(assignName + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexSensitiveIndex))
                                        valTableColumnMap.put(assignName + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexSensitiveIndex))
                                    }
                                    if (inWpGetResults) {
                                        def assignNameIndexRSensitiveIndex = new ArrayList<String>()
                                        if (valTableColumnMap.containsKey(location+" "+assignName+"[0]"+"[" + assignNameSensitiveIndex.get(i) + "]")) {
                                            def assignNameIndexEntry = valTableColumnMap.get(location+" "+assignName+"[0]"+"[" + assignNameSensitiveIndex.get(i) + "]")
                                            assignNameIndexRSensitiveIndex.addAll(assignNameIndexEntry.getValue())
                                        }
                                        if (assignNameIndexRSensitiveIndex.contains(assignNameSensitiveIndex.get(i+4))) {
                                            continue
                                        }
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i))
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+1))
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+2))
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+3))
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+4))
                                        valTableColumnMap.put(location + " " + assignName + "[0]" + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                        valTableColumnMap.put(location + " " + assignName + "[0]" + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                        valTableColumnMap.put(location + " " + assignName + "[0]" + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                        if (assignName.startsWith("\$_SESSION[")) {
                                            valTableColumnMap.put(assignName + "[0]" + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                            valTableColumnMap.put(assignName + "[0]" + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                            valTableColumnMap.put(assignName + "[0]" + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                        }
                                    }
                                    if (inDBGet) {
                                        def assignNameIndexRSensitiveIndex = new ArrayList<String>()
                                        if (valTableColumnMap.containsKey(location+" "+assignName+"[1]"+"[" + assignNameSensitiveIndex.get(i) + "]")) {
                                            def assignNameIndexEntry = valTableColumnMap.get(location+" "+assignName+"[1]"+"[" + assignNameSensitiveIndex.get(i) + "]")
                                            assignNameIndexRSensitiveIndex.addAll(assignNameIndexEntry.getValue())
                                        }
                                        if (assignNameIndexRSensitiveIndex.contains(assignNameSensitiveIndex.get(i+4))) {
                                            continue
                                        }
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i))
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+1))
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+2))
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+3))
                                        assignNameIndexRSensitiveIndex.add(assignNameSensitiveIndex.get(i+4))
                                        valTableColumnMap.put(location + " " + assignName + "[1]" + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                        valTableColumnMap.put(location + " " + assignName + "[1]" + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                        valTableColumnMap.put(location + " " + assignName + "[1]" + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                        if (assignName.startsWith("\$_SESSION[")) {
                                            valTableColumnMap.put(assignName + "[1]" + "[" + assignNameSensitiveIndex.get(i) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                            valTableColumnMap.put(assignName + "[1]" + "[" + assignNameSensitiveIndex.get(i+2) + "]", new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                            valTableColumnMap.put(assignName + "[1]" + "->" + assignNameSensitiveIndex.get(i+2), new AbstractMap.SimpleEntry<Vertex, ArrayList<String>>(node, assignNameIndexRSensitiveIndex))
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else {
                        ret.add("assignName is empty")
                        ret.add(getLocation(query.ithChildren(0).next()))
                    }
                }
                else {
                    ret.add("select node type is not assign")
                    ret.add(getLocation(node))
                    sql_source_map.put(node, sensitive_index)
                }

                if (isDAL) {
                    setDalQuery(node, nodes, index, sensitive_index, dal_sql_query_funcs, dal_sql_fetch_funcs, dalFetchColumn, dal_sql_num_rows_funcs, sqlNumRowsMap, valTableColumnMap, valTableColumnQueue, sessionTables, ret)
                }

            }

            condTableColumnsMap.put(location, getCondTableColumns(conditionCols))

            condUseValue = isCondUseValue(conditionVals)

            useValue_sql_index.add(condUseValue)

            if (condUseValue) {
                for (int i = 0; i < conditionCols.size(); ++i) {
                    def val = conditionVals.get(i)
                    def table = conditionCols.get(i).substring(0, conditionCols.get(i).indexOf("."))
                    if (primaryKeys.contains(conditionCols.get(i)) || userTables.containsKey(table)) {
                        def vals = getAllValsInCond(val)
                        location = node.toFileAbs().next().name + ":" + node.lineno
                        for (v in vals) {
                            def  columns = new HashSet<String>()
                            if (valDefTableColumnMap.containsKey(location+" "+v)) {
                                def entry = valDefTableColumnMap.get(location+" "+v)
                                columns.addAll(entry.getValue())
                            }
                            columns.add(conditionCols.get(i))
                            valDefTableColumnMap.put(location+" "+v, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(node, columns))
                            valDefTableColumnQueue.offer(location+" "+v)
                        }
                    }
                }
            }

            def visitedNodes = new HashSet<Vertex>()
            setSqlNumRows(node, nodes, index, sql_num_rows_funcs, sqlNumRowsMap, controlNodes, visitedNodes, ret)
        }
        else if (query_info instanceof InsertInfo) {
            InsertInfo insertInfo = (InsertInfo) query_info
            def table = insertInfo.getTNames()[0]
            def colNames = insertInfo.getColNames()
            def itemNames = insertInfo.getItemNames()
            def colUseValue = false

            for (int i = 0; i < colNames.size(); ++i) {
                if (i < itemNames.size() && itemNames.get(i).startsWith("\$")) {
                    colUseValue = true
                }
            }

            useValue_sql_index.add(colUseValue)

            if (colUseValue) {
                for (int i = 0; i < colNames.size(); ++i) {
                    if (i < itemNames.size()) {
                        def val = itemNames.get(i)
                        if (primaryKeys.contains(table+"."+colNames.get(i)) || userTables.containsKey(table)) {
                            if (val.startsWith("\$")) {
                                def location = node.toFileAbs().next().name + ":" + node.lineno
                                def  columns = new HashSet<String>()
                                if (valDefTableColumnMap.containsKey(location + " " + val)) {
                                    def entry = valDefTableColumnMap.get(location + " " + val)
                                    columns.addAll(entry.getValue())
                                }
                                columns.add(table + "." + colNames.get(i))
                                valDefTableColumnMap.put(location + " " + val, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(node, columns))
                                valDefTableColumnQueue.offer(location + " " + val)
                            }
                        }
                    }
                }
            }

            def primaryKey = ""
            if (PrimaryKeysMap.containsKey(table)) {
                primaryKey = PrimaryKeysMap.get(table)
            }

            def controlNodes = getControlNodes(node, ret)
            def nodeLocation = node.toFileAbs().next().name + ":" + node.lineno
            def visitedNodes = new HashSet<Vertex>()
            setInsertId(node, nodes, nodeLocation, sql_insert_id_funcs, table, primaryKey, sessionTables, valTableColumnMap, valTableColumnQueue, controlNodes, visitedNodes, ret)
        }
        else if (query_info instanceof DeleteInfo) {
            DeleteInfo deleteInfo = (DeleteInfo)query_info
            def table = deleteInfo.getTNames()[0]
            def conditionCols = deleteInfo.getConditionCols()
            def conditionVals = deleteInfo.getConditionVals()
            def condUseValue = false

            condUseValue = isCondUseValue(conditionVals)

            useValue_sql_index.add(condUseValue)


            if (condUseValue) {
                for (int i = 0; i < conditionCols.size(); ++i) {
                    def val = conditionVals.get(i)
                    if (primaryKeys.contains(conditionCols.get(i)) || userTables.containsKey(table)) {
                        def vals = getAllValsInCond(val)
                        location = node.toFileAbs().next().name + ":" + node.lineno
                        for (v in vals) {
                            def columns = new HashSet<String>()
                            if (valDefTableColumnMap.containsKey(location+" "+v)) {
                                def entry = valDefTableColumnMap.get(location+" "+v)
                                columns.addAll(entry.getValue())
                            }
                            columns.add(conditionCols.get(i))
                            valDefTableColumnMap.put(location+" "+v, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(node, columns))
                            valDefTableColumnQueue.offer(location+" "+v)
                        }
                    }
                }
            }
        }
        else if (query_info instanceof UpdateInfo) {
            UpdateInfo updateInfo = (UpdateInfo)query_info
            def table = updateInfo.getTNames()[0]
            def colNames = updateInfo.getColNames()
            def itemNames = updateInfo.getItemNames()
            def conditionCols = updateInfo.getConditionCols()
            def conditionVals = updateInfo.getConditionVals()
            def colUseValue = false
            def condUseValue = false

            for (int i = 0; i < colNames.size(); ++i) {
                updateColumns.add(table+"."+colNames.get(i))
                if (i < itemNames.size() && itemNames.get(i).startsWith("\$")) {
                    colUseValue = true
                }
            }

            if (colUseValue) {
                for (int i = 0; i < colNames.size(); ++i) {
                    if (i < itemNames.size()) {
                        def val = itemNames.get(i)
                        if (primaryKeys.contains(table+"."+colNames.get(i)) || userTables.containsKey(table)) {
                            if (val.startsWith("\$")) {
                                def location = node.toFileAbs().next().name + ":" + node.lineno
                                def columns = new HashSet<String>()
                                if (valDefTableColumnMap.containsKey(location + " " + val)) {
                                    def entry = valDefTableColumnMap.get(location + " " + val)
                                    columns.addAll(entry.getValue())
                                }
                                columns.add(table + "." + colNames.get(i))
                                valDefTableColumnMap.put(location + " " + val, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(node, columns))
                                valDefTableColumnQueue.offer(location + " " + val)
                            }
                        }
                    }
                }
            }

            condUseValue = isCondUseValue(conditionVals)

            useValue_sql_index.add(colUseValue || condUseValue)

            if (condUseValue) {
                for (int i = 0; i < conditionCols.size(); ++i) {
                    def val = conditionVals.get(i)
                    if (primaryKeys.contains(conditionCols.get(i)) || userTables.containsKey(table)) {
                        def vals = getAllValsInCond(val)
                        location = node.toFileAbs().next().name + ":" + node.lineno
                        for (v in vals) {
                            def columns = new HashSet<String>()
                            if (valDefTableColumnMap.containsKey(location+" "+v)) {
                                def entry = valDefTableColumnMap.get(location+" "+v)
                                columns.addAll(entry.getValue())
                            }
                            columns.add(conditionCols.get(i))
                            valDefTableColumnMap.put(location+" "+v, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(node, columns))
                            valDefTableColumnQueue.offer(location+" "+v)
                        }
                    }
                }
            }
        }
    }
}

def getInnerNode(node) {
    v = node
    if (v.type == "AST_UNARY_OP" && v.flags != null) {
        if (v.flags.contains("UNARY_BOOL_NOT") || v.flags.contains("UNARY_SILENCE")) {
            v = v.ithChildren(0).next()
        }
    }
    if (v.type == "AST_BINARY_OP" && v.flags != null) {
        if (v.flags.contains("BINARY_BOOL_OR")) {
            v = v.ithChildren(0).next()
        }
    }
    return v
}

def parseSession(nodes, hasCodeNodes, sessionMap, sessionQueue, valTableColumnMap, equal_funcs, queryIndex, isWP, isDAL, dal_sql_query_funcs, sanitizations, excludeDirs, excludeFiles, ret) {
    System.out.println("***************************************** parseSession")
    ret.add("***************************************** parseSession")
    def sessionVals = new HashSet<String>()
    def session_statements = new ArrayList<Vertex>()
    for (hasCodeNode in hasCodeNodes) {
        if (hasCodeNode.code.indexOf("_SESSION") != -1) {
            session_statements.add(hasCodeNode.statements().next())
        }
    }
    for (sessionNode in session_statements) {
        def nodeLocation = sessionNode.toFileAbs().next().name + ":" + sessionNode.lineno
        def isExclude = false
        for (excludeDir in excludeDirs) {
            if (nodeLocation.indexOf('/'+excludeDir+'/') != -1) {
                isExclude = true
            }
        }
        for (excludeFile in excludeFiles) {
            if (nodeLocation.indexOf(excludeFile) != -1) {
                isExclude = true
            }
        }
        if (isExclude) {
            continue
        }
        def node = sessionNode
        if (nodes.contains(node)) {
            ret.add(sessionNode)
            ret.add("already")
            continue
        }
        node = getInnerNode(node)
        if (node.type == "AST_ASSIGN") {
            def assignName = getAllValName(node.ithChildren(0).next())
            assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')

            def funcs = new HashSet<String>()
            def start = new HashSet<Boolean>()
            start.add(true)
            def value = statementToString(node.ithChildren(1).next(), start, new HashMap<>(), funcs, sanitizations)

            def inEqual = false
            def inSqlQuery = false
            def qIndex = 0
            for (String func in funcs) {
                if (equal_funcs.contains(func)) {
                    inEqual = true
                }
                else if (queryIndex.containsKey(func)) {
                    inSqlQuery = true
                    qIndex = queryIndex.get(func)
                }
            }

            if (inEqual) {
                value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
            }
            if (inSqlQuery) {
                if (qIndex == 0) {
                    value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
                }
                else if (qIndex == 1) {
                    value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+)([\s,]+)([\$\w\[\]\'-]+)\))/, '$4')
                }
            }

            ret.add(assignName)
            ret.add(value)
            def location = node.toFileAbs().next().name + ":" + node.lineno
            if (value.startsWith("\$_SESSION[")) {
                def sessionVal = new HashSet<String>()
                if (sessionMap.containsKey(location+" "+assignName)) {
                    def entry = sessionMap.get(location+" "+assignName)
                    sessionVal.addAll(entry.getValue())
                }
                def changed = sessionVal.addAll(value)
                if (changed) {
                    sessionMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(sessionNode, sessionVal))
                    sessionQueue.offer(location + " " + assignName)
                    sessionMap.put(location + " " + value, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(sessionNode, sessionVal))
                    if (!isWithinFunction(sessionNode)) {
                        sessionMap.put(assignName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(sessionNode, sessionVal))
                        sessionVals.add(assignName)
                    }
                    System.out.println("assign " + value)
                }
            }
            else if (node.ithChildren(1).next().type == "AST_CALL" || node.ithChildren(1).next().type == "AST_METHOD_CALL" || node.ithChildren(1).next().type == "AST_STATIC_CALL") {
                if (isDAL) {
                    def funcName = getFuncName(node.ithChildren(1).next())
                    if (dal_sql_query_funcs.contains(funcName)) {
                        continue
                    }
                }
                setSessionForCall(node.ithChildren(1).next(), sessionMap, sessionQueue, sanitizations, ret)
            }
            else if (assignName.startsWith("\$_SESSION[") && !valTableColumnMap.containsKey(assignName)) {
                if (!isWithinFunction(sessionNode)) {
                    def sessionVal = new HashSet<String>()
                    if (sessionMap.containsKey(assignName)) {
                        def entry = sessionMap.get(assignName)
                        sessionVal.addAll(entry.getValue())
                    }
                    def changed = sessionVal.addAll(location+" "+value)
                    if (changed) {
                        sessionMap.put(assignName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(sessionNode, sessionVal))
                    }
                }
            }
            else {
                ret.add("other type")
            }
        }
        else if (node.type == "AST_RETURN") {
            setSessionForReturn(node, sessionMap, sessionQueue, sessionNode, ret)
        }
        else if (node.type == "AST_CALL" || node.type == "AST_METHOD_CALL" || node.type == "AST_STATIC_CALL") {
            if (isDAL) {
                def funcName = getFuncName(node)
                if (dal_sql_query_funcs.contains(funcName)) {
                    continue
                }
            }
            setSessionForCall(node, sessionMap, sessionQueue, sanitizations, ret)
        }
    }

    System.out.println("***************************************** sessionQueue")
    ret.add("***************************************** sessionQueue")

    for (sessionVal in sessionVals) {
        sessionQueue.offer(sessionVal)
    }

    while (sessionQueue.size() > 0) {
        def key = sessionQueue.poll()
        ret.add(key)
        System.out.println(key)
        if (sessionMap.containsKey(key)) {
            def entry = sessionMap.get(key)
            def valOfKey = key.substring(key.indexOf(' ')+1)
            def node = entry.getKey()
            def nodeLocation = node.toFileAbs().next().name + ":" + node.lineno
            def sessionVal = entry.getValue()
            ret.add("******valOfKey****")
            ret.add(valOfKey)
            ret.add(key)
            if (valOfKey != key) {
                for (Vertex v in node.out("REACHES")) {
                    def statement = v
                    def location = v.toFileAbs().next().name + ":" + v.lineno
                    if (nodes.contains(v)) {
                        ret.add("already")
                        continue
                    }
                    v = getInnerNode(v)
                    if (v.type == "AST_ASSIGN") {
                        def assignName = getAllValName(v.ithChildren(0).next())
                        assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')

                        def funcs = new HashSet<String>()
                        def start = new HashSet<Boolean>()
                        start.add(true)
                        def value = statementToString(v.ithChildren(1).next(), start, new HashMap<>(), funcs, sanitizations)
                        value = value.trim()

                        def inEqual = false
                        def inSqlQuery = false
                        def qIndex = 0
                        for (String func in funcs) {
                            if (equal_funcs.contains(func)) {
                                inEqual = true
                            }
                            else if (queryIndex.containsKey(func)) {
                                inSqlQuery = true
                                qIndex = queryIndex.get(func)
                            }
                        }
                        if (inEqual) {
                            value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
                        }
                        if (inSqlQuery) {
                            if (qIndex == 0) {
                                value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+).*\))/, '$2')
                            }
                            else if (qIndex == 1) {
                                value = value.replaceAll(/(.*\(([\$\w\[\]\'-]+)([\s,]+)([\$\w\[\]\'-]+)\))/, '$4')
                            }
                        }

                        if (value.startsWith("\$")) {
                            def sessionRefVal = nodeLocation + " " + value
                            if (sessionMap.containsKey(sessionRefVal)) {
                                def sessionEntry = sessionMap.get(sessionRefVal)
                                def nsessionVal = sessionEntry.getValue()
                                if (assignName.startsWith("\$")) {
                                    def newSessionVal = new HashSet<String>()
                                    if (sessionMap.containsKey(location + " " + assignName)) {
                                        def newEntry = sessionMap.get(location + " " + assignName)
                                        newSessionVal.addAll(newEntry.getValue())
                                    }
                                    def changed = newSessionVal.addAll(nsessionVal)
                                    if (changed) {
                                        sessionMap.put(location + " " + assignName, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(statement, newSessionVal))
                                        sessionQueue.offer(location + " " + assignName)
                                    }
                                }
                                else {
                                    ret.add(getLocation(v.ithChildren(0).next()))
                                    ret.add("session assignName is not variable")
                                }
                            }
                            else {
                                ret.add(sessionRefVal)
                                ret.add("sessionRefVal not found")
                            }
                        }
                        else if (v.ithChildren(1).next().type == "AST_CALL" || v.ithChildren(1).next().type == "AST_METHOD_CALL" || v.ithChildren(1).next().type == "AST_STATIC_CALL") {
                            if (isDAL) {
                                def funcName = getFuncName(v.ithChildren(1).next())
                                if (dal_sql_query_funcs.contains(funcName)) {
                                    continue
                                }
                            }
                            transSessionForCall(v.ithChildren(1).next(), nodeLocation, sessionMap, sessionQueue, sanitizations, ret)
                        }
                        else {
                            ret.add(value)
                            ret.add("other type")
                        }
                    }
                    else if (v.type == "AST_RETURN") {
                        transSessionForReturn(v, nodeLocation, sessionMap, sessionQueue, statement, ret)
                    }
                    else if (v.type == "AST_CALL" || v.type == "AST_METHOD_CALL" || v.type == "AST_STATIC_CALL") {
                        if (isDAL) {
                            def funcName = getFuncName(v)
                            if (dal_sql_query_funcs.contains(funcName)) {
                                continue
                            }
                        }
                        transSessionForCall(v, nodeLocation, sessionMap, sessionQueue, sanitizations, ret)
                    }
                    else {
                        ret.add(v)
                        ret.add("session node type is not assign")
                    }
                }
            }
            else {
                def arrayOfVal = valOfKey
                if (valOfKey.indexOf("[") != -1) {
                    arrayOfVal = valOfKey.substring(0, valOfKey.indexOf("["))
                }
                def sessionVal_statements = new ArrayList<Vertex>()
                for (hasCodeNode in hasCodeNodes) {
                    if (hasCodeNode.code.indexOf(arrayOfVal.substring(1)) != -1) {
                        sessionVal_statements.add(hasCodeNode.statements().next())
                    }
                }

                for (sessionValNode in sessionVal_statements) {
                    sessionValNode = getStatement(sessionValNode)
                    def nodeFileLocation = sessionValNode.toFileAbs().next().name
                    def isExclude = false
                    for (excludeDir in excludeDirs) {
                        if (nodeFileLocation.indexOf('/' + excludeDir + '/') != -1) {
                            isExclude = true
                        }
                    }
                    for (excludeFile in excludeFiles) {
                        if (nodeFileLocation.indexOf(excludeFile) != -1) {
                            isExclude = true
                        }
                    }
                    if (isExclude) {
                        continue
                    }
                    def hasDef = false
                    for (v in sessionValNode.in("REACHES")) {
                        def location = v.toFileAbs().next().name + ":" + v.lineno
                        if (sessionMap.containsKey(location+" "+valOfKey) || valTableColumnMap.containsKey(location+" "+valOfKey)) {
                            hasDef = true
                            break
                        }
                        if (v.type == "AST_ASSIGN") {
                            def assignName = getAllValName(v.ithChildren(0).next())
                            assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                            if (assignName == valOfKey) {
                                hasDef = true
                                break
                            }
                        }
                        else if (v.type == "AST_PARAM") {
                            def paramName = getAllValName(v)
                            if (paramName == valOfKey) {
                                hasDef = true
                                break
                            }
                        }
                    }
                    if (hasDef) {
                        continue
                    }
                    def sessionValNodeStatement = statementToString(sessionValNode, new HashSet<>(), new HashMap<>(), new HashSet<>(), sanitizations)
                    if (sessionValNodeStatement.indexOf(valOfKey) == -1) {
                        continue
                    }

                    nodeLocation = nodeFileLocation
                    if (isWithinFunction(sessionValNode)) {
                        nodeLocation = nodeLocation + "_" + sessionValNode.functions().next().name + ":" + sessionValNode.functions().next().lineno
                    }
                    sessionMap.put(nodeLocation+" "+valOfKey, new AbstractMap.SimpleEntry<Vertex, HashSet<String>>(sessionValNode, sessionVal))

                    node = sessionValNode
                    ret.add("********sessionValNode****")
                    if (nodes.contains(node)) {
                        ret.add(sessionValNode)
                        ret.add("already")
                        continue
                    }
                    node = getInnerNode(node)
                    ret.add(sessionValNode)
                    ret.add(node)
                    if (node.type == "AST_ASSIGN") {
                        def assignName = getAllValName(node.ithChildren(0).next())
                        assignName = assignName.replaceAll(/((\$[\w]+)\[\])/, '$2[0]')
                        if (assignName == valOfKey) {
                            continue
                        }

                        if (node.ithChildren(1).next().type == "AST_CALL" || node.ithChildren(1).next().type == "AST_METHOD_CALL" || node.ithChildren(1).next().type == "AST_STATIC_CALL") {
                            if (isDAL) {
                                def funcName = getFuncName(node.ithChildren(1).next())
                                if (dal_sql_query_funcs.contains(funcName)) {
                                    continue
                                }
                            }
                            transSessionForCall(node.ithChildren(1).next(), nodeLocation, sessionMap, sessionQueue, sanitizations, ret)
                        }
                    }
                    else if (node.type == "AST_CALL" || node.type == "AST_METHOD_CALL" || node.type == "AST_STATIC_CALL") {
                        if (isDAL) {
                            def funcName = getFuncName(node)
                            if (dal_sql_query_funcs.contains(funcName)) {
                                continue
                            }
                        }
                        transSessionForCall(node, nodeLocation, sessionMap, sessionQueue, sanitizations, ret)
                    }
                    else if (node) {

                    }
                }
            }
        }
    }

    for (sessionVal in sessionVals) {
        sessionMap.remove(sessionVal)
    }

    System.out.println("*************************************sessionMap***************************")
    ret.add("*************************************sessionMap***************************")
    ret.add(sessionMap)
}

def analyzeUseValue(nodes, sql_querys, combineNodeMap, userTables, PrimaryKeysMap, useValue_sql_index, valTableColumnMap, valDefTableColumnMap, sessionMap, queryCondMap, columnValUseMap, callerDTableMaps, dynamicTableNodeMaps, insertUserReltatedTables, useValueRet) {
    for (tableColumn in QueryProcessing.tableRelations.keySet()) {
        def table = tableColumn.substring(0, tableColumn.indexOf("."))
        def column = tableColumn.substring(tableColumn.indexOf(".")+1)
        def rels = QueryProcessing.tableRelations.get(tableColumn)
        for (rel in rels) {
            def tableOfRel = rel.substring(0, rel.indexOf("."))
            def columnOfRel = rel.substring(rel.indexOf(".")+1)
            if (PrimaryKeysMap.containsKey(tableOfRel) && !PrimaryKeysMap.get(tableOfRel).equalsIgnoreCase(columnOfRel)) {
                if (userTables.containsKey(table)) {
                    userTables.get(table).add(column)
                }
            }
        }
    }
    for (int index = 0; index < nodes.size(); ++index) {
        if (useValue_sql_index[index]) {
            def query_info = QueryProcessing.querys.get(index)
            def node = nodes[index]
            useValueRet.add("*************************************************")
            useValueRet.add(sql_querys[index])
            useValueRet.add(getLocation(node))
            System.out.println("*************************************************")
            System.out.println(sql_querys[index])
            System.out.println(getLocation(node))
            if (query_info instanceof SelectInfo) {
                def selectInfo = (SelectInfo)query_info
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

                setRelationForCond(node, conditionCols, conditionVals, defNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, sql_querys[index], PrimaryKeysMap, userTables, true, queryCondMap, columnValUseMap, callerDTableMaps, dynamicTableNodeMaps, useValueRet)
            }
            else if (query_info instanceof InsertInfo) {
                def insertInfo = (InsertInfo) query_info
                def table = insertInfo.getTNames()[0]
                def colNames = insertInfo.getColNames()
                def itemNames = insertInfo.getItemNames()
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

                setRelationForCol(node, colNames, itemNames, table, defNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, sql_querys[index], PrimaryKeysMap, userTables, callerDTableMaps, dynamicTableNodeMaps, insertUserReltatedTables, useValueRet)
            }
            else if (query_info instanceof DeleteInfo) {
                DeleteInfo deleteInfo = (DeleteInfo) query_info
                def table = deleteInfo.getTNames()[0]
                def conditionCols = deleteInfo.getConditionCols()
                def conditionVals = deleteInfo.getConditionVals()
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

                setRelationForCond(node, conditionCols, conditionVals, defNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, sql_querys[index], PrimaryKeysMap, userTables, false, queryCondMap, columnValUseMap, callerDTableMaps, dynamicTableNodeMaps, useValueRet)
            }
            else if (query_info instanceof UpdateInfo) {
                UpdateInfo updateInfo = (UpdateInfo) query_info
                def table = updateInfo.getTNames()[0]
                def colNames = updateInfo.getColNames()
                def itemNames = updateInfo.getItemNames()
                def conditionCols = updateInfo.getConditionCols()
                def conditionVals = updateInfo.getConditionVals()
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

                setRelationForCol(node, colNames, itemNames, table, defNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, sql_querys[index], PrimaryKeysMap, userTables, callerDTableMaps, dynamicTableNodeMaps, null, useValueRet)

                setRelationForCond(node, conditionCols, conditionVals, defNodes, valTableColumnMap, valDefTableColumnMap, sessionMap, sql_querys[index], PrimaryKeysMap, userTables, false, queryCondMap, columnValUseMap, callerDTableMaps, dynamicTableNodeMaps, useValueRet)
            }
        }
    }
}
