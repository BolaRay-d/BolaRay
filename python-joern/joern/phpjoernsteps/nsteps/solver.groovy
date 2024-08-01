Gremlin.defineStep('resolveBinaryArgs', [Vertex, Pipe], {
    def l, r;
    _().sideEffect { org = it }.ithChildren(0).or(

            _().filter { it.type == 'AST_VAR' }
                    .sideEffect { l = '$' + it.varToName().next() }
            ,

            _().filter { it.type == 'AST_DIM' }
                    .sideEffect {
                        l = '$' + it.ithChildren(0).varToName.next() + '[' + it.ithChildren(1).code.next() + ']'
                    }
            ,
            _().filter { it.type == 'string' && it.code == null }
                    .sideEffect { l = '' }
            ,
            _().filter { it.type == 'string' && it.code != null }
                    .sideEffect { l = it.code }

    )
            .parents()
            .ithChildren(1)
            .or(
                    _().filter { it.type == 'AST_VAR' }
                            .sideEffect { r = '$' + it.ithChildren(1).varToName().next() }
                    ,
                    _().filter { it.type == 'AST_DIM' }
                            .sideEffect {
                                r = '$' + it.ithChildren(1).varToName.next() + '[' + it.ithChildren(1).code.next() + ']'
                            }
                    ,

                    _().filter { it.type == 'string' && it.code != null }
                            .sideEffect { r = it.code }

                    ,
                    _().filter { it.type == 'string' && it.code == null }
                            .sideEffect { r = '' }
            )


            .transform { tacFormula(l, r, org.flags, org.type, org.id) }

});

Gremlin.defineStep('resolveConcatArgs', [Vertex, Pipe], {
    def l, r;
    x = [];
    _().sideEffect { org = it }.ithChildren(0)
            .or(

                    _().filter { it.type == 'AST_VAR' }
                            .sideEffect { l = '$' + it.varToName().next() }
                    ,

                    _().filter { it.type == 'AST_DIM' }
                            .sideEffect {
                                l = '$' + it.ithChildren(0).varToName.next() + '[' + it.ithChildren(1).code.next() + ']'
                            }
                    ,
                    _().filter { it.type == 'string' && it.code == null }
                            .sideEffect { l = "" }
                    ,
                    _().filter { it.type == 'string' && it.code != null }
                            .sideEffect { l = "\"" + it.code + "\"" }

                    ,
                    _().filter { it.type == 'AST_BINARY_OP' && it.flags != null && it.flags.contains("BINARY_CONCAT") }
                            .sideEffect { l = '$temp_' + it.id }

            )
            .parents()
            .ithChildren(1)
            .or(
                    _().filter { it.type == 'AST_VAR' }
                            .sideEffect { r = '$' + it.ithChildren(1).varToName().next() }
                    ,
                    _().filter { it.type == 'AST_DIM' }
                            .sideEffect {
                                r = '$' + it.ithChildren(1).varToName.next() + '[' + it.ithChildren(1).code.next() + ']'
                            }
                    ,

                    _().filter { it.type == 'string' && it.code != null }
                            .sideEffect { r = "\"" + it.code + "\"" }

                    ,
                    _().filter { it.type == 'string' && it.code == null }
                            .sideEffect { r = "" }

                    ,
                    _().filter { it.type == 'AST_BINARY_OP' && it.flags != null && it.flags.contains("BINARY_CONCAT") }
                            .sideEffect { r = '$temp_' + it.id }
            )
            .transform { tacFormula([l, r], '$temp_' + org.id, org.flags, org.type, org.id) }


});



Gremlin.defineStep('resolveIssetArgs', [Vertex, Pipe], {
    def l;
    _().sideEffect { org = it }
            .ithChildren(0)
            .or(
                    _().has('type', T.eq, TYPE_VAR)
                            .sideEffect { l = '$' + it.varToName().next() }
                    ,

                    _().has('type', T.eq, TYPE_DIM)
                            .sideEffect {
                                l = '$' + it.ithChildren(0).varToName.next() + '[' + it.ithChildren(1).code.next() + ']'
                            }
            )
            .transform { tacFormula(l, "", org.type, org.type, org.id) }
});

Gremlin.defineStep('varFormula', [Vertex, Pipe], {
    def l = [];
    _().sideEffect { org = it }
            .or(

                    _().has('type', T.eq, 'AST_DIM')

                            .ifThenElse { it.ithChildren(1).type.next() == 'AST_CONST' }
                            { v = it.ithChildren(1).out.out.code.next() }
                            { v = it.ithChildren(1).code.next() }
                            .sideEffect { l = ('$' + it.ithChildren(0).varToName.next() + '[' + v + ']') }
                    ,
                    _().has('type', T.eq, TYPE_VAR)
                            .sideEffect { l = '$' + it.varToName().next() }
            )
            .transform { l }.scatter().dedup()
});


def resolveAssignment(Map<Vertex, List<Vertex>> ifMap) {
    def formulaList = [];
    for (Map.Entry<Vertex, List<Vertex>> entry : ifMap.entrySet()) {
        if (entry.getValue() == null)//|| entry.isEmpty())
            continue;
        else {
            List<Vertex> value = entry.getValue();
            for (node in value) {
                // formula = node;
                formula = resolveAssignmentHelper(node);
                if (formula != null)
                    formulaList.add(formula);
            }
        }
    }

    return formulaList;

}

def resolveAssignmentHelper(Vertex node) {
    Vertex r = node.ithChildren(1).next();
    def rr, ll, formula = [];
    Vertex l = node.ithChildren(0).next();


    if (l.type == 'AST_VAR')
        ll = '$' + l.varToName().next();
    else if (l.type == 'AST_DIM')
        ll = '$' + l.ithChildren(0).varToName.next() + '[' + l.ithChildren(1).code.next() + ']';
    //else
    // ll=l.type


    if (r.type == TYPE_VAR) {
        rr = '$' + r.varToName().next();
        formula.add(tacFormula(ll, rr, node.type, node.type, node.id));
    } else if (r.type == TYPE_DIM) {
        rr = '$' + r.ithChildren(0).varToName.next() + '[' + r.ithChildren(1).code.next() + ']';
        temp = "left: " + ll + ", right: " + rr + ", op: " + node.type + ", type: " + node.type + ", node_id: " + node.id;
        formula.add(temp);
    } else if (r.type == TYPE_CALL || r.type == TYPE_METHOD_CALL || r.type == TYPE_STATIC_CALL) {
        formula.add(callFormula(r));
        formula.add(tacFormula(ll, '$temp_' + r.id, node.type, node.type, node.id));
        // return formula;
    } else {
        formula.add(tacFormula(ll, '$temp_' + node.id, node.type, node.type, node.id));
    }
    return formula;

}

Gremlin.defineStep('callFormula', [Vertex, Pipe], { node ->
    def varList = [];
    node
            .ithChildren(0)
            .sideEffect { methodName = it }
            .as('astCallName')
            .sideEffect { mname = it.ithChildren(0).next().code }
            .parents()
    //arg list node
            .callToArguments()
            .sideEffect { varList = it.resolveCallArgs() }
            .transform { tacFormula(varList, '$temp_' + node.id, mname, node.type, node.id) }
});

Gremlin.defineStep('resolveCallArgs', [Vertex, Pipe], {
    def l = [];
    _().sideEffect { org = it }
            .or(
                    _().has('type', T.eq, TYPE_VAR)
                            .sideEffect { l = (it.varFormula().next()) }

                    ,
                    _().has('type', T.eq, TYPE_DIM)
                            .sideEffect { l = it.varFormula().next() }
                    ,
                    _().has('type', T.eq, "string")
                            .sideEffect { l = "\"" + it.code.next() + "\"" }
            )

            .transform { l }.scatter().dedup()
});

def tacFormula(left, right, op, type, id) {
    //return new Formula
    'left: ' + left + ', right: ' + right + ', op: ' + op + ', type: ' + type + ', node_id: ' + id;
}

 



