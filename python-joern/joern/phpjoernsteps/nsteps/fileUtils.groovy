/**
 Given a set of vertices, traverse to the enclosing file nodes.
 */
Gremlin.defineStep('toFileAbs', [Vertex, Pipe], {
    _().in('PARENT_OF').loop(1) { true } { it.object.getProperty("type") == 'AST_TOPLEVEL' }
            .filter { (it.flags.contains("TOPLEVEL_FILE")) }
})


/**
 Given a set of vertices, traverse to the enclosing Directory node.
 */
Gremlin.defineStep('toDir', [Vertex, Pipe], {
    _().in('PARENT_OF').loop(1) { true } { it.object.getProperty("type") == 'AST_TOPLEVEL' }
            .filter { (it.flags.contains("TOPLEVEL_FILE")) }
            .in().in(DIRECTORY_EDGE)
})

/**
 Given a set of vertices, traverse to the enclosing file nodes.
 */
Gremlin.defineStep('toFile', [Vertex, Pipe], {
    _().in().loop(1) { it.object.getProperty("type") != TYPE_FILE }
})

/**
 Given a set of file nodes, return their paths.
 */
Gremlin.defineStep('fileToPath', [Vertex, Pipe], {
    _().filter { it.getProperty("type") == TYPE_FILE }.sideEffect { path = it.getProperty("name") }
            .ifThenElse { it.in(DIRECTORY_EDGE).count() > 0 }
    {
        it.in(DIRECTORY_EDGE).sideEffect { path = it.getProperty("name") + "/" + path }.loop(2) {
            it.object.getProperty("id") != 0
        }
    }
    { it }
            .transform { path }
})