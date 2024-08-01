// AST node property keys

Object.metaClass.NODE_INDEX = 'id'
Object.metaClass.NODE_TYPE = 'type'
Object.metaClass.NODE_FLAGS = 'flags'
Object.metaClass.NODE_LINENO = 'lineno'
Object.metaClass.NODE_CODE = 'code'
Object.metaClass.NODE_FUNCID = 'funcid'
Object.metaClass.NODE_ENDLINENO = 'endlineno'
Object.metaClass.NODE_NAME = 'name'
Object.metaClass.NODE_DOCCOMMENT = 'doccomment'


// AST node types

Object.metaClass.TYPE_CFG_FUNC_ENTRY = 'CFG_FUNC_ENTRY'
Object.metaClass.TYPE_STMT_LIST = 'AST_STMT_LIST' // ...; ...; ...;
Object.metaClass.TYPE_CALL = 'AST_CALL' // foo()
Object.metaClass.TYPE_STATIC_CALL = 'AST_STATIC_CALL' // bla::foo()
Object.metaClass.TYPE_METHOD_CALL = 'AST_METHOD_CALL' // $bla->foo()
Object.metaClass.TYPE_CLOSURE = 'AST_CLOSURE'
Object.metaClass.TYPE_PROP = 'AST_PROP' // e.g., $bla->foo
Object.metaClass.TYPE_FUNC_DECL = 'AST_FUNC_DECL' // function foo() {}
Object.metaClass.TYPE_METHOD = 'AST_METHOD' // class bla { ... function foo() {} ... }
Object.metaClass.TYPE_ARG_LIST = 'AST_ARG_LIST' // foo( $a1, $a2, $a3)
Object.metaClass.TYPE_PARAM_LIST = 'AST_PARAM_LIST' // function foo( $p1, $p2, $p3) {}
Object.metaClass.TYPE_PARAM = 'AST_PARAM' // $p1
Object.metaClass.TYPE_ASSIGN = 'AST_ASSIGN' // $buzz = true
Object.metaClass.TYPE_ASSIGN_REF = 'AST_ASSIGN_REF' // $b = &$a
Object.metaClass.TYPE_ASSIGN_OP = 'AST_ASSIGN_OP' // $x += 3
Object.metaClass.TYPE_NAME = 'AST_NAME' // names (e.g., name of a called function in call expressions)
Object.metaClass.TYPE_VAR = 'AST_VAR' // $v
Object.metaClass.TYPE_BINARY_OP = 'AST_BINARY_OP' // e.g., "foo"."bar" or 3+4
Object.metaClass.TYPE_ENCAPS_LIST = 'AST_ENCAPS_LIST' // e.g., "blah{$var1}buzz $var2 beep"
Object.metaClass.TYPE_INCLUDE_OR_EVAL = 'AST_INCLUDE_OR_EVAL' // eval, include, require
Object.metaClass.TYPE_FOREACH = 'AST_FOREACH' // foreach ($x as $y) { ... }
Object.metaClass.TYPE_FOR = 'AST_FOR' // for ($i = 0; $i < 10; $i++) { ... }
//Abeer
Object.metaClass.TYPE_CALLEE = 'Callee'
Object.metaClass.TYPE_FUNCTION = 'Function'
Object.metaClass.TYPE_ECHO = 'AST_ECHO' // eecho
Object.metaClass.TYPE_PRINT = 'AST_PRINT' // PRINT

//ABEER
Object.metaClass.TYPE_IF_ELEM = 'AST_IF_ELEM' // HOLDES THE COND INSIDE IF 
Object.metaClass.TYPE_DIM = 'AST_DIM' // _POST[x]
Object.metaClass.TYPE_ISSET = 'AST_ISSET' // 
// TODO and many more...


// AST node flags
// of AST_ASSIGN.*
Object.metaClass.FLAG_ASSIGN_CONCAT = 'ASSIGN_CONCAT' // $v .= "foo"
// of AST_BINARY_OP
Object.metaClass.FLAG_BINARY_CONCAT = 'BINARY_CONCAT' // "foo"."bar"
//Abeer
Object.metaClass.FLAG_BINARY_EQUAL = 'BINARY_IS_EQUAL' // x==y
Object.metaClass.FLAG_BINARY_NOT_EQUAL = 'BINARY_IS_NOT_EQUAL'
Object.metaClass.FLAG_BINARY_IS_IDENTICAL = 'BINARY_IS_IDENTICAL'
Object.metaClass.FLAG_BINARY_IS_NOT_IDENTICAL = 'BINARY_IS_NOT_IDENTICAL'
// of AST_INCLUDE_OR_EVAL
Object.metaClass.FLAG_EXEC_EVAL = 'EXEC_EVAL' // eval("...")
Object.metaClass.FLAG_EXEC_INCLUDE = 'EXEC_INCLUDE' // include "..."
Object.metaClass.FLAG_EXEC_INCLUDE_ONCE = 'EXEC_INCLUDE_ONCE' // include_once "..."
Object.metaClass.FLAG_EXEC_REQUIRE = 'EXEC_REQUIRE' // require "..."
Object.metaClass.FLAG_EXEC_REQUIRE_ONCE = 'EXEC_REQUIRE_ONCE' // require_once "..."

// TODO and many more...


// Other (non-AST) node types

Object.metaClass.TYPE_DIRECTORY = 'Directory'
Object.metaClass.TYPE_FILE = 'File'

Object.metaClass.TYPE_STRING = 'string'


// Edge types

Object.metaClass.DIRECTORY_EDGE = 'DIRECTORY_OF'
Object.metaClass.FILE_EDGE = 'FILE_OF'
Object.metaClass.AST_EDGE = 'PARENT_OF'


Object.metaClass.TYPE_IDENTIFIER_DECL_STMT = 'IdentifierDeclStatement'
Object.metaClass.TYPE_PARAMETER = 'Parameter'

Object.metaClass.TYPE_FILE = 'File'

// Edge types


Object.metaClass.CALLS_EDGE = 'CALLS'
Object.metaClass.CFG_EDGE = 'FLOWS_TO'

Object.metaClass.USES_EDGE = 'USE'
Object.metaClass.DEFINES_EDGE = 'DEF'
Object.metaClass.DATA_FLOW_EDGE = 'REACHES'

Object.metaClass.FUNCTION_TO_AST_EDGE = 'IS_FUNCTION_OF_AST'
Object.metaClass.FILE_TO_FUNCTION_EDGE = 'IS_FILE_OF'

// Edge keys

Object.metaClass.DATA_FLOW_SYMBOL = 'var'

//Abeer
Object.metaClass.DATA_FLOW_TAINT_SRC = 'taint_src'
Object.metaClass.DATA_FLOW_TAINT_DST = 'taint_dst'

