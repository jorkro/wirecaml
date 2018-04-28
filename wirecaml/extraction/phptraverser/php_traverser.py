from phply.phpast import *

from wirecaml.extraction.phptraverser.php_listener import PHPListener


def traverse(nodes, listener: PHPListener):
    for x in nodes:
        traverse_node(x, listener)


def traverse_node(node, listener: PHPListener):
    if listener.is_traversed(node):
        return

    #
    # $a = 1
    #
    if isinstance(node, Assignment):
        listener.enter_assignment(node)
        traverse_node(node.node, listener)
        traverse_node(node.expr, listener)
        listener.exit_assignment(node)

    #
    # $a += 1
    #
    if isinstance(node, AssignOp):
        listener.enter_assign_op(node)
        listener.exit_assign_op(node)

    #
    # $a == $b
    #
    if isinstance(node, BinaryOp):
        listener.enter_binary_op(node)
        traverse_node(node.left, listener)
        traverse_node(node.right, listener)
        listener.exit_binary_op(node)

    #
    # Unclear
    #
    if isinstance(node, Block):
        listener.enter_block(node)
        for x in node.nodes:
            traverse_node(x, listener)
        listener.exit_block(node)

    #
    # while ($a)
    #
    if isinstance(node, DoWhile):
        listener.enter_do_while(node)
        traverse_node(node.node, listener)
        traverse_node(node.expr, listener)
        listener.exit_do_while(node)

    #
    # echo "..."
    #
    if isinstance(node, Echo):
        listener.enter_echo(node)
        for x in node.nodes:
            traverse_node(x, listener)
        listener.exit_echo(node)

    #
    # for($i = 0; $i < $n; $i++)
    #
    if isinstance(node, For):
        listener.enter_for(node)
        traverse_node(node.node, listener)
        listener.exit_for(node)

    #
    # foreach ($a as $b)
    #
    if isinstance(node, Foreach):
        listener.enter_foreach(node)
        traverse_node(node.expr, listener)
        traverse_node(node.node, listener)
        listener.exit_foreach(node)

    #
    # function foo($a, $b)
    #
    if isinstance(node, Function):
        listener.enter_function_declaration(node)
        for x in node.nodes:
            traverse_node(x, listener)
        listener.exit_function_declaration(node)

    #
    # foo($a, $b)
    #
    if isinstance(node, FunctionCall):
        listener.enter_function_call(node)
        for param in node.params:
            traverse_node(param, listener)
        listener.exit_function_call(node)

    #
    # if ($a)
    #
    if isinstance(node, If):
        listener.enter_if(node)
        traverse_node(node.expr, listener)
        traverse_node(node.node, listener)

        for elseif in node.elseifs:
            listener.enter_if(node)
            traverse_node(elseif.node, listener)
            listener.exit_if(node)
        if node.else_:
            listener.enter_else(node)
            traverse_node(node.else_.node, listener)
            listener.exit_else(node)

        listener.exit_if(node)

    #
    # $a->method()
    #
    if isinstance(node, MethodCall):
        listener.enter_method_call(node)
        for param in node.params:
            traverse_node(param, listener)
        listener.exit_method_call(node)

    #
    # return $a
    #
    if isinstance(node, Return):
        listener.enter_return(node)
        traverse_node(node.node, listener)
        listener.exit_return(node)

    #
    # $a
    #
    if isinstance(node, Variable):
        listener.enter_variable(node)
        listener.exit_variable(node)

    #
    # while ($a)
    #
    if isinstance(node, While):
        listener.enter_while(node)
        traverse_node(node.expr, listener)
        traverse_node(node.node, listener)
        listener.exit_while(node)
