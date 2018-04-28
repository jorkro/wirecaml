import re

import networkx as nx
from networkx.algorithms import shortest_paths

from functools import reduce

from phply.phpast import *

from wirecaml.extraction.phptraverser.php_listener import PHPListener
from wirecaml.extraction.code_node import CodeNode, Tainted


class MyPHPListener(PHPListener):
    def __init__(self, line_map, name):
        self.G = nx.DiGraph()
        self.G.name = name
        self.line_map = line_map

        self.exit_nodes = []
        self.if_nodes = []
        self.for_nodes = []
        self.while_nodes = []
        self.do_nodes = []
        self.do_not_parse = 0
        self.backlog = []
        self.traversed = []
        self.stmt_vars = set()
        self.stmt_funcs = set()
        self.stmt_consts = set()
        self.in_functions = []
        self.functions = dict()

    def enter_return(self, ctx):
        if self.do_not_parse == 0:
            cn = self.add_node(CodeNode(self.get_location(ctx.lineno), 'return', self.unparse_node(ctx)))

            cn.set_vars(self.get_tracked_vars())
            cn.set_funcs(self.get_tracked_funcs())
            cn.set_consts(self.get_tracked_consts())

        self.do_not_parse += 1

    def exit_return(self, ctx):
        self.do_not_parse -= 1

    def enter_function_declaration(self, ctx):
        if self.do_not_parse == 0:
            func = self.unparse_node(ctx)

            self.in_functions.append((self.generate_func_id(func), self.exit_nodes))

    def exit_function_declaration(self, ctx):
        (func_name, exit_nodes) = self.in_functions.pop()

        self.exit_nodes = exit_nodes

    def enter_function_call(self, ctx):
        if self.do_not_parse != 0:
            return

        self.reset_tracking()

        func = self.unparse_node(ctx)
        cn = CodeNode(self.get_location(ctx.lineno), func)
        cn.set_vars(self.get_tracked_vars())
        cn.set_funcs(self.get_tracked_funcs())
        cn.set_consts(self.get_tracked_consts())
        cn.set_node_type(FunctionCall)

        self.set_exit_nodes(self.add_node(cn))

    def enter_assignment(self, ctx):
        if self.do_not_parse != 0:
            return

        self.reset_tracking()

        expr = self.unparse_node(ctx)
        assign = self.unparse_node(ctx.node)

        cn = CodeNode(self.get_location(ctx.lineno), 'expression', assign=assign, text=expr, tainted=self.is_tainted(ctx.expr))
        cn.set_vars(self.get_tracked_vars() - {assign})
        cn.set_funcs(self.get_tracked_funcs())
        cn.set_consts(self.get_tracked_consts())

        self.set_exit_nodes(self.add_node(cn))

    def enter_assign_op(self, ctx):
        if self.do_not_parse != 0:
            return

        self.reset_tracking()

        expr = self.unparse_node(ctx)
        assign = self.unparse_node(ctx.left)

        cn = CodeNode(self.get_location(ctx.lineno), 'expression', assign=assign, text=expr, tainted=self.is_tainted(ctx.right))
        cn.set_vars(self.get_tracked_vars() - {assign})
        cn.set_funcs(self.get_tracked_funcs())
        cn.set_consts(self.get_tracked_consts())

        self.set_exit_nodes(self.add_node(cn))

    def enter_echo(self, ctx):
        if self.do_not_parse == 0:
            self.reset_tracking()

            self.stmt_funcs.add('echo')

            if all(self.is_tainted(x) == Tainted.NOT_TAINTED for x in ctx.nodes):
                tainted = Tainted.NOT_TAINTED
            else:
                tainted = Tainted.MAYBE_TAINTED

            cn = CodeNode(self.get_location(ctx.lineno), 'echo', 'echo %s' % ''.join(self.unparse_node(x) for x in ctx.nodes), tainted=tainted)
            cn.set_vars(self.get_tracked_vars())
            cn.set_funcs(self.get_tracked_funcs())
            cn.set_consts(self.get_tracked_consts())

            self.set_exit_nodes(self.add_node(cn))

        self.do_not_parse += 1

    def exit_echo(self, ctx):
        self.do_not_parse -= 1

    def enter_if(self, ctx):
        if self.do_not_parse != 0:
            return

        self.reset_tracking()
        expr = self.unparse_node(ctx.expr)

        cn = None
        assign = None

        if isinstance(ctx.expr, BinaryOp):
            if isinstance(ctx.expr.left, Assignment):
                assign = self.unparse_node(ctx.expr.left.node)

                cn = self.add_node(CodeNode(self.get_location(ctx.lineno), 'if', 'if (%s)' % expr, assign=assign))
            elif isinstance(ctx.expr.right, Assignment):
                assign = self.unparse_node(ctx.expr.right.node)

                cn = self.add_node(CodeNode(self.get_location(ctx.lineno), 'if', 'if (%s)' % expr, assign=assign))

        if cn is None:
            cn = self.add_node(CodeNode(self.get_location(ctx.lineno), 'if', 'if (%s)' % expr))

        cn.set_vars(self.get_tracked_vars() - {assign})
        cn.set_funcs(self.get_tracked_funcs())

        self.if_nodes.append((cn, False))

        self.set_exit_nodes(cn)

    def exit_if(self, ctx):
        if self.do_not_parse != 0:
            return

        (n, else_set) = self.if_nodes.pop()

        exit_nodes = [x for x in self.G.nodes_iter() if self.G.out_degree(x) == 0 and
                      shortest_paths.has_path(self.G, n, x)] # TODO: This is a performance killer

        if not else_set:
            exit_nodes.append(n)

        self.set_exit_nodes(exit_nodes)

    def enter_elseif(self, ctx):
        if self.do_not_parse != 0:
            return

        (n, _) = self.if_nodes[-1]
        self.set_exit_nodes(n)

    def enter_else(self, ctx):
        if self.do_not_parse != 0:
            return

        (n, _) = self.if_nodes.pop()
        self.set_exit_nodes(n)
        self.if_nodes.append((n, True))

    def enter_while(self, ctx):
        if self.do_not_parse != 0:
            return

        self.reset_tracking()

        # Get the expression between the parenthesis
        expr = self.unparse_node(ctx.expr)

        if isinstance(ctx.expr, Assignment):
            # We found an assignment in the expression
            assign = self.unparse_node(ctx.expr.node)
            tainted = self.is_tainted(ctx.expr.node)
        else:
            assign = None
            tainted = Tainted.MAYBE_TAINTED

        cn = self.add_node(CodeNode(self.get_location(ctx.lineno), 'while', text='while (%s)' % expr, assign=assign,
                                    tainted=tainted))
        cn.set_vars(self.get_tracked_vars())
        cn.set_funcs(self.get_tracked_funcs())
        cn.set_consts(self.get_tracked_consts())

        self.while_nodes.append(cn)
        self.set_exit_nodes(cn)

    def exit_while(self, ctx):
        if self.do_not_parse != 0:
            return

        while_node = self.while_nodes.pop()

        if len(self.exit_nodes) > 1:
            self.set_exit_nodes(self.add_node(CodeNode(("", -1), 'empty')))  # TODO

        if len(self.exit_nodes) > 0:
            self.add_edge(self.exit_nodes[0], while_node)

        self.add_exit_node(while_node)

    def enter_do_while(self, ctx):
        if self.do_not_parse != 0:
            return

        n = self.add_node(CodeNode(self.get_location(ctx.lineno), 'do'))

        self.do_nodes.append(n)

        self.set_exit_nodes(n)

    def exit_do_while(self, ctx):
        if self.do_not_parse != 0:
            return

        self.reset_tracking()

        # Get the expression between the parenthesis
        expr = self.unparse_node(ctx.expr)

        do_node = self.do_nodes.pop()

        cn = CodeNode(self.get_location(ctx.lineno), 'while', 'while (%s)' % expr)

        cn.set_vars(self.get_tracked_vars())
        cn.set_funcs(self.get_tracked_funcs())
        cn.set_consts(self.get_tracked_consts())

        self.set_exit_nodes(self.add_node(cn))

        self.add_edge(self.exit_nodes[0], do_node)

    def enter_for(self, ctx):
        if self.do_not_parse != 0:
            return

        # TODO: Figure out how to get the expression out

        n = self.add_node(CodeNode(self.get_location(ctx.lineno), 'for', 'for'))

        self.for_nodes.append(n)
        self.set_exit_nodes(n)

    def exit_for(self, ctx):
        if self.do_not_parse != 0:
            return

        for_node = self.for_nodes.pop()

        if len(self.exit_nodes) > 1:
            self.set_exit_nodes(self.add_node(CodeNode(("", -1), 'empty'))) # TODO

        if len(self.exit_nodes) > 0:
            self.add_edge(self.exit_nodes[0], for_node)

    def enter_foreach(self, ctx):
        if self.do_not_parse != 0:
            return

        n = self.add_node(CodeNode(self.get_location(ctx.lineno), 'foreach'))

        self.for_nodes.append(n)
        self.set_exit_nodes(n)

    def exit_foreach(self, ctx):
        if self.do_not_parse != 0:
            return

        foreach_node = self.for_nodes.pop()

        if len(self.exit_nodes) > 1:
            self.set_exit_nodes(self.add_node(CodeNode(("", -1), 'empty'))) # TODO

        if len(self.exit_nodes) > 0:
            self.add_edge(self.exit_nodes[0], foreach_node)

    def unparse_node(self, node):
        self.traversed.append(node)

        if isinstance(node, (str, int, float)):
            return repr(node)

        if isinstance(node, InlineHTML):
            return str(node.data)

        if isinstance(node, Constant):
            self.stmt_consts.add(str(node.name))

            return str(node.name)

        if isinstance(node, Variable):
            self.stmt_vars.add(str(node.name))
            return str(node.name)

        if isinstance(node, Echo):
            return '{{ %s }}' % (''.join(self.unparse_node(x) for x in node.nodes))

        if isinstance(node, (Include, Require)):
            return '{%% include %s -%%}' % (self.unparse_node(node.expr))

        if isinstance(node, Block):
            return ''.join(self.unparse_node(x) for x in node.nodes)

        if isinstance(node, ArrayOffset):
            return '%s[%s]' % (self.unparse_node(node.node),
                               self.unparse_node(node.expr))

        if isinstance(node, ObjectProperty):
            return '%s.%s' % (self.unparse_node(node.node), node.name)

        if isinstance(node, Array):
            elems = []
            for elem in node.nodes:
                elems.append(self.unparse_node(elem))
            if node.nodes and node.nodes[0].key is not None:
                return '{%s}' % ', '.join(elems)
            else:
                return '[%s]' % ', '.join(elems)

        if isinstance(node, ArrayElement):
            if node.key:
                return '%s: %s' % (self.unparse_node(node.key),
                                   self.unparse_node(node.value))
            else:
                return self.unparse_node(node.value)

        if isinstance(node, Assignment):
            if isinstance(node.node, ArrayOffset) and node.node.expr is None:
                return '{%% do %s.append(%s) -%%}' % (self.unparse_node(node.node.node),
                                                      self.unparse_node(node.expr))
            else:
                return '%s = %s' % (self.unparse_node(node.node),
                                    self.unparse_node(node.expr))

        if isinstance(node, UnaryOp):
            return '%s %s' % (node.op, self.unparse_node(node.expr))

        if isinstance(node, BinaryOp):
            return '%s %s %s' % (self.unparse_node(node.left), node.op, self.unparse_node(node.right))

        if isinstance(node, TernaryOp):
            return '%s ? %s : %s' % (self.unparse_node(node.expr),
                                     self.unparse_node(node.iftrue),
                                     self.unparse_node(node.iffalse))

        if isinstance(node, IsSet):
            if len(node.nodes) == 1:
                return '(%s is defined)' % self.unparse_node(node.nodes[0])
            else:
                tests = ['(%s is defined)' % self.unparse_node(n)
                         for n in node.nodes]
                return '(' + ' and '.join(tests) + ')'

        if isinstance(node, Empty):
            return '(not %s)' % (self.unparse_node(node.expr))

        if isinstance(node, Silence):
            return self.unparse_node(node.expr)

        if isinstance(node, Cast):
            filter = ''
            if node.type in ('int', 'float', 'string'):
                filter = '|%s' % node.type
            return '%s%s' % (self.unparse_node(node.expr), filter)

        if isinstance(node, If):
            body = self.unparse_node(node.node)
            for elseif in node.elseifs:
                body += '{%% elif %s -%%}%s' % (self.unparse_node(elseif.expr),
                                                self.unparse_node(elseif.node))
            if node.else_:
                body += '{%% else -%%}%s' % (self.unparse_node(node.else_.node))
            return '{%% if %s -%%}%s{%% endif -%%}' % (self.unparse_node(node.expr),
                                                       body)

        if isinstance(node, While):
            dummy = Foreach(node.expr, None, ForeachVariable('$XXX', False), node.node)
            return self.unparse_node(dummy)

        if isinstance(node, Foreach):
            var = node.valvar.name[1:]
            if node.keyvar:
                var = '%s, %s' % (node.keyvar.name[1:], var)
            return '{%% for %s in %s -%%}%s{%% endfor -%%}' % (var,
                                                               self.unparse_node(node.expr),
                                                               self.unparse_node(node.node))

        if isinstance(node, Function):
            name = node.name
            params = []
            for param in node.params:
                params.append(param.name[1:])

            params = ', '.join(params)
            return '%s(%s)' % (name, params)

        if isinstance(node, Return):
            return 'return %s' % self.unparse_node(node.node)

        if isinstance(node, FunctionCall):
            self.stmt_funcs.add(str(node.name))

            # if node.name.endswith('printf'):
            #     params = [self.unparse_node(x.node) for x in node.params[1:]]
            #
            #     return '%s %% (%s,)' % (self.unparse_node(node.params[0].node),
            #                             ', '.join(params))

            params = ', '.join(self.unparse_node(param.node)
                               for param in node.params)

            return '%s(%s)' % (node.name, params)

        if isinstance(node, MethodCall):
            params = ', '.join(self.unparse_node(param.node)
                               for param in node.params)

            return '%s.%s(%s)' % (self.unparse_node(node.node),
                                  node.name, params)

        return 'XXX(%r)' % str(node)

    # TODO:
    # A bit of a clumsy solution. Methods are expected to reset the tracking lists before using the unparse_node method.
    def reset_tracking(self):
        self.stmt_vars = set()
        self.stmt_funcs = set()
        self.stmt_consts = set()

    def get_tracked_vars(self):
        return self.stmt_vars

    def get_tracked_funcs(self):
        return self.stmt_funcs

    def get_tracked_consts(self):
        return self.stmt_consts

    def add_exit_node(self, exit_node):
        self.exit_nodes.append(exit_node)

    def set_exit_nodes(self, exit_nodes):
        if not isinstance(exit_nodes, list):
            self.exit_nodes = [exit_nodes]
        else:
            self.exit_nodes = exit_nodes

        return self.exit_nodes

    def add_edge(self, n1, n2):
        self.G.add_edge(n1, n2)

    def add_node(self, n):
        self.G.add_node(n, n.get_attr())

        if len(self.in_functions) > 0:
            # We're in a function
            (func, _) = self.in_functions[-1]

            if func not in self.functions:
                # Save start and end node in functions dict
                self.functions[func] = (n, n)

                self.exit_nodes = []

                return n
            else:
                start_node, end_node = self.functions[func]

                self.functions[func] = (start_node, n)

        if len(self.exit_nodes) > 0:
            for exit_node in self.exit_nodes:
                    self.G.add_edge(exit_node, n)

        self.exit_nodes = []

        return n

    def get_backlog(self):
        return self.backlog

    def get_graph(self):
        if len(self.exit_nodes) > 1:
            empty = CodeNode(("", -1), 'empty')
            self.add_node(empty)

        for cn in [x for x in self.G.nodes_iter() if x.get_node_type() == FunctionCall]:
            func_id = self.generate_func_id(cn.get_stmt())

            if func_id in self.functions:
                (start_node, end_node) = self.functions[func_id]

                self.add_edge(cn, start_node)
                self.add_edge(end_node, cn)

        change = True

        # Calculate inset and outset for Reaching Definitions
        while change:
            change = False

            for n in self.G.nodes_iter():
                n.inset = reduce(lambda x, y: x | y, [0] + [x.outset for x in self.G.predecessors(n)])

                old_outset = n.outset
                n.outset = n.gen | (n.inset & ~n.kill)

                if old_outset != n.outset:
                    change = True

        return self.G

    def is_traversed(self, node):
        # We use the 'is' keyword for an exact comparison
        return bool([n for n in self.traversed if n is node])

    def get_location(self, line_no):
        if self.line_map[line_no]:
            return self.line_map[line_no]
        else:
            return "", -1

    @staticmethod
    def is_tainted(expr):
        types = [float, bool, int, str]
        types_str = ('int', 'float', 'double', 'bool', 'long')

        # tainted = -1 is maybe tainted, tainted = 0 is not tainted
        tainted = Tainted.MAYBE_TAINTED

        if type(expr) in types:
            # assigning primitive types
            tainted = Tainted.NOT_TAINTED
        elif isinstance(expr, Cast) and expr.type in types_str:
            # casting to primitive types
            tainted = Tainted.NOT_TAINTED
        elif isinstance(expr, BinaryOp) and expr.op != '.' and (type(expr.left) in types or type(expr.right) in types):
            # arithmetic with primitive types
            tainted = Tainted.NOT_TAINTED
        elif isinstance(expr, TernaryOp) and (type(expr.iffalse) in types or type(expr.iftrue) in types):
            # ternary with primitive result types
            tainted = Tainted.NOT_TAINTED
        elif hasattr(expr, 'name') and (expr.name == 'floatval' or expr.name == 'intval'):
            # floatval() returns float, intval() returns int
            tainted = Tainted.NOT_TAINTED

        return tainted

    @staticmethod
    def generate_func_id(func):
        match = re.search("(.*)\((.*)\)", func)

        func_name = match.group(1)
        params = match.group(2)

        if params == '':
            params = []
        else:
            params = params.split(',')

        # We create a unique function ID by combining its name with the number of its parameters
        return "%s%d" % (func_name, len(params))



