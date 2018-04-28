from wirecaml.extraction.definition_register import DefinitionRegister
from enum import Enum


class Tainted(Enum):
    TAINTED = 1
    NOT_TAINTED = 0
    MAYBE_TAINTED = -1
    MAYBE_TAINTED_TRACKED = -2


class CodeNode:
    def __init__(self, loc, stmt, text='', assign=None, tainted=Tainted.MAYBE_TAINTED):
        self.file = loc[0]
        self.line = loc[1]
        self.stmt = stmt
        self.text = text
        self.stmt_vars = set()
        self.stmt_funcs = set()
        self.stmt_consts = set()
        self.tainted = tainted

        self.inset = 0

        if assign is not None:
            gen_bits, kill_bits = DefinitionRegister.get_gen_kill(self, assign)

            self.gen = gen_bits
            self.kill = kill_bits

            self.outset = gen_bits
        else:
            self.gen = 0
            self.kill = 0
            self.outset = 0

        self.font_name = 'Verdana'
        self.font_size = 10
        self.node_style = ''
        self.node_shape = 'rect'
        self.node_type = None

    def get_attr(self):
        if self.line < 0:
            label_text = ""
        elif self.text != '':
            # escape double quotes
            text = self.text.replace("\"", "\\\"")

            label_text = '"%s:%s:%s"' % (self.file, self.line, text)
        else:
            label_text = '"%s:%s:%s"' % (self.file, self.line, self.stmt)

        return {
            'fontname': self.font_name,
            'fontsize': self.font_size,
            'style': self.node_style,
            'shape': self.node_shape,
            'label': label_text,
            'assign': self.gen
        }

    def set_node_type(self, type):
        self.node_type = type

    def get_node_type(self):
        return self.node_type

    def set_vars(self, v):
        self.stmt_vars = v

    def is_tainted(self):
        if self.tainted == Tainted.MAYBE_TAINTED:
            self.tainted = Tainted.MAYBE_TAINTED_TRACKED

            nodes = self.get_node_deps()

            if nodes == set():
                # If we're maybe tainted and not dependent on other nodes, we're tainted
                self.tainted = Tainted.TAINTED
            else:
                tainted_nodes = [n.is_tainted() for n in nodes]

                if any(tainted_nodes):
                    # If any of the nodes we depend on is tainted, we're tainted
                    self.tainted = Tainted.TAINTED
                else:
                    self.tainted = Tainted.NOT_TAINTED
        elif self.tainted == Tainted.MAYBE_TAINTED_TRACKED:
            self.tainted = Tainted.TAINTED

        return bool(self.tainted.value)

    def set_funcs(self, f):
        self.stmt_funcs = f

    def get_funcs(self):
        return self.stmt_funcs

    def get_stmt(self):
        return self.stmt

    def set_consts(self, f):
        self.stmt_consts = f

    def get_consts(self):
        return self.stmt_consts

    def calculate_use_defs(self):
        bitmask = DefinitionRegister.get_def_bitmask(self.stmt_vars)

        return self.inset & bitmask

    def get_node_deps(self):
        nodes = set()
        i = 0

        bitmask = self.calculate_use_defs()

        while (1 << i) <= bitmask:
            if (1 << i) & bitmask != 0:
                nodes.add(DefinitionRegister.get_def_int(i))

            i += 1

        return nodes

    def __str__(self):
        return str(id(self))

    def __repr__(self):
        return str(id(self))
