import os

import networkx as nx

from phply.phplex import lexer
from phply.phpparse import make_parser

from wirecaml.extraction.definition_register import DefinitionRegister
from wirecaml.extraction.my_php_listener import MyPHPListener
from wirecaml.extraction.phptraverser import php_traverser
from wirecaml.extraction.preprocessor import Preprocessor
from wirecaml.tools import config


def create_graph(path, file):
    # Preprocess file so includes are considered
    pre = Preprocessor(path)

    # Line map contains a mapping between line number and original file + original line number
    line_map, file_str = pre.preprocess_file(file)

    # Reset definition register with every new graph
    DefinitionRegister.reset()

    # Make a parser
    parser = make_parser()

    # Make a lexer
    l = lexer.clone()

    nodes = parser.parse(file_str, lexer=l, tracking=True, debug=False)

    listener = MyPHPListener(line_map=line_map, name=file)

    php_traverser.traverse(nodes, listener)

    return listener.get_graph()


def create_png(graph):
        graph_dir = config.get_str('CFG', 'GraphDirectory')
        basename = os.path.basename(graph.name)

        dot_file = os.path.join(graph_dir, '%s.dot' % basename)
        png_file = os.path.join(graph_dir, '%s.png' % basename)

        # Write DOT file
        nx.nx_pydot.write_dot(graph, dot_file)

        # Convert DOT to PNG
        os.system("dot -Tpng %s >%s" % (dot_file, png_file))

