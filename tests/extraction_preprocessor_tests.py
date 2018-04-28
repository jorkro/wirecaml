from nose.tools import *
from wirecaml.extraction.preprocessor import Preprocessor
from os.path import join

pre = None
working_dir = "tests/examples"


def setup():
    global pre

    pre = Preprocessor(working_dir)


def teardown():
    pass


def test_preprocess_file_no_include():
    path = "tests/examples/test_preprocess_no_include.php"

    _, preprocess_output = pre.preprocess_file(path)

    with open(path, encoding="latin-1") as inp:
        read_output = inp.read()

    assert_equal(read_output.rstrip(), preprocess_output)


def test_preprocess_file_include():
    path = "tests/examples/test_preprocess_include.php"

    _, preprocess_output = pre.preprocess_file(path)

    file_output = "<?php\n\n\necho \"Test\";\n\n"

    assert_equal(file_output, preprocess_output)


def test_parse_file_name():
    global working_dir

    pre.reset_included_files()

    p1 = pre.parse_file_name("\"test_preprocess_include.php\"")
    assert_equal(join(working_dir, "test_preprocess_include.php"), p1)

    pre.reset_included_files()

    p2 = pre.parse_file_name("\'test_preprocess_include.php\'")
    assert_equal(join(working_dir, "test_preprocess_include.php"), p2)

    pre.reset_included_files()

    p3 = pre.parse_file_name(" \" test_preprocess_include.php \" ")
    assert_equal(join(working_dir, "test_preprocess_include.php"), p3)

