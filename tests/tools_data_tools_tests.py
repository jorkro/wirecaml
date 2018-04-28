from wirecaml.tools.data_tools import slice_perc


def setup():
    pass


def teardown():
    pass


def test_slice_perc():
    for n in range(0, 100):
        x = list(range(0, n))

        l1 = slice_perc(x, 0, 70)
        l2 = slice_perc(x, 70, 80)
        l3 = slice_perc(x, 80, 100)

        assert(len(l1) + len(l2) + len(l3) == n)

