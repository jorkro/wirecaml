from nose.tools import *
from wirecaml.preparation import dataset_factory
from wirecaml.tools import config


def setup():
    config.init(config_filename='config.ini')


def teardown():
    pass


def test_sample_nvd():
    config.set('NVD', 'SamplingPercentageSQLi', 1.0)
    config.set('NVD', 'SamplingPercentageXSS', 1.0)
    nvd = dataset_factory.get_dataset('nvd')
    sets = nvd.get_sets()

    config.set('NVD', 'SamplingPercentageSQLi', 0.5)
    config.set('NVD', 'SamplingPercentageXSS', 0.5)
    nvd = dataset_factory.get_dataset('nvd')
    sampled_sets = nvd.get_sets()

    for s in ['training_set', 'tuning_set', 'testing_set']:
        assert_greater(len(sets[s]['PHP']['SQLi']), len(sampled_sets[s]['PHP']['SQLi']))
        assert_greater(len(sets[s]['PHP']['XSS']), len(sampled_sets[s]['PHP']['XSS']))