import os
import random

import pickle

from wirecaml.tools import config
from wirecaml.tools.ascii import print_notice, print_warning


class Dataset:
    def __init__(self, pickle_path):
        self.pickle_path = pickle_path
        self.sampling_perc = dict()
        self.sampling_perc['SQLi'] = config.get_float('dataset', 'SamplingPercentageSQLi')
        self.sampling_perc['XSS'] = config.get_float('dataset', 'SamplingPercentageXSS')

    def create_sets(self):
        pass

    def get_sets(self):
        pkl = self.pickle_path

        # Load the pickle file
        print_notice("Loading pickle file")

        with open(pkl, 'rb') as pickle_file:
            sets = pickle.load(pickle_file)

        if self.sampling_perc['SQLi'] < 1.0 or self.sampling_perc['XSS'] < 1.0:
            return self.sample_set(sets)

        return sets

    def sample_set(self, sets):
        filtered_set = dict()
        filtered_set['flaw_dict'] = sets['flaw_dict']

        for set_name in ['training_set', 'tuning_set', 'testing_set']:
            filtered_set[set_name] = dict()
            filtered_set[set_name]['PHP'] = dict()

            for vuln_type in ['SQLi', 'XSS']:
                filtered_set[set_name]['PHP'][vuln_type] = []

                for file in sets[set_name]['PHP'][vuln_type]:
                    r = random.random()

                    if file in sets['flaw_dict']['PHP'][vuln_type] and len(sets['flaw_dict']['PHP'][vuln_type][file]) > 0:
                        filtered_set[set_name]['PHP'][vuln_type].append(file)
                    elif r < self.sampling_perc[vuln_type]:
                        filtered_set[set_name]['PHP'][vuln_type].append(file)

        return filtered_set

    def delete_sets(self):
        pkl = self.pickle_path

        if os.path.isfile(pkl):
            print_notice("Removing %s" % pkl)
            os.remove(pkl)
        else:
            print_warning("Unable to remove %s. File does not exist." % pkl)
