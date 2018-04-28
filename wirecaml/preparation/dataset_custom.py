import os
import pickle
from os import walk
from os.path import isdir, join, abspath

from wirecaml.preparation.dataset import Dataset
from wirecaml.tools import config
from wirecaml.tools.ascii import print_notice


class CustomDataset(Dataset):
    def __init__(self):
        super(CustomDataset, self).__init__(config.get_str('analysis', 'CustomPickle'))

    @staticmethod
    def add_to_list(lst, language, vuln_type, file):
        if language not in lst:
            lst[language] = {vuln_type: [file]}
        elif vuln_type not in lst[language]:
            lst[language][vuln_type] = [file]
        else:
            lst[language][vuln_type].append(file)

        return lst

    def create_list(self, app_path, languages, vuln_types):
        vuln_list = {}
        training_set = {}
        tuning_set = {}
        testing_set = {}
        flaw_dict = {}

        if isdir(app_path):
            files = [abspath(join(dp, f)) for dp, dn, fn in walk(app_path) for f in fn if f.endswith('.php') or
                     f.endswith('.phar')]
        else:
            files = None

        # Create list
        for language in languages:
            if language not in flaw_dict:
                flaw_dict[language] = {}

            for vuln_type in vuln_types:
                if vuln_type not in flaw_dict:
                    flaw_dict[language][vuln_type] = {}

                if isdir(app_path) and files is not None:
                    for file in files:
                        vuln_list = self.add_to_list(vuln_list, language, vuln_type, file)

        for language in languages:
            training_set[language] = {}
            tuning_set[language] = {}
            testing_set[language] = {}

            for vuln_type in vuln_types:
                if vuln_type not in vuln_list[language]:
                    continue

                training_set[language][vuln_type] = []
                tuning_set[language][vuln_type] = []
                testing_set[language][vuln_type] = vuln_list[language][vuln_type]

        return {'training_set': training_set, 'tuning_set': tuning_set, 'testing_set': testing_set,
                'flaw_dict': flaw_dict}

    def create_sets(self):
        source_dir = config.get_str('analysis', 'CustomTestSet')
        custom_pickle = config.get_str('analysis', 'CustomPickle')
        languages = config.get_list('dataset', 'Languages')
        vulnerabilities = config.get_list('dataset', 'Vulnerabilities')

        if not os.path.isfile(custom_pickle):

            dataset = self.create_list(source_dir, languages, vulnerabilities)

            # Save to pickle file for future use
            with open(custom_pickle, 'wb') as pickle_file:
                pickle.dump(dataset, pickle_file)
        else:
            print_notice("Pickle file already created")

    def get_sets(self):
        sets = super(CustomDataset, self).get_sets()

        return sets
