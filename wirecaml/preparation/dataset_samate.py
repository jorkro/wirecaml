import os
import pickle
from random import shuffle

from lxml import etree as et

from wirecaml.preparation.dataset import Dataset
from wirecaml.tools import config
from wirecaml.tools.ascii import print_notice
from wirecaml.tools.data_tools import slice_perc


class SamateDataset(Dataset):
    def __init__(self):
        super(SamateDataset, self).__init__(config.get_str('SAMATE', 'SamatePickle'))

    @staticmethod
    def get_file_list(vuln_type):
        flaw_dir = config.get_str('SAMATE', 'SamateDirectory')
        flaw_dict = {}

        if vuln_type == 'XSS':
            flaw_dir += '/XSS'
        elif vuln_type == 'SQLi':
            flaw_dir += '/Injection'

        lst = []

        tree = et.parse(flaw_dir + "/manifest.xml")

        for file in tree.findall('testcase/file'):
            p = file.get('path')

            if not p.startswith('CWE_79') and not p.startswith('CWE_89'):
                continue

            file_path = flaw_dir + '/' + p

            flaw = file.find('flaw')

            if flaw is not None:
                flaw_dict[file_path] = [int(flaw.get('line'))]
            else:
                flaw_dict[file_path] = []

            lst.append(file_path)

        return flaw_dict, lst

    def create_sets(self):
        language = 'PHP'  # TODO: What are we going to do with Python?
        samate_pickle = config.get_str('SAMATE', 'SamatePickle')

        if not os.path.isfile(samate_pickle):
            training_perc = config.get_int('dataset', 'TrainingPercentage')
            tuning_perc = config.get_int('dataset', 'TuningPercentage')

            training_set = {language: {}}
            tuning_set = {language: {}}
            testing_set = {language: {}}
            flaw_dict = {language: {}}

            for vuln_type in config.get_list('dataset', 'Vulnerabilities'):
                flaws, lst = self.get_file_list(vuln_type)

                flaw_dict[language][vuln_type] = flaws
                shuffle(lst)

                training_set[language][vuln_type] = slice_perc(lst, 0, training_perc)
                tuning_set[language][vuln_type] = slice_perc(lst, training_perc, training_perc + tuning_perc)
                testing_set[language][vuln_type] = slice_perc(lst, training_perc + tuning_perc, 100)

            dataset = {'training_set': training_set, 'tuning_set': tuning_set, 'testing_set': testing_set,
                       'flaw_dict': flaw_dict}

            # Save to pickle file for future use
            with open(samate_pickle, 'wb') as pickle_file:
                pickle.dump(dataset, pickle_file)
        else:
            print_notice("Pickle file already created")
