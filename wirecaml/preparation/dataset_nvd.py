import os
import pickle
from os import listdir, walk
from os.path import isdir, join, abspath
from random import shuffle

from unidiff import PatchSet

from wirecaml.preparation.dataset import Dataset
from wirecaml.tools import config
from wirecaml.tools.ascii import print_notice
from wirecaml.tools.data_tools import slice_perc


class NvdDataset(Dataset):
    def __init__(self):
        super(NvdDataset, self).__init__(config.get_str('NVD', 'NvdPickle'))

    @staticmethod
    def get_vulnerables_lines(dir):
        flaw_dict = {}
        patch_file = join(dir, 'patch/file.patch')
        patch = PatchSet.from_filename(patch_file, encoding='latin-1')

        for file in patch:
            filename = abspath(join(dir, 'app', file.path))

            # Produces a list of vulnerable line numbers
            vulnerable_lines = [line.source_line_no for hunk in file for line in hunk if line.is_removed]

            flaw_dict[filename] = vulnerable_lines

        return flaw_dict

    @staticmethod
    def add_to_list(lst, language, vuln_type, file):
        if language not in lst:
            lst[language] = {vuln_type: [file]}
        elif vuln_type not in lst[language]:
            lst[language][vuln_type] = [file]
        else:
            lst[language][vuln_type].append(file)

        return lst

    def create_list(self, my_vuln_path, languages, vuln_types, training_perc, tuning_perc):
        vuln_list = {}
        training_set = {}
        tuning_set = {}
        testing_set = {}
        flaw_dict = {}

        # Create list
        for language in languages:
            if language not in flaw_dict:
                flaw_dict[language] = {}

            for vuln_type in vuln_types:
                if vuln_type not in flaw_dict:
                    flaw_dict[language][vuln_type] = {}

                vuln_path = my_vuln_path + "/%s/%s" % (language, vuln_type)
                for cve_id in listdir(vuln_path):
                    cve_path = join(vuln_path, cve_id)
                    app_path = join(cve_path, 'app')

                    if isdir(app_path):
                        vulnerable_lines = self.get_vulnerables_lines(cve_path)

                        flaw_dict[language][vuln_type] = {**flaw_dict[language][vuln_type], **vulnerable_lines}

                        files = [abspath(join(dp, f)) for dp, dn, fn in walk(app_path) for f in fn if f.endswith('.php')]

                        for file in files:
                            vuln_list = self.add_to_list(vuln_list, language, vuln_type, file)

        # Shuffle list
        for language in languages:
            training_set[language] = {}
            tuning_set[language] = {}
            testing_set[language] = {}

            for vuln_type in vuln_types:
                if vuln_type not in vuln_list[language]:
                    continue

                shuffle(vuln_list[language][vuln_type])
                lst = vuln_list[language][vuln_type]

                training_set[language][vuln_type] = slice_perc(lst, 0, training_perc)
                tuning_set[language][vuln_type] = slice_perc(lst, training_perc, training_perc + tuning_perc)
                testing_set[language][vuln_type] = slice_perc(lst, training_perc + tuning_perc, 100)

        return {'training_set': training_set, 'tuning_set': tuning_set, 'testing_set': testing_set,
                'flaw_dict': flaw_dict}

    def create_sets(self):
        source_dir = config.get_str('NVD', 'SourceDirectory')
        nvd_pickle = config.get_str('NVD', 'NvdPickle')
        languages = config.get_list('dataset', 'Languages')
        vulnerabilities = config.get_list('dataset', 'Vulnerabilities')

        if not os.path.isfile(nvd_pickle):

            dataset = self.create_list(source_dir, languages, vulnerabilities,
                                       config.get_int('dataset', 'TrainingPercentage'),
                                       config.get_int('dataset', 'TuningPercentage'))

            # Save to pickle file for future use
            with open(nvd_pickle, 'wb') as pickle_file:
                pickle.dump(dataset, pickle_file)
        else:
            print_notice("Pickle file already created")