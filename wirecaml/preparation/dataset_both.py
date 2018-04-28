from wirecaml.preparation.dataset import Dataset
from wirecaml.preparation.dataset_nvd import NvdDataset
from wirecaml.preparation.dataset_samate import SamateDataset
from wirecaml.tools import config


class BothDataset(Dataset):
    def __init__(self):
        self.ds1 = SamateDataset()
        self.ds2 = NvdDataset()

    def create_sets(self):
        self.ds1.create_sets()
        self.ds2.create_sets()

    def get_sets(self):
        s1 = self.ds1.get_sets()
        s2 = self.ds2.get_sets()

        s3 = dict()

        for s in ['flaw_dict', 'training_set', 'tuning_set', 'testing_set']:
            for language in config.get_list('dataset', 'Languages'):
                s3[s] = {language: dict()}

                for vuln_type in config.get_list('dataset', 'Vulnerabilities'):
                    if type(s1[s][language][vuln_type]) == dict:
                        s3[s][language][vuln_type] = {**s1[s][language][vuln_type], **s2[s][language][vuln_type]}
                    else:  # list
                        s3[s][language][vuln_type] = s1[s][language][vuln_type] + s2[s][language][vuln_type]

        return s3

    def delete_sets(self):
        self.ds1.delete_sets()
        self.ds2.delete_sets()
