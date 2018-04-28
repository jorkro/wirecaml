from wirecaml.preparation.dataset_both import BothDataset
from wirecaml.preparation.dataset_custom import CustomDataset
from wirecaml.preparation.dataset_nvd import NvdDataset
from wirecaml.preparation.dataset_samate import SamateDataset


def get_dataset(ds):
    if ds.lower() == 'samate':
        ds = SamateDataset()

        ds.create_sets()

        return ds
    elif ds.lower() == 'nvd':
        ds = NvdDataset()

        ds.create_sets()

        return ds
    elif ds.lower() == 'both':
        ds = BothDataset()

        ds.create_sets()

        return ds
    elif ds.lower() == 'custom':
        ds = CustomDataset()

        ds.create_sets()

        return ds
    else:
        return None

