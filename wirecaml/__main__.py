# Ignoring deprecation warnings (and all other warnings)
import warnings


def warn(*args, **kwargs):
    pass

warnings.warn = warn

from wirecaml.analysis import data
from wirecaml.analysis.metrics import display_pr_curve, print_metrics, display_prob_histogram, compare_results, \
    print_model_results, find_best_threshold
from wirecaml.model import train
from wirecaml.preparation import dataset_factory
from wirecaml.tools import config
from wirecaml.tools.ascii import print_banner, print_notice
from wirecaml.transformation import transform
from sklearn.calibration import CalibratedClassifierCV
import numpy as np
import sys

sets = None
model = None
popular_features = None
selected_features = None
train_features = None
language = None
vuln_type = None
visited = []
X_test = None
Y_test = None

dependencies = {'clean_set': ['clean_transform'],
                'clean_all': ['clean_set', 'clean_custom'],
                'create_features': ['create_set'],
                'create_transform': ['create_set'],
                'create_model': ['create_transform'],
                'tune_params': ['create_transform'],
                'calibrate_model': ['create_model'],
                'select_features': ['create_transform'],
                'filter_features': ['create_transform'],
                'test_model': ['create_model'],
                'store_outliers': ['create_model'],
                'store_custom': ['create_model'],
                'store_all': ['create_model'],
                'display_model': ['test_model'],
                'display_histo': ['test_model'],
                'compare_tools': ['create_model'],
                'count_sets': ['create_transform']}


def get_dependencies(i):
    l = [i]

    if i in dependencies:
        for dep in dependencies[i]:
            l = get_dependencies(dep) + l
        return l
    else:
        return l


def run_commands(commands):
    for command in commands:
        deps = get_dependencies(command)

        for ex in deps:
            if ex not in visited:
                globals()["cmd_" + ex]()
                visited.append(ex)


def print_help():
    print_notice("Valid commands are:")
    valid_commands = sorted([k[4:] for k in globals().keys() if k[:4] == 'cmd_'])

    print_notice(', '.join(valid_commands))
    exit(0)


def sync_features(X):
    missing_cols = set(train_features) - set(X.columns)
    drop_cols = set(X.columns) - set(train_features)

    for c in missing_cols:
        X[c] = 0

    X.drop(drop_cols, axis=1, inplace=True)

    X.sort_index(axis=1, inplace=True)

    return X


# --- Define commands to run --
def cmd_clean_set():
    print_banner("Cleaning sets")

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    dataset_factory.get_dataset(sel_ds).delete_sets()


def cmd_clean_custom():
    print_banner("Cleaning custom set")

    sel_ds = 'Custom'

    dataset_factory.get_dataset(sel_ds).delete_sets()

    transform.delete_transforms([sel_ds])


def cmd_clean_transform():
    print_banner("Cleaning transforms")

    transform.delete_transforms()


def cmd_clean_all():
    pass


def cmd_create_set():
    print_banner("Building sets")

    global sets

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    sets = dataset_factory.get_dataset(sel_ds).get_sets()


def cmd_create_features():
    print_banner("Creating features")

    global popular_features

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    popular_features = transform.create_popular_features(sel_ds, sets, language)


def cmd_create_transform():
    print_banner("Transforming sets")

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    transform.transform_sets(sel_ds, sets, language)


def cmd_create_model():
    print_banner("Creating model")

    global model, train_features

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    X, Y = transform.get_xy(sel_ds, 'training_set', language, vuln_type, selected_features)

    X.sort_index(axis=1, inplace=True)

    if train_features is None:
        train_features = X.columns

    model = train.select_model(language, vuln_type, X, Y)


def cmd_tune_params():
    print_banner("Tuning model parameters")

    global model, train_features

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    X, Y = transform.get_xy(sel_ds, 'training_set', language, vuln_type, selected_features)

    X.sort_index(axis=1, inplace=True)

    if train_features is None:
        train_features = X.columns

    X_tuning, Y_tuning = transform.get_xy(sel_ds, 'tuning_set', language, vuln_type, selected_features)

    X_tuning = sync_features(X_tuning)

    train.select_best_model(X, Y, X_tuning, Y_tuning)


def cmd_calibrate_model():
    global model

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    X, Y = transform.get_xy(sel_ds, 'tuning_set', language, vuln_type, selected_features)

    X = sync_features(X)

    model = CalibratedClassifierCV(model, method='isotonic', cv='prefit')
    model.fit(X, Y)


def cmd_select_features():
    print_banner("Selecting features")

    global selected_features

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    X, Y = transform.get_xy(sel_ds, 'training_set', language, vuln_type)

    selected_features = train.select_features(X, Y)


def cmd_filter_features():
    print_banner("Filtering features")

    global selected_features

    start_string = config.get_str('model', 'FeatureFilterStartString')

    if selected_features is None:
        sel_ds = config.get_str('dataset', 'SelectedDataset')

        X, Y = transform.get_xy(sel_ds, 'training_set', language, vuln_type)

        selected_features = X.columns.values

    selected_features = [feature for feature in selected_features if not feature.startswith(start_string)]
    n = 1

    for feature in selected_features:
        print_notice("%d. %s" % (n, feature))
        n += 1


def cmd_store_outliers():
    print_banner("Store outliers")

    global model

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    orig, X, Y = transform.get_xy_with_orig(sel_ds, 'testing_set', language, vuln_type, selected_features)

    X = sync_features(X)

    data.store_data(model, orig, X, Y, just_outliers=True)


def cmd_store_custom():
    print_banner("Store custom test set results")

    global model

    print_notice("Creating a custom test set")
    sel_ds = 'Custom'

    my_sets = dataset_factory.get_dataset(sel_ds).get_sets()

    transform.transform_sets(sel_ds, my_sets, language)

    orig, X, Y = transform.get_xy_with_orig(sel_ds, 'testing_set', language, vuln_type, selected_features)

    X = sync_features(X)

    data.store_data(model, orig, X, Y, just_outliers=True, threshold=0.0)


def cmd_store_all():
    print_banner("Store all")

    global model

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    orig, X, Y = transform.get_xy_with_orig(sel_ds, 'testing_set', language, vuln_type, selected_features)

    X = sync_features(X)

    data.store_data(model, orig, X, Y, just_outliers=False)


def cmd_test_model():
    print_banner("Testing model")

    global X_test, Y_test

    sel_ds = config.get_str('dataset', 'SelectedDataset')

    X_test, Y_test = transform.get_xy(sel_ds, 'testing_set', language, vuln_type, selected_features)

    X_test = sync_features(X_test)

    print_metrics(model=model, X=X_test, Y=Y_test)


def cmd_display_model():
    print_banner("Displaying model")

    global X_test, Y_test

    model_type = config.get_str('model', 'Model')
    sel_ds = config.get_str('dataset', 'SelectedDataset')

    if X_test is None or Y_test is None:
        X_test, Y_test = transform.get_xy(sel_ds, 'testing_set', language, vuln_type, selected_features)

        X_test = sync_features(X_test)

    display_pr_curve(title="%s %s" % (vuln_type, model_type), model=model, X=X_test, Y=Y_test)


def cmd_display_histo():
    print_banner("Displaying histogram")

    global X_test, Y_test

    model_type = config.get_str('model', 'Model')
    sel_ds = config.get_str('dataset', 'SelectedDataset')

    if X_test is None or Y_test is None:
        X_test, Y_test = transform.get_xy(sel_ds, 'testing_set', language, vuln_type, selected_features)

        X_test = sync_features(X_test)

    display_prob_histogram(title="%s %s (class: not vulnerable)" % (vuln_type, model_type), model=model, X=X_test, Y=Y_test, cls=0)

    display_prob_histogram(title="%s %s (class: vulnerable)" % (vuln_type, model_type), model=model, X=X_test, Y=Y_test, cls=1)


def cmd_compare_tools():
    global train_features

    print_banner("Comparing results")

    sel_ds = config.get_str('dataset', 'SelectedDataset')
    sel_vt = config.get_str('dataset', 'SelectedVulnerabilityType')

    if train_features is None:
        X, _ = transform.get_xy(sel_ds, 'training_set', language, vuln_type, selected_features)
        X.sort_index(axis=1, inplace=True)

        train_features = X.columns

    orig_tuning, X_tuning, _ = transform.get_xy_with_orig(sel_ds, 'tuning_set', language, vuln_type, selected_features)

    X_tuning = sync_features(X_tuning)

    c = find_best_threshold(model, orig_tuning, X_tuning)

    print_notice("Preferred threshold (Y > c): %.2f" % c)

    orig, X, _ = transform.get_xy_with_orig(sel_ds, 'testing_set', language, vuln_type, selected_features)

    print_notice('-' * 55)
    print_notice("Our results")

    print_model_results(model, orig, X, c)

    for (tool, file_name) in config.get_items('tools'):
        print_notice('-' * 55)
        print_notice('Comparing against tool: %s' % tool)
        compare_results(file_name, orig, sel_vt)


def cmd_count_sets():
    sel_ds = config.get_str('dataset', 'SelectedDataset')
    _, Y_training = transform.get_xy(sel_ds, 'training_set', language, vuln_type, None)
    _, Y_tuning = transform.get_xy(sel_ds, 'tuning_set', language, vuln_type, None)
    _, Y_testing = transform.get_xy(sel_ds, 'testing_set', language, vuln_type, None)

    non_vuln = 0
    vuln = 0

    for setname, df in zip(['training', 'tuning', 'testing'], [Y_training, Y_tuning, Y_testing]):
        nv = len(df.loc[df[0:] == 0])
        v = len(df.loc[df[0:] == 1])
        non_vuln += nv
        vuln += v
        print_notice("%s set: non-vulnerable lines %d, vulnerable lines %d" % (setname, nv, v))

    print_notice("total: non-vulnerable lines %d, vulnerable lines %d" % (non_vuln, vuln))


def main(args=None):
    global language, vuln_type

    if args is None:
        args = sys.argv[1:]

    if not args:
        print_help()

    # Remove all spaces
    command_line = args[0].replace(" ", "")

    commands = command_line.split(",")

    # --- Initialize configuration --
    config.init()

    language = config.get_str('dataset', 'SelectedLanguage')
    vuln_type = config.get_str('dataset', 'SelectedVulnerabilityType')

    np.set_printoptions(precision=3, suppress=True)

    # --- Run commands ---
    run_commands(commands)

    # -- Final clean up for some models --
    if hasattr(model, 'clean_up'):
        print_banner("Cleaning up")
        model.clean_up()


if __name__ == "__main__":
    main()

