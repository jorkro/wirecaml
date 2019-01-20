import os
import pickle
import timeit
from pathos.multiprocessing import ProcessingPool as Pool
import pandas as pd
from wirecaml.extraction import cfg
from wirecaml.model.batched_pca import BatchedPCA
from wirecaml.model.popular_features import PopularFeatures
from wirecaml.tools import config
from wirecaml.tools.ascii import print_warning, print_notice


def is_vulnerable(flaw_dict, lines_to_check):
    return [x for x in lines_to_check if x[0] in flaw_dict and x[1] in flaw_dict[x[0]]] != []


def get_node_with_dependencies(track_nodes, nodes):
    add_nodes = set()

    for n in nodes:
        add_nodes |= n.get_node_deps()

    add_nodes -= nodes

    if not add_nodes:  # No more nodes to add
        return track_nodes | nodes
    elif add_nodes.issubset(track_nodes):  # All nodes that we wanted to add are already being tracked
        return track_nodes | nodes | add_nodes

    track_nodes |= nodes | add_nodes  # track_nodes contains all the nodes we've already visited

    return get_node_with_dependencies(track_nodes, add_nodes)


def transform_graph(graph, flaw_dict, mark_whole_path, feature_filter=None):
    lines = []
    vulnerable_line = 0
    max_path = 0

    # Loop through all the nodes in the CFG
    for n in graph.nodes_iter():

        # Grab all the nodes it depends on
        all_path_nodes = get_node_with_dependencies(set(), {n})

        # Grab all the functions called in those nodes
        funcs = {'func_' + f for a in all_path_nodes for f in a.get_funcs()}

        # Grab all the constants used in those nodes
        consts = {'const_' + c for a in all_path_nodes for c in a.get_consts()}

        # Store for each line the functions it depends on
        line_dict = {'file_name': n.file, 'line': n.line, 'vulnerable': 0, 'tainted': int(n.is_tainted())}

        feat_dict = dict()

        # 1 if the function is used, 0 if it's not
        for f in funcs:
            feat_dict[f] = 1

        # the same for the consts
        for c in consts:
            feat_dict[c] = 1

        # A line that results in a sparse vector of all 0s is skipped
        if sum(feat_dict.values()) == 0:
            continue

        # Merge all features
        line_dict = {**line_dict, **feat_dict}

        if is_vulnerable(flaw_dict, [(a.file, a.line) for a in all_path_nodes]):

            if mark_whole_path:
                line_dict['vulnerable'] = 1
            elif max_path < len(all_path_nodes):
                max_path = len(all_path_nodes)
                vulnerable_line = (n.file, n.line)

        lines.append(line_dict)

    df = pd.DataFrame(lines)

    if len(lines) > 0:
        df.fillna(0, inplace=True)
        df.sort_values('line', inplace=True)

        if not mark_whole_path:
            df.loc[(df['file_name'] == vulnerable_line[0]) & (df['line'] == vulnerable_line[1]), 'vulnerable'] = 1

    if feature_filter is not None:
        # We drop these columns so our feature filter can ignore them
        columns_to_drop = ['file_name', 'line', 'vulnerable', 'tainted']

        dropped_columns = df[columns_to_drop]

        df.drop(columns_to_drop, axis=1, inplace=True)

        df = feature_filter.transform(df)

        # We add them back after the filter
        df = pd.concat([pd.DataFrame(df), dropped_columns], axis=1)

    return df


def get_transform_filename(dataset, language, vuln_type):
    filename_format = config.get_str('dataset', 'TransformFilenameFormat')

    return filename_format % (dataset, language, vuln_type)


def get_features_filename(dataset, language, vuln_type):
    filename_format = config.get_str('dataset', 'FeaturesFilenameFormat')

    return filename_format % (dataset, language, vuln_type)


def transform_file(flaw_dict, mark_whole_path, feature_filter=None):
    def f(file):
        try:
            g = cfg.create_graph(os.path.dirname(file), file)
        except (SyntaxError, IndexError, RecursionError):  # TODO: Fix the IndexError and RecursionError
            print_warning("Syntax error in file %s" % file)
            return None

        try:
            df = transform_graph(g, flaw_dict, mark_whole_path, feature_filter)
        except RecursionError:
            print_warning("Maximum recursion depth exceeded (%s)" % file)
            return None

        return df
    return f


def transform_sets(dataset, sets, language):

    mark_whole_path = config.get_boolean('dataset', 'MarkWholePathVulnerable')
    flaw_dict = sets['flaw_dict'][language]
    num_processes = 100

    set_dfs = {'training_set': {language: dict()}, 'tuning_set': {language: dict()}, 'testing_set': {language: dict()}}

    with Pool(processes=num_processes) as pool:
        for vuln_type in config.get_list('dataset', 'Vulnerabilities'):
            filename = get_transform_filename(dataset, language, vuln_type)
            # pf = get_popular_features(dataset, language, vuln_type)

            if not os.path.isfile(filename):
                f = transform_file(flaw_dict[vuln_type], mark_whole_path)

                for set_type in ['training_set', 'tuning_set', 'testing_set']:
                    # counter = 0
                    #
                    # l = len(sets[set_type][language][vuln_type])
                    # generator = iter(sets[set_type][language][vuln_type])
                    #
                    # ff = BatchedPCA(all_features=pf.get_all_features(), n_components=30)
                    #
                    # # First we determine popular columns
                    # if set_type == 'training_set':
                    #     while True:
                    #         next_elements = list(next(generator) for _ in range(num_processes))
                    #         counter += len(next_elements)
                    #
                    #         if not next_elements:
                    #             break
                    #
                    #         start = timeit.default_timer()
                    #         res = pool.map(f, next_elements)
                    #
                    #         chunk = pd.concat([df.to_sparse(fill_value=0) for df in res if df is not None],
                    #                           ignore_index=True)
                    #         chunk.fillna(0, inplace=True)
                    #         print_notice("Chunk columns: %d memory usage: %d" % (len(chunk.columns),
                    #                                                              chunk.memory_usage().sum()))
                    #
                    #         # We drop these columns so our feature filter can ignore them
                    #         chunk.drop(['file_name', 'line', 'vulnerable', 'tainted'], axis=1, inplace=True)
                    #
                    #         ff.partial_fit(chunk)
                    #
                    #         print_notice(
                    #             "%s %s %s: %d/%d (run took %.2f secs)" % (language, vuln_type, set_type, counter, l,
                    #                                                       timeit.default_timer() - start))
                    #
                    # # Create a new transform function with our feature filter
                    # f = transform_file(flaw_dict[vuln_type], mark_whole_path, feature_filter=ff)

                    counter = 0

                    l = len(sets[set_type][language][vuln_type])
                    generator = iter(sets[set_type][language][vuln_type])

                    chunks = []

                    while True:
                        next_elements = list(next(generator) for _ in range(num_processes))
                        counter += len(next_elements)

                        if not next_elements:
                            break

                        start = timeit.default_timer()
                        res = pool.map(f, next_elements)

                        chunk = pd.concat([df.to_sparse(fill_value=0) for df in res if df is not None],
                                          ignore_index=True)
                        chunk.fillna(0, inplace=True)
                        print_notice("Chunk columns: %d memory usage: %d" % (len(chunk.columns),
                                                                             chunk.memory_usage().sum()))
                        chunks.append(chunk)

                        print_notice(
                            "%s %s %s: %d/%d (run took %.2f secs)" % (language, vuln_type, set_type, counter, l,
                                                                      timeit.default_timer() - start))

                    print_notice("Concatenating %d data frames, this will take a while" % len(chunks))

                    if len(chunks) > 0:
                        set_dfs[set_type][language][vuln_type] = pd.concat(chunks, ignore_index=True)
                        set_dfs[set_type][language][vuln_type].fillna(0, inplace=True)
                        set_dfs[set_type][language][vuln_type] = set_dfs[set_type][language][vuln_type].to_dense()

                with open(filename, 'wb') as pickle_file:
                    # Protocol version 4 supports large objects (> 4GB)
                    pickle.dump(set_dfs, pickle_file, protocol=4)

                set_dfs = {'training_set': {language: dict()}, 'tuning_set': {language: dict()},
                           'testing_set': {language: dict()}}
            else:
                print_notice("Pickle file %s already created" % filename)


def create_popular_features(dataset, sets, language):

    mark_whole_path = config.get_boolean('dataset', 'MarkWholePathVulnerable')
    flaw_dict = sets['flaw_dict'][language]
    num_processes = 100

    with Pool(processes=num_processes) as pool:
        for vuln_type in config.get_list('dataset', 'Vulnerabilities'):
            filename = get_features_filename(dataset, language, vuln_type)

            if not os.path.isfile(filename):
                f = transform_file(flaw_dict[vuln_type], mark_whole_path)
                set_type = 'training_set'

                counter = 0

                l = len(sets[set_type][language][vuln_type])
                generator = iter(sets[set_type][language][vuln_type])

                pf = PopularFeatures(num_features=200)

                while True:
                    next_elements = list(next(generator) for _ in range(num_processes))
                    counter += len(next_elements)

                    if not next_elements:
                        break

                    start = timeit.default_timer()
                    res = pool.map(f, next_elements)

                    for df in res:
                        if df is None:
                            continue

                        if not all(x in df.columns.values for x in ['file_name', 'line', 'vulnerable', 'tainted']):
                            print_warning("Could not find the right columns in data frame. Ignoring.")
                            continue

                        # We drop these columns so our feature filter can ignore them
                        df.drop(['file_name', 'line', 'vulnerable', 'tainted'], axis=1, inplace=True)

                        pf.partial_fit(df)

                    print_notice(
                        "%s %s %s: %d/%d (run took %.2f secs)" % (language, vuln_type, set_type, counter, l,
                                                                  timeit.default_timer() - start))

                with open(filename, 'wb') as pickle_file:
                    # Protocol version 4 supports large objects (> 4GB)
                    pickle.dump(pf, pickle_file, protocol=4)

            else:
                print_notice("Pickle file %s already created" % filename)


def get_popular_features(dataset, language, vuln_type):
    filename = get_features_filename(dataset, language, vuln_type)

    with open(filename, 'rb') as pickle_file:
        return pickle.load(pickle_file)


def get_xy(dataset, set_name, language, vuln_type, features=None):
    _, X, Y = get_xy_with_orig(dataset, set_name, language, vuln_type, features)

    return X, Y


def get_xy_with_orig(dataset, set_name, language, vuln_type, features=None):
    filename = get_transform_filename(dataset, language, vuln_type)

    with open(filename, 'rb') as pickle_file:
        set_dfs = pickle.load(pickle_file)

        orig = set_dfs[set_name][language][vuln_type]
        X = set_dfs[set_name][language][vuln_type].drop(['file_name', 'line', 'vulnerable'], axis=1)
        Y = set_dfs[set_name][language][vuln_type]['vulnerable']

    num_features = len(X.columns)

    if features is not None:
        num_features = len(features)

    print_notice("Using set '%s' with %d features" % (set_name, num_features))

    if features is not None:
        return orig, X[list(set(features).intersection(X.columns))], Y
    else:
        return orig, X, Y


def delete_transforms(datasets=None):
    remove = False

    if datasets is None:
        datasets = ['NVD', 'SAMATE']

    for dataset in datasets:
        for language in config.get_list('dataset', 'Languages'):
            for vuln_type in config.get_list('dataset', 'Vulnerabilities'):
                transform_filename = get_transform_filename(dataset, language, vuln_type)
                features_filename = get_features_filename(dataset, language, vuln_type)

                for f in [transform_filename, features_filename]:
                    if os.path.isfile(f):
                        print_notice("Removing %s" % f)
                        os.remove(f)
                        remove = True

    if not remove:
        print_warning("Could not find any transform files to remove.")

