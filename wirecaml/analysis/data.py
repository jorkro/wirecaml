from wirecaml.tools.ascii import print_notice
from wirecaml.tools import config
import numpy as np
import os


def store_data(model, orig, X, Y, just_outliers, threshold=0.5):
    outliers_file = os.path.join(config.get_str('analysis', 'OutliersPath'), 'outliers.csv')
    model_type = config.get_str('model', 'Model')

    probas = model.predict_proba(X)

    df = X.copy()
    df[['file_name', 'line']] = orig[['file_name', 'line']]
    df['actual'] = Y
    df['predict_proba'] = probas[:, 1]
    df['predicted'] = (df['predict_proba'] > threshold)

    if model_type == 'DecisionTreeClassifier':
        print_notice("Adding decision paths to the data as model is a DT")
        node_indicator = model.decision_path(X)

        for i in df.index:
            df.loc[i, 'path'] = str(node_indicator.indices[node_indicator.indptr[i]:node_indicator.indptr[i + 1]])

    print_notice("Storing in file %s" % outliers_file)

    if just_outliers:
        indices = np.flatnonzero(df['predicted'] - Y)
        print_notice("Number of outliers %d" % indices.size)
        df.iloc[indices].to_csv(outliers_file)
    else:
        print_notice("Number of records %d" % len(df.index))
        df.to_csv(outliers_file)
