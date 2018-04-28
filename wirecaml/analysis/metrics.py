import matplotlib.pyplot as plt
import numpy as np
import csv
import os
from sklearn import metrics
from sklearn.metrics import precision_recall_curve, auc, roc_auc_score

from wirecaml.tools.ascii import print_notice
from wirecaml.tools.data_tools import frange


def get_auc_score(Y, probas):
    precision, recall, _ = precision_recall_curve(Y, probas[:, 1], 1)
    area = auc(recall, precision)

    return precision, recall, area


def display_pr_curve(title, model, X, Y):
    probas = model.predict_proba(X)

    # Compute Precision-Recall and plot curve
    precision, recall, area = get_auc_score(Y, probas)

    roc_score = roc_auc_score(Y, probas[:, 1])
    print_notice("AUC-PR: %0.2f" % area)
    print_notice("AUC-ROC: %0.2f" % roc_score)

    # Plot Precision-Recall curve
    plt.clf()
    plt.plot(recall, precision, lw=2, color='navy', label='PR curve')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.ylim([0.0, 1.0])
    plt.xlim([0.0, 1.0])
    plt.title('%s AUC-PR=%.2f' % (title, area))
    plt.tight_layout()
    plt.legend(loc="lower left")
    plt.show()


def print_metrics(model, X, Y):
    predicted = model.predict(X)
    probas = model.predict_proba(X)

    print_notice("Brier score (class: not vulnerable) %.4f" % calculate_brier_score(probas, Y, cls=0))
    print_notice("Brier score (class: vulnerable) %.4f" % calculate_brier_score(probas, Y, cls=1))
    print_notice("Brier score %.4f" % _brier_score_loss(Y, probas[:, 1]))
    print_notice("Accuracy %.2f" % metrics.accuracy_score(Y, predicted))
    print_notice(metrics.classification_report(Y, predicted, target_names=['not vulnerable', 'vulnerable']))


def calculate_brier_score(probas, Y, cls):
    indexes = Y[Y == cls].index

    return _brier_score_loss(Y[indexes], probas[indexes][:, 1])


# There's a bug in scikit where all y_true labels get replaced for 0 when there's only one label
def _brier_score_loss(y_true, y_prob):
    return np.average((y_true - y_prob) ** 2)


def display_prob_histogram(title, model, X, Y, cls):
    # Determine the indexes of that class
    indexes = Y[Y == cls].index

    probas = model.predict_proba(X)

    # Filter probabilities based on the indexes
    probas = probas[indexes]

    bins = 50

    # the histogram of the data
    plt.hist(probas[:, 1], bins=bins, normed=False, facecolor='green', alpha=0.75)

    plt.xlabel('Probabilities (bins=%d)' % bins)
    plt.ylabel('Count')
    plt.xlim([0.0, 1.0])
    plt.title(title)
    plt.grid(True)

    plt.show()


def find_best_threshold(model, orig, X):
    pref_thr = max_f1 = -1

    probas = model.predict_proba(X)

    print_notice("Finding the best threshold value for F1 score")

    for c in frange(0.0, 1.01, 0.01):
        predicted = []
        y_only_filename = []

        orig['predicted'] = probas[:, 1]
        orig['predicted'] = orig['predicted'].apply(lambda x: int(x > c))

        for _, row in orig.groupby(['file_name']).agg({'vulnerable': np.sum, 'predicted': np.sum}).iterrows():
            y_only_filename.append(row['vulnerable'] != 0)
            predicted.append(row['predicted'] != 0)

        # Due to the class imbalance, we use a weighted F1 score
        f1_score = metrics.f1_score(y_only_filename, predicted, average='weighted')

        if f1_score > max_f1:
            max_f1 = f1_score
            pref_thr = c

    return pref_thr


def print_model_results(model, orig, X, c):
    probas = model.predict_proba(X)

    predicted = []
    y_only_filename = []

    orig['predicted'] = probas[:, 1]
    orig['predicted'] = orig['predicted'].apply(lambda x: int(x > c))

    for _, row in orig.groupby(['file_name']).agg({'vulnerable': np.sum, 'predicted': np.sum}).iterrows():
        y_only_filename.append(row['vulnerable'] != 0)
        predicted.append(row['predicted'] != 0)

    print_notice(metrics.classification_report(y_only_filename, predicted, target_names=['not vulnerable', 'vulnerable']))


def compare_results(file_name, orig, sel_vt):
    compare_set = {'SQLi': [], 'XSS': []}

    with open(file_name, newline='') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            compare_set[row[0]].append((os.path.realpath(row[1]), row[2]))

    predicted = []
    y_only_filename = []

    for f, row in orig.groupby(['file_name']).agg({'vulnerable': np.sum}).iterrows():
        vuln_file = os.path.realpath(f)

        if row['vulnerable'] == 0:
            y_only_filename.append(0)
        else:
            y_only_filename.append(1)

        if any([el for el in compare_set[sel_vt] if el[0] == vuln_file]):
            predicted.append(1)
        else:
            predicted.append(0)

    print_notice(metrics.classification_report(y_only_filename, predicted, target_names=['not vulnerable', 'vulnerable']))

