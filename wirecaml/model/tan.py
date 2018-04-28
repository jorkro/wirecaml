from weka.classifiers import Classifier, Evaluation
from weka.core.converters import Loader
import weka.core.jvm as jvm
import numpy as np
import tempfile
import os

from wirecaml.tools.ascii import print_notice
from wirecaml.tools.file_tools import silent_remove
from wirecaml.tools.data_tools import pandas2arff


class TAN:
    def __init__(self):
        self.classifier = None
        self.train_data = None
        self.train_fn = os.path.join(tempfile.gettempdir(), 'TAN_train_data.arff')
        self.test_fn = os.path.join(tempfile.gettempdir(), 'TAN_test_data.arff')
        self.mbc = ""
        self.score_type = "BAYES"

    def fit(self, X, Y):
        # Create combined dataframe of X and Y
        X['class'] = Y.as_matrix()

        filename = self.to_arff(X, False)

        # Remove class column
        del X['class']

        if not jvm.started:
            print_notice("Starting JVM")
            jvm.start()

        loader = Loader("weka.core.converters.ArffLoader")
        self.train_data = loader.load_file(filename)
        self.train_data.class_is_last()

        self.classifier = Classifier(classname="weka.classifiers.bayes.BayesNet",
                                     options=["-Q", "weka.classifiers.bayes.net.search.local.TAN",
                                              "--", "-S", self.score_type, self.mbc,
                                              "-E", "weka.classifiers.bayes.net.estimate.SimpleEstimator",
                                              "--", "-A", "0.9"])

        self.classifier.build_classifier(self.train_data)

    def predict(self, X):
        evaluation = Evaluation(self.train_data)

        # Add class column (we can't copy X, because this is a large object, so we add the column and remove it later)
        X['class'] = None

        filename = self.to_arff(X, True)

        # Remove class column
        del X['class']

        loader = Loader("weka.core.converters.ArffLoader")
        test_data = loader.load_file(filename)
        test_data.class_is_last()

        preds = evaluation.test_model(self.classifier, test_data)

        return preds

    def predict_proba(self, X):
        evaluation = Evaluation(self.train_data)

        # Add class column (we can't copy X, because this is a large object, so we add the column and remove it later)
        X['class'] = None

        filename = self.to_arff(X, True)

        # Remove class column
        del X['class']

        loader = Loader("weka.core.converters.ArffLoader")
        test_data = loader.load_file(filename)
        test_data.class_is_last()

        evaluation.test_model(self.classifier, test_data)

        probas = None

        # Return probabilities
        for pred in evaluation.predictions:
            if probas is None:
                probas = pred.distribution
            else:
                probas = np.vstack([probas, pred.distribution])

        return probas

    def to_arff(self, df, test):
        if test:
            filename = self.test_fn
        else:
            filename = self.train_fn

        print_notice("Writing ARFF data to filename %s" % filename)

        pandas2arff(df, filename)

        return filename

    def clean_up(self):
        print_notice("Removing temporary files")
        silent_remove(self.train_fn)
        silent_remove(self.test_fn)

        print_notice("Stopping JVM")
        jvm.stop()


