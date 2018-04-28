from collections import Counter


class PopularFeatures:

    def __init__(self, num_features):
        self.feature_counter = Counter()

        self.num_features = num_features

    def partial_fit(self, X, y=None):
        self.feature_counter.update(X.columns.values)

    def transform(self, X, y=None):
        popular_features = [column for column, _ in self.feature_counter.most_common(self.num_features)]

        return X[[c for c in X.columns.values if c in popular_features]]

    def get_all_features(self):
        return list(self.feature_counter)

    def set_num_features(self, num_features):
        self.num_features = num_features
