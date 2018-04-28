from os import listdir
from os.path import isfile, join


class PathCache:
    path_cache = dict()

    @staticmethod
    def get_path_files(path):
        if not path in PathCache.path_cache:
            PathCache.path_cache[path] = [join(path, f) for f in listdir(path) if isfile(join(path, f))]

        return PathCache.path_cache[path]
