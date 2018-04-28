import re
from wirecaml.extraction.path_cache import PathCache


class Preprocessor:
    def __init__(self, path):
        self.re_include = re.compile("(include|include_once|require|require_once)\(([^)]+)\)", re.IGNORECASE)
        self.re_start_tag = re.compile("<\?php[\r\n\s]", re.IGNORECASE)
        self.re_end_tag = re.compile("\?>")

        self.included_files = []
        self.project_files = PathCache.get_path_files(path)

    def parse_file_name(self, s):
        fn = s.replace("\"", "").replace("'", "").strip()

        # We try to find the file to include based on the files that are part of the project
        # We're willfully ignoring the context of the path, so admin/include.php and user/include.php
        # are both valid answers for a search for include.php. Oh well.
        for proj_file in self.project_files:
            if proj_file not in self.included_files and \
                    (proj_file == fn or proj_file.endswith("\\%s" % fn) or proj_file.endswith("/%s" % fn)):
                self.included_files.append(proj_file)

                return proj_file

        return None

    def preprocess_file(self, file):
        lines = self._preprocess_file(file)
        # 0th element is not a valid line number, so we initialize it as None
        line_map = [(None, None)]
        output = ""

        for tuple in lines:
            line_map.append((tuple[0], tuple[1]))

            output += tuple[2]

        return line_map, output

    def _preprocess_file(self, file, ignore_tags=False):
        output = []

        with open(file, encoding="latin-1") as inp:
            file_str = inp.read()

        # Remove any trailing white spaces and then split
        lines = file_str.rstrip().splitlines(True)

        for line_no in range(len(lines)):
            line = lines[line_no]

            if ignore_tags:
                if line_no == 0 and self.re_start_tag.search(line):
                    continue

                if line_no == len(lines) - 1 and self.re_end_tag.search(line):
                    continue

            m = self.re_include.search(line)
            fn = None

            if m is not None:
                fn = self.parse_file_name(m.group(2))

            if fn is not None:
                output += self._preprocess_file(fn, ignore_tags=True)
            else:
                # File lines start at 1
                output.append((file, line_no + 1, line))

        return output

    def reset_included_files(self):
        self.included_files = []
