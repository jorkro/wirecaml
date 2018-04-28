import numpy as np


def slice_perc(lst, start_perc, end_perc):
    new_lst = lst[int(len(lst) * (start_perc / 100)): int(len(lst) * (end_perc / 100))]

    return new_lst


# Creates a float range
def frange(start, stop, step):
    i = start
    while i < stop:
        yield i
        i += step


# Originally from https://github.com/saurabhnagrecha/Pandas-to-ARFF
def pandas2arff(df, filename, wekaname="pandasdata", cleanstringdata=True, cleannan=True):
    """
    converts the pandas dataframe to a weka compatible file
    df: dataframe in pandas format
    filename: the filename you want the weka compatible file to be in
    wekaname: the name you want to give to the weka dataset (this will be visible to you when you open it in Weka)
    cleanstringdata: clean up data which may have spaces and replace with "_", special characters etc which seem to annoy Weka.
                     To suppress this, set this to False
    cleannan: replaces all nan values with "?" which is Weka's standard for missing values.
              To suppress this, set this to False
    """
    import re

    def cleanstring(s):
        if s != "?":
            return re.sub('[^A-Za-z0-9]+', "_", str(s))
        else:
            return "?"

    dfcopy = df  # all cleaning operations get done on this copy

    if cleannan != False:
        dfcopy = dfcopy.fillna(-999999999)  # this is so that we can swap this out for "?"
        # this makes sure that certain numerical columns with missing values don't get stuck with "object" type

    f = open(filename, "w")
    arffList = []
    arffList.append("@relation " + wekaname + "\n")
    # look at each column's dtype. If it's an "object", make it "nominal" under Weka for now (can be changed in source for dates.. etc)
    for i in range(df.shape[1]):
        if dfcopy.dtypes[i] == 'O' or (df.columns[i] in ["Class", "CLASS", "class"]):
            if cleannan != False:
                dfcopy.iloc[:, i] = dfcopy.iloc[:, i].replace(to_replace=-999999999, value="?")
            if cleanstringdata != False:
                dfcopy.iloc[:, i] = dfcopy.iloc[:, i].apply(cleanstring)
            _uniqueNominalVals = [str(_i) for _i in np.unique(dfcopy.iloc[:, i])]
            _uniqueNominalVals = ",".join(_uniqueNominalVals)
            _uniqueNominalVals = _uniqueNominalVals.replace("[", "")
            _uniqueNominalVals = _uniqueNominalVals.replace("]", "")
            _uniqueValuesString = "{" + _uniqueNominalVals + "}"
            arffList.append("@attribute " + df.columns[i] + _uniqueValuesString + "\n")
        else:
            arffList.append("@attribute attribute%d real\n" % i)
            # even if it is an integer, let's just deal with it as a real number for now
    arffList.append("@data\n")
    for i in dfcopy.values.tolist():

        _instanceString = ','.join(map(str, i))
        _instanceString += "\n"

        if cleannan != False:
            _instanceString = _instanceString.replace("-999999999.0", "?")  # for numeric missing values
            _instanceString = _instanceString.replace("\"?\"", "?")  # for categorical missing values
        arffList.append(_instanceString)
    f.writelines(arffList)
    f.close()
    del dfcopy
    return True
