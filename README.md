# WIRECAML

## What does it stand for?
WIRECAML stands for "Weakness Identification Research Employing CFG Analysis and Machine Learning"

## What does it do?
This tool combines data-flow analysis and machine learning to find software vulnerabilities (SQLi and XSS) in PHP applications. The thesis that I've written on this topic can be found in the docs/ directory.

## How do I get the data set?
Due to its size, the data set will have to be downloaded separately. The tarball is ~1.6GB and once unpacked, the resulting data set is ~6GB.

```
curl -L -o wirecaml-data.tar.gz https://www.dropbox.com/s/i6e4kv64eudoq6m/wirecaml-data.tar.gz?dl=1
tar xzf wirecaml-data.tar.gz
rm wirecaml-data.tar.gz
```

## How do I install it?
To install its dependencies execute the following command:
```
pip install "unidiff>=0.5.2" "numpy>=1.11.3+mkl" "lxml>=3.7.3" "networkx>=1.11" "scikit-learn>=0.18.1" "matplotlib>=2.0.0" "xgboost>=0.6" "python-weka-wrapper3>=0.1.2" "nose>=1.3.7" "pandas>=0.19.2" "pydotplus>=2.0.2" "pathos>=0.2.0" "phply>=1.0.0"
```
And make sure that you have Python 3.5 installed.

If you want to use the TAN classifier, you will also need to install Weka, which can be found here: https://www.cs.waikato.ac.nz/ml/weka/

## How do I use it?
```
python -m wirecaml <command>
```

The following commands may be of interest:

| Command         | Description                                                                                                                               |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| clean_all       | Remove the file sets and transformation files. This is the same as running clean_set, clean_transform, and clean_custom together          |
| clean_custom    | Remove the file sets and transformation files for the custom test set.                                                                    |
| clean_set       | Remove the file sets                                                                                                                      |
| clean_transform | Remove the transformation files                                                                                                           |
| compare_tools   | Compare the results of 4 OSS tools (Pixy, RIPS, WAP, Yasca) and a generated model using the F<sub>1</sub> score                           |
| count_sets      | Provide metrics on the transformed sets (# vulnerable vs. # non-vulnerable)                                                               |
| display_histo   | Show the probability histograms of the non-vulnerable and vulnerable class                                                                |
| display_model   | Show the PR curve and AUC-PR value for the given model                                                                                    |
| select_features | Select the top *k* features using the *χ<sup>2</sup>*-test. *k* can be specified in the config.ini file using the parameter *kFeatures*   |
| store_custom    | Store all lines where P > 0.0 into a CSV file                                                                                             |
| store_outliers  | Store all outliers where the predicted class != actual class into a CSV file                                                              |
| tune_params     | Generate tuning parameters using a grid search algorithm for the specified model. The parameters can then be added to the config.ini file |

Commands can also be chained together, such as:
```
clean_all,display_histo
```
or:
```
select_features,display_model
```

The config file can be used to specify the model (parameter *model*), the data set (*SelectedDataset*) and the vulnerability type (*SelectedVulnerabilityType*). 

## I have questions. Who can I ask them?
If you are interested in this research but have questions, just send me an e-mail (**jorrit at wafel dot org**) and I will try to answer them.
