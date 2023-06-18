from sklearn.linear_model import PassiveAggressiveClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import f1_score
from sklearn.metrics import classification_report
import joblib
import pandas as pd
import yaml

def Compare(X, y):

    scaler = StandardScaler()
    scaler.fit(X)
    x_scaled = scaler.transform(X)

    skf = StratifiedKFold(n_splits=5)

    sgd = SGDClassifier(max_iter=1000, tol=1e-3)
    sgd_f1 = []
    sgd_report = []
    pac = PassiveAggressiveClassifier(max_iter=1000, random_state=0,tol=1e-3)
    pac_f1 = []
    pac_report = []


    for train_index, test_index in skf.split(x, y):
        x_train_fold, x_test_fold = x_scaled[train_index], x_scaled[test_index]
        y_train_fold, y_test_fold = y[train_index], y[test_index]
        sgd.fit(x_train_fold, y_train_fold)
        y_pred = sgd.predict(x_test_fold)
        sgd_f1.append(f1_score(y_test_fold,y_pred))
        sgd_report.append(classification_report(y_test_fold,y_pred))

        pac.fit(x_train_fold, y_train_fold)
        y_pred = pac.predict(x_test_fold)
        pac_f1.append(f1_score(y_test_fold,y_pred))
        pac_report.append(classification_report(y_test_fold,y_pred))

    print(pac_f1)
    print(sgd_f1)

    return pac_report, sgd_report

def SGD_fit(X, y):
    clf = make_pipeline(StandardScaler(),SGDClassifier(max_iter=1000, tol=1e-3))      
    clf.fit(X,y)
    return clf 

def PAC_fit(X, y):
    clf = make_pipeline(StandardScaler(),PassiveAggressiveClassifier(max_iter=1000, random_state=0,tol=1e-3))
    clf.fit(X, y)
    return clf


def Partial(X,y,clf):
    clf.partial_fit(X, y,[0, 1])
    return clf

def predict(X, clf):
    return clf.predict(X)

def dump(clf):
    filename = 'clf.pkl'
    _ = joblib.dump(clf, filename, compress=9)

def load():
    filename = 'clf.pkl'
    return joblib.load(filename)

def LoadValues(filename):
    with open(filename, 'r') as stream:
        data = yaml.safe_load(stream)
    X = []
    for i in data:
        X.append(i)
    return X

def LoadValueForFit():
    X = pd.read_csv('data.csv')
    y = pd.read_csv('labels.csv')
    return X, y