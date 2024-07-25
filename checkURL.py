import requests
import time
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer 
from sklearn import metrics
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import BaggingClassifier  
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LinearRegression 
from sklearn import svm
from xgboost import XGBClassifier    
from lightgbm import LGBMClassifier
from sklearn.tree import DecisionTreeClassifier  

from urllib.parse import urlparse, parse_qs
import re
import requests
from bs4 import BeautifulSoup
import tldextract
import math
import csv

import warnings
warnings.filterwarnings('ignore')



def checkStatusCode(url : str) -> None:
    '''
    Gets the  URL and checks it's status code if it's active or not
    '''
    try:
        response = requests.get(url)
        if response.status_code == 200:
            file = open('openURLS.txt', 'a')
            print(response.status_code)
            file.write('0 ' + url + '\n')
        else:
            print("URL Down")
    except Exception as error:
        print("Error Can not connect to the URLs")


def parseFile(file : str) -> None:
    '''
    Passes the URL to get checked for the status code
    '''
    with open(file, 'r') as phishingURLs:
        for line in phishingURLs:
            url = line.strip()
            checkStatusCode(url)



headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0'
}



def ShannonEntropy(entropyType):
    probabilities = [float(entropyType.count(c)) / len(entropyType) for c in dict.fromkeys(list(entropyType))]
    return -sum([p * math.log(p) / math.log(2.0) for p in probabilities])


def getTitle(url):
    try:
        return BeautifulSoup(requests.get(url, headers=headers).content, 'html.parser').title.string
    except:
        return 0
    
def HasTitle(url):
    hasTitle = BeautifulSoup(requests.get(url, headers=headers).content, 'html.parser').title
    if hasTitle:
        return 1  
    else:
        return 0 


def hasFavicon(url):
    if BeautifulSoup(requests.get(url, headers=headers).content, 'html.parser').find("link", rel=re.compile(r'^(shortcut )?icon$', re.I)):
        return 1
    else:
        return 0 

def hasCopyRightInfo(url):
    for element in BeautifulSoup(requests.get(url, headers=headers).content, 'html.parser').find_all(['footer', 'div', 'span', 'p', 'small', 'a']):
        text = element.get_text().lower()
        for keyword in ['copyright', '©']:
            if keyword in text:
                return 1
    return 0

def hasRedirects(url):
    if len(requests.get(url, headers=headers).history):
        return 1
    else:
        return 0 


def constructDataSet(label, url):
    print(url, label)
    try:
        features = {}
        parseUrl = urlparse(url)
        domainInfo = tldextract.extract(url)
        queryParameters = parse_qs(parseUrl.query)
        features['URL'] = url
        features['UrlLength'] = len(url)
        features['DomainLength'] = len(parseUrl.netloc)
        features['NumOfDots'] = url.count('.')
        features['NumOfHypens'] = url.count('-')
        features['NumOfUnderscores'] = url.count('_')
        features['NumOfSlashes'] = url.count('/')
        features['NumOfDigits'] = sum(c.isdigit() for c in url)
        features['NumOfSpecialCharacters'] = len(re.findall(r'[^\w\s]', url))
        features['NumOfCaptialLetters'] = sum(1 for c in url if c.isupper())
        features['NumOfSubdomains'] = len(domainInfo.subdomain.split('.'))
        features['IsDomainIP'] = int(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', parseUrl.netloc) is not None)
        features['TLDLength'] = len(domainInfo.suffix)
        features['NumOfDirectories'] = len(parseUrl.path.split('/')) - 1
        features['PathEntropy'] = ShannonEntropy(parseUrl.path)
        features['NumOfParameters'] = len(queryParameters)
        features['QueryEntropy'] = ShannonEntropy(parseUrl.query)
        features['IsHTTPS'] = int(parseUrl.scheme == 'https')
        features['NoOfObusfucatedCharacters'] = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
        features['HasTitle'] = HasTitle(url)
        features['Title'] = getTitle(url)
        features['HasFavicon'] = hasFavicon(url)
        features['HasCopyRightInfo'] = hasCopyRightInfo(url)
        features['HasURLRedirects'] = hasRedirects(url)
        features['label'] = label
        print(features)
    except Exception:
        pass
    return features


def trainModel(file):
    all_features = []
    first_write = False
    with open(file, 'r') as f:
        for line in f:
            label, url = line.strip().split(maxsplit=1)
            features = constructDataSet(label, url)
            all_features.append(features)
            if first_write:
                pd.DataFrame([features]).to_csv('myDataSet.csv', index=False, mode='a', header=True)
                first_write = False
            else:
                pd.DataFrame([features]).to_csv('myDataSet.csv', index=False, mode='a', header=False)
    print("DataSet Completed!")





def checkCSV():
    with open('myDataSet.csv', 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        if not any(reader):
            print("Error")
        else:
            print("Passed Syntax Check")





def checkAccuracy():
    df = pd.read_csv("myDataSet.csv")
    LABEL = df.iloc[:,-1:].columns[0]
    cols = df.select_dtypes(include=['float64', 'int64']).columns
    df = pd.DataFrame(df[cols]).copy()
    myTrain, myTest = train_test_split(df, test_size=0.3)
    yTrain = pd.DataFrame(myTrain[LABEL]).copy()
    yTest = pd.DataFrame(myTest[LABEL]).copy()
    xTrain = myTrain.drop(LABEL, axis=1)
    xTest = myTest.drop(LABEL, axis=1)
    imputer = SimpleImputer(strategy='mean')
    xTrain = imputer.fit_transform(xTrain)
    xTest = imputer.transform(xTest)
    yImputer = SimpleImputer(strategy='most_frequent')
    yTrain = yImputer.fit_transform(yTrain)
    yTest = yImputer.transform(yTest)

    Models = []
    Models.append(('AdaBoost', AdaBoostClassifier()))
    Models.append(('Bagging', BaggingClassifier()))
    Models.append(('GradientBoost', GradientBoostingClassifier()))
    Models.append(('KNN', KNeighborsClassifier()))
    Models.append(('RandomForest', RandomForestClassifier())) 
    for name, Model in Models:
        Model = Model.fit(xTrain, yTrain.ravel())
        predict = Model.predict(xTest)
        accuracy = metrics.accuracy_score(yTest, predict)
        print(name , ' Accuracy : ', accuracy)



if __name__ == "__main__":
    #parseFile('Phishing.txt')
    #print('URL Check Completed')
    #time.sleep(1.5)
    print('Triggering Data Set Constructions')
    trainModel('openURLS.txt')
    time.sleep(1.5)
    print("Checking Syntax For CSV")
    checkCSV()
    time.sleep(1.5)
    print("Checking Accuracy for the DataSet")
    checkAccuracy()
