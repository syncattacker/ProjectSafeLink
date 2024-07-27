# All imports
import requests
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
from bs4 import BeautifulSoup
import tldextract
import math
import csv
import warnings


# Suppress the terminal warnings
warnings.filterwarnings('ignore')


# Headers for sending requests for training and extracting data.
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept-Language': 'en-US,en;q=0.9',
    'Referer': 'https://www.google.com/',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'DNT': '1',
}


# Check for Shannon Entropy
def ShannonEntropy(entropyType : str) -> int:
    '''
    Shannon Entropy is a measure of the unpredictability or randomness of a set of data.
    '''
    probabilities = [float(entropyType.count(c)) / len(entropyType) for c in dict.fromkeys(list(entropyType))]
    return -sum([p * math.log(p) / math.log(2.0) for p in probabilities])


# Get the title of the URL
def getTitle(url : str) -> str:
    '''
    Gets the Title Of the URL.
    '''
    try:
        return BeautifulSoup(requests.get(url, headers=headers).content, 'html.parser').title.string
    except:
        return 0


# Check if the URL has title
def hasTitle(url :  str) -> bool:
    '''
    Checks if the Website has Title.
    Returns 1 if title is there, 0 if there is no title found.
    '''
    hasTitle = BeautifulSoup(requests.get(url, headers=headers).content, 'html.parser').title
    if hasTitle:
        return 1  
    else:
        return 0 


# Check if the URL has favicon
def hasFavicon(url : str) -> bool:
    '''
    Checks if the Website has Favicon or not.
    Returns 1 if favicon is present else 0 if not present.
    '''
    if BeautifulSoup(requests.get(url, headers=headers).content, 'html.parser').find("link", rel=re.compile(r'^(shortcut )?icon$', re.I)):
        return 1
    else:
        return 0 


# Check if the URL has Copyright Information
def hasCopyRightInfo(url : str) -> bool:
    '''
    Checks if the Website has Copyright Informations.
    Returns 1 if copyright informations are present else returns 0.
    '''
    for element in BeautifulSoup(requests.get(url, headers=headers).content, 'html.parser').find_all(['footer', 'div', 'span', 'p', 'small', 'a']):
        text = element.get_text().lower()
        for keyword in ['copyright', '©']:
            if keyword in text:
                return 1
    return 0


# Check if it has any redirects
def hasRedirects(url : str) -> bool:
    '''
    Checks if the URL redirects to any other destination.
    Returns 1 if redirects else returns 0.
    '''
    if len(requests.get(url, headers=headers).history):
        return 1
    else:
        return 0 


# Check for new updates everytime the script runs
def checkUpdates(url : str, textFile : str) -> bool:
    '''
    Check for updates from OpenPhish for new urls before constructing online phishing urls.
    Return true if updates available else return false
    '''
    previousFile = open(textFile, 'r')
    readLink = previousFile.readlines(1)[0].strip('\n')
    try:
        response = requests.get(url)
        if response.ok:
            extractOne = response.text.split('\n')[0]
            if readLink == extractOne:
                return False
            else:
                return True
    except Exception as error:
        return f"Error! Occured, {error}"


# Write the new Urls to the text file for further processing
def appendNewURLs(url : str, textFile : str, isUpdate : bool) -> bool:
    '''
    If Update is available then write the new URLs into the file.
    Returns true if write success else Returns error
    '''
    if isUpdate:
        try:
            response = requests.get(url)
            if response.ok:
                file = open(textFile, 'w')
                file.write(response.text)
                return True
            else:
                return False
        except Exception as error:
            return f"Error! Occurred, {error}"
    else:
        return False


# Clear the newFile for the new URLs that will arrive, and update the trained URL Base
def updateBase(newFile :  str, urlBase : str) -> bool:
    '''
    Updates the Trained URL Base and clears the openURLs Base for new URLs.
    Returns True if the proccess carried out goes smooth, else returns the error.
    '''
    try:
        with open(newFile, 'r') as previousBase:
            previousURLBase = previousBase.read()
        with open(urlBase, 'a') as trainBase:
            trainBase.write(previousURLBase)
        with open(newFile, 'w') as newBase:
            newBase.write('')
            return True
    except Exception as error:
        return f"Error! Occured {error}"



# Check for URLs that are accessible and label them as 0 as all of them are Phishing
def checkOnlineURLs(url : str, onlineURLsFile :  str) -> None:
    '''
    Takes Phishing URLs from the new URLs after the update and checks if they are accessible.
    If accessible appends them to a new file with a label of 0.
    '''
    try:
        isOnline = requests.get(url)
        if isOnline.status_code == 200:
            file = open(onlineURLsFile, 'a')
            file.write('0 ' + url + '\n')
        else:
            pass
    except Exception:
        pass


# Check for online Urls from the list of Urls available
def checkURLs(textFile : str, newFile : str) -> None:
    '''
    Takes in the Original Phishing File and extracts single URLs from it and passes them for check.
    Calls Online Check Function for extracting online URLs
    Return is None
    '''
    with open(textFile, 'r') as phishingURLs:
        for urls in phishingURLs:
            url = urls.strip()
            checkOnlineURLs(url, newFile)
           

# URLs Feature extractions
def extractFeatures(label : str, url : str) -> dict:
    '''
    Extract the features from url and assign label as 0 or 1.
    0 ---> Phishing
    1 ---> Legitimate
    Returns the features extracted.
    '''
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
        features['HasTitle'] = hasTitle(url)
        features['Title'] = getTitle(url)
        features['HasFavicon'] = hasFavicon(url)
        features['HasCopyRightInfo'] = hasCopyRightInfo(url)
        features['HasURLRedirects'] = hasRedirects(url)
        features['label'] = label
    except Exception:
        pass
    return features


# Construct the CSV dataset for training.
def constructDataSet(newFile : str) -> bool:
    '''
    Construct the dataset using the extracted features for both Phishing and Legitimate URLs.
    '''
    all_features = []
    first_write = False
    with open(newFile, 'r') as file:
        for line in file:
            label, url = line.strip().split(maxsplit=1)
            features = extractFeatures(label, url)
            all_features.append(features)
            if first_write:
                pd.DataFrame([features]).to_csv('myDataSet.csv', index=False, mode='a', header=True)
                first_write = False
            else:
                pd.DataFrame([features]).to_csv('myDataSet.csv', index=False, mode='a', header=False)
    return True


# Check if the CSV constructed is valid or not.
def checkDataSet(dataset : str) -> bool:
    '''
    Syntax check for the CSV for no errors.
    Return True if all ok else return False
    '''
    with open(dataset, 'r', encoding='utf-8') as file:
        reader = csv.reader(file)
        if not any(reader):
            return False
        else:
            return True


# Check the accuracy of dataset on different models before training it.
def checkAccuracy(dataset :  str) -> None:
    df = pd.read_csv(dataset)
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


# Global files and variables.
url = 'https://openphish.com/feed.txt'
textFile = 'Phishing.txt'
newFile = 'openURLs.txt'
trainBase = 'trained.txt'
dataset = 'myDataSet.csv'


# Execute Functions for automation.
if __name__ == "__main__":
    isUpdated = checkUpdates(url, textFile)
    if isUpdated:
        newURLs = appendNewURLs(url, textFile, isUpdated)
        if newURLs:
            isBaseUpdated = updateBase(newFile, trainBase)
            if isBaseUpdated:
                checkURLs(textFile, newFile)
            else:
                print(isBaseUpdated)
        else:
            print(newURLs)
        isConstructed = constructDataSet(newFile)
        if isConstructed:
            isCorrect = checkDataSet(dataset)
            if isCorrect:
                checkAccuracy(dataset)
                print("Done! You are all set")
            else:
                print(isCorrect)
        else:
            print(isConstructed)
    else:
        print("No Updates Available")
        exit()