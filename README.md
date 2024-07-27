# Documentation

This documentation provides a comprehensive overview of the script, its functionality, and detailed descriptions of each function, making it easier to understand, maintain and contribute.

## Dataset Preparation Script

This Python script automates the process of updating, validating, and constructing a dataset for phishing URL detection. It fetches new phishing URLs from OpenPhish, extracts features from these URLs, constructs a dataset, and evaluates the accuracy of various machine learning models on this dataset.

### Overview

The script performs the following tasks:

1.  **Fetch updates from OpenPhish**: Checks for new phishing URLs.
2.  **Append new URLs**: Writes new phishing URLs to a file.
3.  **Update the training base**: Appends new phishing URLs to the training base and clears the new URL file.
4.  **Check online URLs**: Verifies which phishing URLs are accessible.
5.  **Extract features**: Extracts various features from each URL.
6.  **Construct dataset**: Builds a CSV file containing the features of each URL.
7.  **Validate dataset**: Checks the validity of the constructed dataset.
8.  **Evaluate models**: Assesses the accuracy of different machine learning models on the dataset.

### Dependencies

Ensure you have the following Python packages installed :

- requests
- pandas
- scikit-learn
- tldextract
- BeautifulSoup4
- xgboost
- lightgbm

```
pip install requests pandas scikit-learn tldextract beautifulsoup4 xgboost lightgbm
```

### Functions

1. **ShannonEntropy(entropyType: str) -> int**<br><br>
   Calculates the Shannon Entropy of a given string, which is a measure of its unpredictability or randomness.

2. **getTitle(url: str) -> str**<br><br>
   Fetches the title of the webpage corresponding to the given URL. Returns the title as a string or 0 if the title is not found.

3. **hasTitle(url: str) -> bool**<br><br>
   Checks if the webpage corresponding to the given URL has a title. Returns 1 if the title is present, otherwise 0.

4. **hasFavicon(url: str) -> bool**<br><br>
   Checks if the webpage corresponding to the given URL has a favicon. Returns 1 if the favicon is present, otherwise 0.

5. **hasCopyRightInfo(url: str) -> bool**<br><br>
   Checks if the webpage corresponding to the given URL contains copyright information. Returns 1 if copyright information is found, otherwise 0.

6. **hasRedirects(url: str) -> bool**<br><br>
   Checks if the given URL redirects to another destination. Returns 1 if redirections are found, otherwise 0.

7. **checkUpdates(url: str, textFile: str) -> bool**<br><br>
   Checks for updates from OpenPhish by comparing the latest URL with the previously stored URL. Returns True if updates are available, otherwise False.

8. **appendNewURLs(url: str, textFile: str, isUpdate: bool) -> bool**<br><br>
   Appends new phishing URLs to the specified file if updates are available. Returns True if the operation is successful, otherwise False.

9. **updateBase(newFile: str, urlBase: str) -> bool**<br><br>
   Updates the training base with new URLs and clears the new URLs file. Returns True if the process is successful, otherwise returns an error message.

10. **checkOnlineURLs(url: str, onlineURLsFile: str) -> None**<br><br>
    Checks if the given URL is accessible and appends it to a file with a label of 0 if accessible.

11. **checkURLs(textFile: str, newFile: str) -> None**<br><br>
    Reads URLs from a file and checks if they are accessible. Calls checkOnlineURLs for each URL.

12. **extractFeatures(label: str, url: str) -> dict**<br><br>
    Extracts various features from the given URL and assigns a label (0 for phishing, 1 for legitimate). Returns a dictionary of extracted features.

13. **constructDataSet(newFile: str) -> bool**<br><br>
    Constructs a dataset by extracting features from URLs and writes the data to a CSV file. Returns True if successful, otherwise False.

14. **checkDataSet(dataset: str) -> bool**<br><br>
    Validates the constructed CSV dataset by checking for any syntax errors. Returns True if the dataset is valid, otherwise False.

15. **checkAccuracy(dataset: str) -> None**<br><br>
    Evaluates the accuracy of various machine learning models on the dataset. Prints the accuracy of each model.

### Execution

The script's main execution block performs the following steps:

1. Checks for updates from OpenPhish.
2. Appends new URLs to the file if updates are available.
3. Updates the training base with new URLs.
4. Checks which phishing URLs are accessible.
5. Constructs the dataset by extracting features from URLs.
6. Validates the constructed dataset.
7. Evaluates the accuracy of different machine learning models on the dataset.

### Notes

- Ensure that the URLs and paths provided in the script are correct and accessible.
- Handle exceptions appropriately to ensure the script's robustness and reliability.
- Modify and extend the feature extraction as needed to improve the phishing detection model.
