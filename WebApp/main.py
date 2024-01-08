from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from flask_bootstrap import Bootstrap
import pandas
import joblib
import threading
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import numpy as np
from sklearn.preprocessing import LabelEncoder
from io import BytesIO
from PIL import Image
import base64
import urllib.parse

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.secret_key = 'secret'
fileToTest = ""
issues_data = {}
predictedFile = "PredictedResults.xlsx"
lock = threading.Lock()

@app.get('/')
def upload():
    return render_template('home.html')

@app.post('/view')
def view():
    if request.files['file'].filename == '':
        flash('Please select a file.')
        return redirect(url_for('upload'))
    else:
        file = request.files['file']
        file.save(file.filename)
        lock.acquire()
        global fileToTest
        fileToTest = file.filename
        lock.release()

        verificationMessage = verify_excel(fileToTest)
        if verificationMessage != 'No error':
            flash(verificationMessage)
            return redirect(url_for('upload'))
        else:
            data = pandas.read_excel(fileToTest)
            return render_template('viewData.html', table_data=data.to_html())

@app.route('/confirm', methods=['GET', 'POST'])
def confirm_action():
    if request.method == 'POST':
        if request.form.get('confirm'):
            return redirect(url_for('view'))
        else:
            return redirect(url_for('upload'))
    else:
        return render_template('upload.html')

@app.post('/classify')
def classify():
    data = adjust_excel(fileToTest)
    #data = adjust_excel_with_sum_reduction(fileToTest)
    data.to_excel(fileToTest, index=False)
    data = pandas.read_excel(io=fileToTest)

    firstColumn = data.iloc[:, 0]
    data.drop(columns=data.columns[0], axis=1, inplace=True)
    model = joblib.load('finalized_model.sav')
    prediction = model.predict(data)
    df = pandas.DataFrame({'Component': firstColumn})
    label_encoder = joblib.load('encoder.sav')
    prediction = np.round(prediction).astype(int)
    predicted_strings = label_encoder.inverse_transform(prediction)

    df['Refactoring Type'] = predicted_strings
    df['Refactoring Type'] = df['Refactoring Type'].replace('Empty_list', 'No refactoring needed')
    df.to_excel(predictedFile)

    return render_template('finalResults.html', table_data=df.to_dict('records'), columns=df.columns)

@app.post('/data')
def data_visualization():
    selected_option = request.form["option"]
    data = pandas.read_excel(io=fileToTest)
    if selected_option == "nrIssues":
        if 'FrequencyClass' not in data.columns:
            freq_vector = data['component'].value_counts()
            lock.acquire()
            global issues_data
            issues_data = freq_vector.to_dict()
            lock.release()
        else:
            lock.acquire()
            issues_data = dict(zip(data['component'].tolist(), data['FrequencyClass'].tolist()))
            lock.release()
        return render_template("barGraph.html", issues_data=issues_data, label="Number of issues")
    elif selected_option == "severity":
        severities = ['MINOR', 'MAJOR', 'INFO', 'CRITICAL', 'BLOCKER']
        if data.loc[0, 'severity'] not in severities:
            flash('Cannot create these statistics. Invalid severities values.')
            return redirect(url_for('upload'))
        else:
            freq_vector = data['severity'].value_counts()
            lock.acquire()
            issues_data = freq_vector.to_dict()
            lock.release()
            return render_template("barGraph.html", issues_data=issues_data, label="Number of issues")
    elif selected_option == "type":
        types = ['BUG', 'CODE_SMELL', 'VULNERABILITY']
        if data.loc[0, 'type'] not in types:
            flash('Cannot create these statistics. Invalid type values.')
            return redirect(url_for('upload'))
        else:
            freq_vector = data['type'].value_counts()
            lock.acquire()
            issues_data = freq_vector.to_dict()
            lock.release()
            return render_template("barGraph.html", issues_data=issues_data, label="Number of issues")
    elif selected_option == "debt":
        lock.acquire()
        issues_data = {"0-10":0, "10-25":0, "25-50":0, "50-80":0, "80+":0}
        for i in range(len(data)):
            if data.loc[i, 'debt'] < 10:
                issues_data["0-10"] += 1
            elif data.loc[i, 'debt'] < 25:
                issues_data["10-25"] += 1
            elif data.loc[i, 'debt'] < 50:
                issues_data["25-50"] += 1
            elif data.loc[i, 'debt'] < 80:
                issues_data["50-80"] += 1
            else:
                issues_data["80+"] += 1
        lock.release()
        return render_template("barGraph.html", issues_data=issues_data, label="Number of issues")
    elif selected_option == "maintainability":
        data = pandas.read_excel(predictedFile)
        freq_vector = data['Maintainability Class'].value_counts()
        lock.acquire()
        issues_data = freq_vector.to_dict()
        lock.release()
        return render_template("barGraph.html", issues_data=issues_data, label="Number of issues")
    else:
        data = pandas.read_excel(predictedFile)
        freq_vector = data['Refactoring Type'].value_counts()
        lock.acquire()
        issues_data = freq_vector.to_dict()
        lock.release()
        return render_template("barGraph.html", issues_data=issues_data, label="Number of refactorings")

@app.route('/download')
def download_excel():
    return send_file(predictedFile, as_attachment=True)

@app.route('/submitCredentials', methods=['POST'])
def submitCredentials():
    username = request.form['username']
    password = request.form['password']
    project = request.form['project']
    print(username)
    print(password)
    print(project)

    if username == '' or password == '' or project == '':
        flash('Invalid username, password or project name', 'error')
        return redirect(url_for('upload'))
    else:
        try:
            requestResult = get_issues_from_sonar(username, password, project)
            if not requestResult:
                flash('Incorrect credentials', 'error')
                return redirect(url_for('upload'))
            else:
                lock.acquire()
                global fileToTest
                fileToTest = 'example.xlsx'
                lock.release()
                data = pandas.read_excel(fileToTest)
                columns = data.columns

                return render_template('viewData.html', table_data=data.to_html(), columns=columns)
        except requests.exceptions.ConnectionError:
            flash('SonarQube is not active', 'error')
            return redirect(url_for('upload'))

def get_issues_from_sonar(username, password, project):
    url = 'http://localhost:9000/api/issues/search'
    ##params = {'severities': 'MAJOR,CRITICAL', 'assignees': 'nits', 'pageSize': '-1', 'componentKeys': 'JEdit55'}
    #params = {'componentKeys': 'JEdit55'}
    params = {'componentKeys': project}
    #auth = ('admin', '1!Happyhappy')
    auth = (username, password)
    session = requests.Session()
    retry = Retry(connect=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    response = session.get(url, params=params, auth=auth)

    if response.status_code == requests.codes.ok:
        json_content = response.json()
        issues = json_content["issues"]
        severity = {'MINOR': 2, 'MAJOR': 3, 'INFO': 1, 'CRITICAL': 4, 'BLOCKER': 5}
        type = {'BUG': 2, 'VULNERABILITY': 3, 'CODE_SMELL': 1}
        componentsDebts = {}
        componentSeverities = {}
        componentsTypes = {}
        componentsFreq = {}
        components = []
        severities = []
        debts = []
        types = []

        for elem in issues:
            components.append(elem["component"])
            severities.append(elem["severity"])
            debts.append(elem["debt"][:-3])
            types.append(elem["type"])

        data = {"component": components, "severity": severities, "debt": debts, "type": types}
        df = pandas.DataFrame(data)
        df.to_excel("example.xlsx", index=False)
        return True
    else:
        return False

def verify_excel(fileName):
    data = pandas.read_excel(fileName)
    detectedError = False
    errorMessage = "Missing the following columns: "
    columns = ['component', 'severity', 'debt', 'type']

    for i in range(len(columns)):
        if columns[i] not in data:
            errorMessage += columns[i]
            errorMessage += ', '
            detectedError = True

    if detectedError:
        if errorMessage[-1] == ' ':
            errorMessage = errorMessage[:-2]
        return errorMessage
    else:
        #data = data.filter(columns, axis=1)
        return 'No error'

def is_float(value):
    try:
        float(value)
        return True
    except ValueError:
        return False

def adjust_debt(debt):
    if debt == None or debt == 'n/a':
        return 0
    return debt
def adjust_excel(filename):
    data = pandas.read_excel(filename)
    severities = {}
    types = {}
    debts = {}
    severity = {'MINOR': 2,  'MAJOR': 3,  'INFO': 1, 'CRITICAL': 4,  'BLOCKER': 5}

    if not is_float(data.loc[0, 'severity']):
        frequencyClass = {}
        type = {'BUG': 2, 'VULNERABILITY': 3, 'CODE_SMELL': 1}

        for i in range(len(data)):
            if data.loc[i, 'component'] in frequencyClass.keys():
                if adjust_debt(data.loc[i, 'debt']) > 0:
                    frequencyClass[data.loc[i, 'component']] += 1
                    debts[data.loc[i, 'component']] += data.loc[i, 'debt']
                    severities[data.loc[i, 'component']] += severity[data.loc[i, 'severity']]
                    types[data.loc[i, 'component']] += type[data.loc[i, 'type']]
            else:
                if adjust_debt(data.loc[i, 'debt']) > 0:
                    frequencyClass[data.loc[i, 'component']] = 1
                    debts[data.loc[i, 'component']] = data.loc[i, 'debt']
                    severities[data.loc[i, 'component']] = severity[data.loc[i, 'severity']]
                    types[data.loc[i, 'component']] = type[data.loc[i, 'type']]

        for key in frequencyClass:
            severities[key] /= frequencyClass[key]
            debts[key] /= frequencyClass[key]
            types[key] /= frequencyClass[key]

        components = frequencyClass.keys()
        newData = {"component": components, "severity": severities.values(), "debt": debts.values(), "type": types.values()}
        df = pandas.DataFrame(newData)
        return df
    else:
        newData = {"component": data['component'], "severity": data['severity'], "debt": data['debt'],
                   "type": data['type']}
        df = pandas.DataFrame(newData)
        return df

def adjust_excel_with_sum_reduction(filename):
    data = pandas.read_excel(filename)
    severities = {}
    types = {}
    debts = {}
    severity = {'MINOR': 2,  'MAJOR': 3,  'INFO': 1, 'CRITICAL': 4,  'BLOCKER': 5}

    if not is_float(data.loc[0, 'severity']):
        frequencyClass = {}
        type = {'BUG': 2, 'VULNERABILITY': 3, 'CODE_SMELL': 1}

        for i in range(len(data)):
            if data.loc[i, 'component'] in frequencyClass.keys():
                if adjust_debt(data.loc[i, 'debt']) > 0:
                    frequencyClass[data.loc[i, 'component']] += 1
                    debts[data.loc[i, 'component']] += data.loc[i, 'debt']
                    severities[data.loc[i, 'component']] += severity[data.loc[i, 'severity']]
                    types[data.loc[i, 'component']] += type[data.loc[i, 'type']]
            else:
                if adjust_debt(data.loc[i, 'debt']) > 0:
                    frequencyClass[data.loc[i, 'component']] = 1
                    debts[data.loc[i, 'component']] = data.loc[i, 'debt']
                    severities[data.loc[i, 'component']] = severity[data.loc[i, 'severity']]
                    types[data.loc[i, 'component']] = type[data.loc[i, 'type']]

        components = frequencyClass.keys()
        newData = {"component": components, "severity": severities.values(), "debt": debts.values(), "type": types.values()}
        df = pandas.DataFrame(newData)
        return df
    else:
        newData = {"component": data['component'], "severity": data['severity'], "debt": data['debt'],
                   "type": data['type']}
        df = pandas.DataFrame(newData)
        return df

def mapPredictionsToRef(floatPredictions):
    label_encoder = joblib.load('finalized_model.sav')
    predicted_labels = np.round(floatPredictions).astype(int)

    # Invert the mapping from integer labels to original strings
    inverse_mapping = {i: label for i, label in enumerate(label_encoder.classes_)}

    # Convert predicted labels back to original strings
    predicted_strings = [inverse_mapping[label] for label in predicted_labels]

    return predicted_strings
def mapRefactoringsToMaintainability(floatPredictions):
    predictions = []
    for i in range(len(floatPredictions)):
        if floatPredictions[i] < 5:
            predictions.append('Great')
        elif floatPredictions[i] < 20:
            predictions.append('Good')
        else:
            predictions.append('Poor')

    return predictions

def make_integer(elements):
    for i in range(len(elements)):
        elements[i] = int(elements[i])
    return elements

if __name__ == '__main__':
    app.run(debug=True)