#=============================================================================#
# Script Name: prioritize_report.py 										  #
# Description: Script generates a vulnerability report from Tenable.io 	      #
#              based on VPR score to prioritize remediation. Also shows first #
#			   discovery date. 												  #
# Author: Jose Lopez														  #
#=============================================================================#

import config, csv, json, requests
import pandas as pd
import numpy as np
from csv import reader


baseURL = 'https://cloud.tenable.com'
apiKeys = "accessKey= " + config.accessKey + ";secretKey= " + config.secretKey

def main():

	url = baseURL + '/workbenches/vulnerabilities'
	querystring = {
		"exploitable": "true"
	}
	headers = {
		"Accept": "application/json",
		"x-apikeys": apiKeys
	}
	r = requests.get(url, headers=headers, params=querystring)
	d = json.loads(r.text)
	vuln_name = [i['plugin_name'] for i in d['vulnerabilities']]
	vuln_id = [i['plugin_id'] for i in d['vulnerabilities']]
	count = [i['count'] for i in d['vulnerabilities']]
	severity = [i.get('severity') for i in d['vulnerabilities']]
	discovery_date = []
	for id in vuln_id:
		url = f'''https://cloud.tenable.com/workbenches/vulnerabilities/{id}/info'''
		headers = {
			"Accept": "application/json",
			"x-apikeys": apiKeys
		}
		r = requests.get(url, headers=headers)
		d = r.json()
		date = []
		if(d["info"]["discovery"]["seen_first"] == " "):
			continue
		else:
			date = d["info"]["discovery"]["seen_first"]
			discovery_date.append(date)
	data = {'No. of Assets/Vulnerability': count, 'Vulnerability Name': vuln_name, 'ID': vuln_id, 'Vulnerability Severity': severity, 'First Discovered': discovery_date}
	df = pd.DataFrame(data)
	df1 = df.replace(np.nan, 'No Value Available', regex=True)
	print(df1)
	df1.to_csv('priority_report.csv')

if __name__ == '__main__':
	main()





	