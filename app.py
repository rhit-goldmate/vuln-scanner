from flask import Flask, render_template, request
import requests
import re

app = Flask(__name__)

# Function to check if URL is valid
def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IP address
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

# Function to check if the URL is malicious using VirusTotal API
def check_url_virustotal(url, api_key):
    vt_url = f'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': url}
    
    response = requests.get(vt_url, params=params)
    
    if response.status_code == 200:
        json_response = response.json()
        
        # Check if the URL is in VirusTotal's database
        if json_response['response_code'] == 1:
            positives = json_response.get('positives', 0)
            total = json_response.get('total', 0)
            
            # If there are positive detections, collect details from the 'scans' field
            if positives > 0:
                detailed_results = {
                    'phishing': [],
                    'malicious': [],
                    'clean': [],
                    'malware': [],
                    'unrated': []
                }
                phishing_count = 0
                malicious_count = 0
                clean_count = 0
                malware_count = 0
                unrated_count = 0

                scans = json_response.get('scans', {})
                for source, details in scans.items():
                    if details.get('detected'):
                        result = details.get('result', '').lower()
                        if 'phishing' in result:
                            phishing_count += 1
                            detailed_results['phishing'].append({
                                'source': source,
                                'result': result
                            })
                        elif 'malicious' in result:
                            malicious_count += 1
                            detailed_results['malicious'].append({
                                'source': source,
                                'result': result
                            })
                        elif 'malware' in result:
                            malware_count += 1
                            detailed_results['malware'].append({
                                'source': source,
                                'result': result
                            })
                        else:
                            unrated_count += 1
                            detailed_results['unrated'].append({
                                'source': source,
                                'result': result
                            })
                    else:
                        clean_count += 1
                        detailed_results['clean'].append({
                            'source': source,
                            'result': 'clean'
                        })
                
                return {
                    'status': 'malicious',
                    'positives': positives,
                    'total': total,
                    'phishing': phishing_count,
                    'malicious': malicious_count,
                    'malware': malware_count,
                    'clean': clean_count,
                    'unrated': unrated_count,
                    'detailed_results': detailed_results
                }
            else:
                return {'status': 'clean', 'positives': positives, 'total': total}
        else:
            return {'status': 'not_found'}
    else:
        return {'status': 'error'}

@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    details = None
    if request.method == 'POST':
        url = request.form['url']
        api_key = '60aeb4e8da17028ecc1a1ea5f826bca9bbf91c674eac754ef7c83bc047ed3187' 
        if is_valid_url(url):
            result = check_url_virustotal(url, api_key)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
