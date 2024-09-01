import requests
import time

# Replace with your VirusTotal API key
API_KEY = '60aeb4e8da17028ecc1a1ea5f826bca9bbf91c674eac754ef7c83bc047ed3187'

def scan_url(url):
    headers = {
        'x-apikey': API_KEY
    }
    
    # Submit URL to VirusTotal
    response = requests.post(
        'https://www.virustotal.com/api/v3/urls',
        headers=headers,
        data={'url': url}
    )
    
    if response.status_code == 200:
        result = response.json()
        scan_id = result['data']['id']
        print(f'Scan ID: {scan_id}')
        print('Scanning URL, please wait...')
        
        # Poll for the scan report
        while True:
            report_response = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{scan_id}',
                headers=headers
            )
            
            if report_response.status_code == 200:
                report = report_response.json()
                attributes = report['data']['attributes']
                
                if 'last_analysis_stats' in attributes:
                    last_analysis_stats = attributes['last_analysis_stats']
                    print('Scan results:')
                    print(f"- Detected: {last_analysis_stats['malicious']} malicious")
                    print(f"- Clean: {last_analysis_stats['undetected']} clean")
                    print(f"- Suspicious: {last_analysis_stats['suspicious']} suspicious")
                    print(f"- Unknown: {last_analysis_stats['unknown']} unknown")
                    break
                else:
                    print('Scan report is not yet available. Retrying in 10 seconds...')
                    time.sleep(10)  # Wait before retrying
            else:
                print('Failed to retrieve scan report. Please try again later.')
                break
    else:
        print('Failed to submit URL for scanning. Please check your API key and URL.')

if __name__ == '__main__':
    url_to_scan = input('Enter the URL to scan: ')
    scan_url(url_to_scan)
