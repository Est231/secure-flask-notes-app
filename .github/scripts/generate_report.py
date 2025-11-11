import json
import os

def main():
    try:
        with open('bandit-report.json', 'r') as f:
            data = json.load(f)
        
        high = len([i for i in data['results'] if i['issue_severity'] == 'HIGH'])
        medium = len([i for i in data['results'] if i['issue_severity'] == 'MEDIUM'])
        low = len([i for i in data['results'] if i['issue_severity'] == 'LOW'])
        
        print(f'- High: {high}')
        print(f'- Medium: {medium}')
        print(f'- Low: {low}')
        
        if high > 0:
            print('CRITICAL ISSUES FOUND - MERGE BLOCKED')
        else:
            print('No critical issues found')
            
    except Exception as e:
        print(f'Error generating report: {e}')

if __name__ == '__main__':
    main()