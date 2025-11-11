import json
import sys
import os

def main():
    try:
        with open('bandit-report.json', 'r') as f:
            data = json.load(f)
        
        critical = len([i for i in data['results'] if i['issue_severity'] == 'HIGH'])
        print(f'Critical issues found: {critical}')
        
        if critical > 0:
            print('Critical security issues detected! Merge blocked.')
            sys.exit(1)
        else:
            print('No critical issues found')
            sys.exit(0)
            
    except Exception as e:
        print(f'Error reading bandit report: {e}')
        sys.exit(0)

if __name__ == '__main__':
    main()