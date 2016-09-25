#!/usr/bin/env python

import requests
import time
import sys
import logging


API = 'https://api.ssllabs.com/api/v2/'

def requestAPI(path, payload={}):
    '''This is a helper method that takes the path to the relevant
        API call and the user-defined payload and requests the
        data/server test from Qualys SSL Labs.

        Returns JSON formatted data'''

    url = API + path

    try:
        response = requests.get(url, params=payload)
    except requests.exception.RequestException:
        logging.exception('Request failed.')
        sys.exit(1)

    data = response.json()
    return data


def resultsFromCache(host, publish='off', startNew='off', fromCache='on', all='done'):
    path = 'analyze'
    payload = {
                'host': host,
                'publish': publish,
                'startNew': startNew,
                'fromCache': fromCache,
                'all': all
              }
    data = requestAPI(path, payload)

    '''
    my_results = {}
    my_results['startTime'] = data['startTime']
    my_results['grade'] = data['endpoints'][0]['grade']
    my_results['hasWarnings'] = data['endpoints'][0]['hasWarnings']
    my_results['rc4'] = data['endpoints'][0]['details']['rc4WithModern']
    my_results['fallbackScsv'] = data['endpoints'][0]['details']['fallbackScsv']
    my_results['poodleTls'] = data['endpoints'][0]['details']['poodleTls']
    my_results['dhYsReuse'] = data['endpoints'][0]['details']['dhYsReuse']
    my_results['cert'] = {}
    my_results['cert']['sigAlg'] = data['endpoints'][0]['details']['chain']['certs'][0]['sigAlg']
    my_results['cert']['keyAlg'] = data['endpoints'][0]['details']['chain']['certs'][0]['keyAlg']
    my_results['cert']['keyStrength'] = data['endpoints'][0]['details']['chain']['certs'][0]['keyStrength']
    my_results['cert']['notBefore'] = data['endpoints'][0]['details']['chain']['certs'][0]['notBefore']
    my_results['cert']['notAfter'] = data['endpoints'][0]['details']['chain']['certs'][0]['notAfter']
    my_results['poodle'] = data['endpoints'][0]['details']['poodle']
    my_results['drownVulnerable'] = data['endpoints'][0]['details']['drownVulnerable']
    my_results['vulnBeast'] = data['endpoints'][0]['details']['vulnBeast']
    my_results['heartbleed'] = data['endpoints'][0]['details']['heartbleed']
    my_results['ipAddress'] = data['endpoints'][0]['ipAddress']
    return my_results
    '''
    return data


def newScan(host, publish='off', startNew='on', all='done', ignoreMismatch='on'):
    path = 'analyze'
    payload = {
                'host': host,
                'publish': publish,
                'startNew': startNew,
                'all': all,
                'ignoreMismatch': ignoreMismatch
              }
    results = requestAPI(path, payload)

    payload.pop('startNew')

    while results['status'] != 'READY' and results['status'] != 'ERROR':
        time.sleep(30)
        results = requestAPI(path, payload)

    '''
    my_results = {}
    my_results['startTime'] = results['startTime']
    my_results['grade'] = results['endpoints'][0]['grade']
    my_results['hasWarnings'] = results['endpoints'][0]['hasWarnings']
    my_results['rc4'] = results['endpoints'][0]['details']['rc4WithModern']
    my_results['fallbackScsv'] = results['endpoints'][0]['details']['fallbackScsv']
    my_results['poodleTls'] = results['endpoints'][0]['details']['poodleTls']
    my_results['dhYsReuse'] = results['endpoints'][0]['details']['dhYsReuse']
    my_results['cert'] = {}
    my_results['cert']['sigAlg'] = results['endpoints'][0]['details']['chain']['certs'][0]['sigAlg']
    my_results['cert']['keyAlg'] = results['endpoints'][0]['details']['chain']['certs'][0]['keyAlg']
    my_results['cert']['keyStrength'] = results['endpoints'][0]['details']['chain']['certs'][0]['keyStrength']
    my_results['cert']['notBefore'] = results['endpoints'][0]['details']['chain']['certs'][0]['notBefore']
    my_results['cert']['notAfter'] = results['endpoints'][0]['details']['chain']['certs'][0]['notAfter']
    my_results['poodle'] = results['endpoints'][0]['details']['poodle']
    my_results['drownVulnerable'] = resutls['endpoints'][0]['details']['drownVulnerable']
    my_results['vulnBeast'] = results['endpoints'][0]['details']['vulnBeast']
    my_results['heartbleed'] = results['endpoints'][0]['details']['heartbleed']
    my_results['ipAddress'] = data['endpoints'][0]['ipAddress']
    '''
    return results

def docheckcert(host):
    data = resultsFromCache(host)
    #print data
    #print len(data['endpoints'])
    if (data['status'] != 'READY' and data['status'] != 'ERROR') or (data['status'] == 'READY' and data['endpoints'][0]['eta'] == -1):
        data = newScan(host)
    return data

#print docheckcert("https://blog.trich.im")