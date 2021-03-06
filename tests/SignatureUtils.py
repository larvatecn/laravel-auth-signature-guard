#!/usr/bin/python
# -*- coding:utf-8 -*-

import sys,os
import urllib, urllib2
import base64
import hmac
import hashlib
from hashlib import sha1
import time
import uuid
import json
from optparse import OptionParser
import ConfigParser
import traceback

client_id = '';
client_secret = '';
api_server_address = 'https://api.server.com'
CONFIGFILE = os.getcwd() + '/config.ini'
CONFIGSECTION = 'Credentials'
cmdlist = '''
接口说明请参照pdf文档
'''

def percent_encode(str):
    res = urllib.quote(str.decode(sys.stdin.encoding).encode('utf8'), '')
    res = res.replace('+', '%20')
    res = res.replace('*', '%2A')
    res = res.replace('%7E', '~')
    return res

def compute_signature(parameters, access_key_secret):
    sortedParameters = sorted(parameters.items(), key=lambda parameters: parameters[0])

    canonicalizedQueryString = ''
    for (k,v) in sortedParameters:
        canonicalizedQueryString += '&' + percent_encode(k) + '=' + percent_encode(v)

    stringToSign = percent_encode(canonicalizedQueryString[1:])

    h = hmac.new(access_key_secret + "&", stringToSign, sha1)
    signature = base64.encodestring(h.digest()).strip()
    return signature

def compose_url(user_params):
    parameters = { \
            'app_id'   : client_id, \
            'signature_version'  : '1.0', \
            'signature_method'   : 'HMAC-SHA1', \
            'signature_nonce'    : str(uuid.uuid1()), \
            'timestamp'         : time.time(), \
    }

    for key in user_params.keys():
        parameters[key] = user_params[key]

    signature = compute_signature(parameters, client_secret)
    parameters['Signature'] = signature
    url = server_address + "/?" + urllib.urlencode(parameters)
    return url

def make_request(user_params, quiet=False):
    url = compose_url(user_params)
    print url

def configure_clientkeypair(args, options):
    if options.client_id is None or options.client_secret is None:
        print("config miss parameters, use --id=[client_id] --secret=[client_secret]")
        sys.exit(1)
    config = ConfigParser.RawConfigParser()
    config.add_section(CONFIGSECTION)
    config.set(CONFIGSECTION, 'client_id', options.client_id)
    config.set(CONFIGSECTION, 'client_secret', options.client_secret)
    cfgfile = open(CONFIGFILE, 'w+')
    config.write(cfgfile)
    cfgfile.close()

def setup_credentials():
    config = ConfigParser.ConfigParser()
    try:
        config.read(CONFIGFILE)
        global client_id
        global client_secret
        client_id = config.get(CONFIGSECTION, 'client_id')
        client_secret = config.get(CONFIGSECTION, 'client_secret')
    except Exception, e:
		print traceback.format_exc()
		print("can't get access key pair, use config --id=[client_id] --secret=[client_secret] to setup")
		sys.exit(1)



if __name__ == '__main__':
    parser = OptionParser("%s Param1=Value1 Param2=Value2\n" % sys.argv[0])
    parser.add_option("-i", "--id", dest="client_id", help="specify client id")
    parser.add_option("-s", "--secret", dest="client_secret", help="specify client secret")
	
    (options, args) = parser.parse_args()
    if len(args) < 1:
		parser.print_help()
		sys.exit(0)

    if args[0] == 'help':
		print cmdlist
		sys.exit(0)
    if args[0] != 'config':
		setup_credentials()
    else: #it's a configure id/secret command
        configure_clientkeypair(args, options)
        sys.exit(0)

    user_params = {}
    idx = 1
    
    for arg in sys.argv[idx:]:
        try:
            key, value = arg.split('=')
            user_params[key.strip()] = value
        except ValueError, e:
            print(e.read().strip())
            raise SystemExit(e)
    make_request(user_params)

