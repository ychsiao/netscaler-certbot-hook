#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""netscaler-certbot-hook.py: A Certbot Hook for Citrix NetScaler ADC"""

__author__ = "Simon Lauger"
__copyright__ = "Copyright 2020, IT Consulting Simon Lauger"
__license__ = "MIT"
__version__ = "0.0.1"
__maintainer__ = "Simon Lauger"
__email__ = "simon@lauger.de"

import argparse
import os
import sys
import json
import time
import base64
import requests
import urllib.parse
requests.packages.urllib3.disable_warnings()
from OpenSSL import crypto
import nitro

add_args = {
  '--name': {
    'metavar': '<string>',
    'help': 'object name of the ssl certificate',
    'type': str,
    'default': None,
    'required': True,
  },
  '--chain': {
    'metavar': '<string>',
    'help': 'object name of the ssl chain certificate',
    'type': str,
    'default': 'letsencrypt',
    'required': False,
  },
  '--cert': {
    'metavar': '<file>',
    'help': 'path to the ssl certificate (default: /etc/letsencrypt/live/name/cert.pem)',
    'type': str,
    'default': None,
    'required': False,
  },
  '--privkey': {
    'metavar': '<file>',
    'help': 'path to the ssl private key (default: /etc/letsencrypt/live/name/privkey.pem)',
    'type': str,
    'default': None,
    'required': False,
  },
  '--chain-cert': {
    'metavar': '<file>',
    'help': 'path to the ssl chain certificate (default: /etc/letsencrypt/live/name/chain.pem)',
    'type': str,
    'default': None,
    'required': False,
  },
  '--ns-url': {
    'metavar': '<url>',
    'help': 'NetScaler URL (e.g., https://netscaler.example.com)',
    'type': str,
    'default': None,
    'required': False,
  },
  '--ns-login': {
    'metavar': '<string>',
    'help': 'NetScaler login username (default: nsroot)',
    'type': str,
    'default': None,
    'required': False,
  },
  '--ns-password': {
    'metavar': '<string>',
    'help': 'NetScaler login password (default: nsroot)',
    'type': str,
    'default': None,
    'required': False,
  },
  '--ns-verify-ssl': {
    'metavar': '<yes|no>',
    'help': 'Verify NetScaler SSL certificate (default: no)',
    'type': str,
    'default': None,
    'required': False,
  },
  '--dev-mode': {
    'metavar': '',
    'help': 'Enable development mode (uses ../cert as default cert-dir)',
    'type': bool,
    'default': False,
    'required': False,
  },
  '--cert-dir': {
    'metavar': '<directory>',
    'help': 'Base directory for certificates (default: /etc/letsencrypt/live in production, ../cert in dev mode)',
    'type': str,
    'default': None,
    'required': False,
  },
}

def add_argument(parser, arg, params):
    if params['type'] == bool:
        parser.add_argument(
            arg,
            action='store_true',
            help=params['help'],
            default=params['default'],
        )
    else:
        parser.add_argument(
            arg,
            metavar=params['metavar'],
            type=params['type'],
            help=params['help'],
            default=params['default'],
            required=params['required']
        )

# check for existence of an certificate via nitro api
def nitro_check_cert(nitro_client, objectname):
  try:
    result = nitro_client.request(
      'get',
      endpoint='config',
      objecttype='sslcertkey',
      objectname=objectname,
    )
  except:
    result = False
  return result

# upload a file via nitro api
def nitro_upload(nitro_client, source_file, target_filename):
  return nitro_client.request(
    'post',
    endpoint='config',
    objecttype='systemfile',
    data=json.dumps({
      'systemfile': {
        'filename': target_filename,
        'filecontent': base64.b64encode(open(source_file, 'rb').read()).decode('utf-8'),
        'filelocation': '/nsconfig/ssl',
        'fileencoding': 'BASE64',
      }
    }),
  )

def nitro_delete(nitro_client, filename):
  return nitro_client.request(
    'delete',
    endpoint='config',
    objecttype='systemfile',
    objectname=filename,
    params={'args': 'filelocation:%%2Fnsconfig%%2Fssl'},
  )

# install a certificate via nitro api
def nitro_install_cert(nitro_client, name, cert=None, key=None, update=False, nodomaincheck=False):
  data = {
    'sslcertkey': {
      'certkey': name,
    }
  }

  if update:
    params = {'action': 'update'}
  else:
    params = {}

  if cert:
    data['sslcertkey']['cert'] = "/nsconfig/ssl/{}".format(cert)
  if key:
    data['sslcertkey']['key'] = "/nsconfig/ssl/{}".format(key)
  if nodomaincheck:
    data['sslcertkey']['nodomaincheck'] = True

  return nitro_client.request(
    'post',
    endpoint='config',
    objecttype='sslcertkey',
    data=json.dumps(data),
    params=params,
  )

# link a certificate to a chain certificate via nitro api
def nitro_link_cert(nitro_client, name, chain):
  return nitro_client.request(
    'post',
    endpoint='config',
    objecttype='sslcertkey',
    data=json.dumps({
      'sslcertkey': {
        'certkey': name,
        'linkcertkeyname': chain,
      }
    }),
    params={'action': 'link'},
  )

def nitro_save_config(nitro_client):
  return nitro_client.request(
    'post',
    endpoint='config',
    objecttype='nsconfig',
    data=json.dumps({
      'nsconfig': {}
    }),
    params={'action': 'save'},
  )

# add cli arguments
parser = argparse.ArgumentParser(description='command line arguments.')

# optional arguments
for key in add_args:
  add_argument(parser, key, add_args[key])

# parse arguments
args = parser.parse_args()

# get credentials from command line arguments or environment (arguments take precedence)
username   = args.ns_login if args.ns_login else os.getenv('NS_LOGIN', 'nsroot')
password   = args.ns_password if args.ns_password else os.getenv('NS_PASSWORD', 'nsroot')
verify_ssl_str = args.ns_verify_ssl if args.ns_verify_ssl else os.getenv('NS_VERIFY_SSL', 'no')
verify_ssl = verify_ssl_str.lower() in ('yes', 'true', '1')
url        = args.ns_url if args.ns_url else os.getenv('NS_URL', None)

# determine certificate base directory
if args.cert_dir:
  cert_base_dir = args.cert_dir
elif args.dev_mode:
  cert_base_dir = '../cert'
else:
  cert_base_dir = '/etc/letsencrypt/live'

# default to certbot cert
if args.cert == None:
  cert_file = '{}/{}/cert.pem'.format(cert_base_dir, args.name)
else:
  cert_file = args.cert

# default to certbot privkey
if args.privkey == None:
  privkey_file = '{}/{}/privkey.pem'.format(cert_base_dir, args.name)
else:
  privkey_file = args.privkey

# default to certbot chain
if args.chain_cert == None:
  chain_file = '{}/{}/chain.pem'.format(cert_base_dir, args.name)
else:
  chain_file = args.chain_cert

# url is required
if url == None:
  raise Exception('required environment variable NS_URL not set')

# global unique timestamp
timestamp = int(time.time())

# start nitro client
nitro_client = nitro.NitroClient(url, username, password)

# disable ssl verification if needed
nitro_client.set_verify(verify_ssl)

# continue on errors
nitro_client.on_error('continue')

# get serial from certificates
chain_serial = crypto.load_certificate(crypto.FILETYPE_PEM, open(chain_file).read()).get_serial_number()
cert_serial  = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read()).get_serial_number()

# get installed chain certkey
check_chain = nitro_check_cert(nitro_client, args.chain)

if check_chain:
  installed_chain_serial = int(check_chain['sslcertkey'][0]['serial'], 16)
  print("chain certificate {} found with serial {}".format(args.chain, installed_chain_serial))

  if installed_chain_serial == chain_serial:
    print("installed chain certificate matches our serial - nothing to do")
  else:
    print("installed chain certificate serial {} does not match our serial {}".format(installed_chain_serial, chain_serial))
    print("uploading new chain certificate as {}-{}.crt".format(args.chain, timestamp))
    nitro_upload(nitro_client, chain_file, '{}-{}.crt'.format(args.chain, timestamp))
    print("updating chain certificate with serial {}".format(chain_serial))
    nitro_install_cert(nitro_client, args.chain, cert="{}-{}.crt".format(args.chain, timestamp), update=True, nodomaincheck=True)
else:
  print("chain certificate {} not found".format(args.chain))
  print("uploading chain certificate as {}-{}.crt".format(args.chain, timestamp))
  nitro_upload(nitro_client, chain_file, '{}-{}.crt'.format(args.chain, timestamp))
  print("installing chain certificate with serial {}".format(chain_serial))
  nitro_install_cert(nitro_client, args.chain, cert="{}-{}.crt".format(args.chain, timestamp))

check_cert = nitro_check_cert(nitro_client, args.name)

if check_cert:
  print("certificate {} found with serial {}".format(args.name, int(check_cert['sslcertkey'][0]['serial'], 16)))

  if int(check_cert['sslcertkey'][0]['serial'], 16) == cert_serial:
    print("installed certificate matches our serial - nothing to do")
  else:
    print("uploading certificate as {}-{}.crt".format(args.name, timestamp))
    nitro_upload(nitro_client, cert_file, '{}-{}.crt'.format(args.name, timestamp))
    print("uploading private key as {}-{}.key".format(args.name, timestamp))
    nitro_upload(nitro_client, privkey_file, '{}-{}.key'.format(args.name, timestamp))
    print("update certificate {}".format(args.name))
    nitro_install_cert(nitro_client, args.name, cert="{}-{}.crt".format(args.name, timestamp), key="{}-{}.key".format(args.name, timestamp), update=True, nodomaincheck=True)
    print("link certificate {} to chain certificate {}".format(args.name, args.chain))
    try:
      nitro_link_cert(nitro_client, args.name, args.chain)
    except:
      print("certificate link was already present - nothing to do")
    print("saving configuration")
    nitro_save_config(nitro_client)
else:
  print("certificate {} not found".format(args.name))
  print("uploading certificate as {}-{}.crt".format(args.name, timestamp))
  nitro_upload(nitro_client, cert_file, '{}-{}.crt'.format(args.name, timestamp))
  print("uploading private key as {}-{}.key".format(args.name, timestamp))
  nitro_upload(nitro_client, privkey_file, '{}-{}.key'.format(args.name, timestamp))
  print("installing certificate with serial {}".format(cert_serial))
  nitro_install_cert(nitro_client, args.name, cert="{}-{}.crt".format(args.name, timestamp), key="{}-{}.key".format(args.name, timestamp))
  print("link certificate {} to chain certificate {}".format(args.name, args.chain))
  try:
    nitro_link_cert(nitro_client, args.name, args.chain)
  except:
    print("certificate link was already present - nothing to do")
  print("saving configuration")
  nitro_save_config(nitro_client)

sys.exit(0)
