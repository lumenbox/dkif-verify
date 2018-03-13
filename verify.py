#!/usr/bin/env python
# -*- coding: utf-8 -*-

import dns.resolver
import urllib
import urllib2
import toml
import sys
import json
import base64
import hashlib
import ed25519
from federationxdr import Xdr
from flask import Flask, jsonify


__version__ = "0.1.0"
app = Flask(__name__)

class AccountID(object):
    def __init__(self, account_id):
        self._account_id = account_id

    def __str__(self):
        return 'account id: %s' % self._account_id

    @property
    def _ed25519_key(self):
        return base64.b32decode(self._account_id)[1:-2]

    @property
    def xdr_object(self):
        ret = Xdr.types.AccountID(Xdr.const.KEY_TYPE_ED25519, self._ed25519_key)
        return ret


class Memo(object):
    def __init__(self, memo_type=None, memo=None):
        self._memo = memo
        self._memo_type = memo_type
        self._memo_type_dict = {None: {'type': Xdr.const.MEMO_NONE},
                                '': {'type': Xdr.const.MEMO_NONE},
                                'id': {'type': Xdr.const.MEMO_ID, 'id': self._memo},
                                'text': {'type': Xdr.const.MEMO_TEXT, 'text': self._memo},
                                'hash': {'type': Xdr.const.MEMO_HASH, 'hash': self._memo}}

    def __str__(self):
        return 'memo_type: %s memo: %s' % (self._memo_type, self._memo)

    @property
    def xdr_object(self):
        try:
            memo_dict = self._memo_type_dict[self._memo_type]
        except KeyError:
            raise ValueError(
                'memo_type is %s but must be one of the following: %s' % (self._memo_type_dict.keys(), self._memo_type))
        if memo_dict['type'] == Xdr.const.MEMO_ID:
            try:
                memo_dict['id'] = int(memo_dict['id'])
            except ValueError:
                ValueError('memo_type is id but "%s" memo cannot be converted to integer' % self._memo)
        ret = Xdr.types.Memo(**memo_dict)
        return ret

class FederationResponse(object):
    def __init__(self, stellar_address, account_id, memo_type=None, memo=None):
        self._stellar_address = stellar_address
        self._account_id = AccountID(account_id)
        self._memo = Memo(memo_type, memo)

    def __str__(self):
        return 'stellar_address: %s %s %s' % (self._stellar_address, self._account_id, self._memo)

    @property
    def xdr_object(self):
        ext = Xdr.nullclass
        ext.v = 0
        return Xdr.types.FederationResponse(self._stellar_address, self._account_id.xdr_object, self._memo.xdr_object,
                                            ext)

    @property
    def xdr(self):
        fedresp = Xdr.federationPacker()
        fedresp.pack_FederationResponse(self.xdr_object)
        packed_xdr = fedresp.get_buffer()
        return packed_xdr

# get TXT record for DKIF in DNS
def getTXT(domain):
  address = "federation._stellardomainkey." + domain
  keys = []
  try:
    records = dns.resolver.query(address, 'TXT')
    for record in records:
      keys = keys + record.strings
  except:
    return None
  return keys

# get federation server from stellar.toml file
def getFederationInfo(domain):
  url = "https://" + domain + "/.well-known/stellar.toml"
  answer = {}
  try:
    response = urllib2.urlopen(url)
    answer['request'] = response.getcode()
  except:
    answer['request_error'] = "Could not open 'stellar.toml' url"
    return answer
  try:
    headers = response.info()
    answer['control'] = headers['Access-Control-Allow-Origin']
    if answer['control'] != "*":
      answer['control_error'] = "Header 'Access-Control-Allow-Origin' must be set to '*'"
  except:
    answer['control_error'] = "Header 'Access-Control-Allow-Origin' is not set"
  try:
    answer['toml'] = response.read()
  except:
    answer['toml_error'] = "Could not read 'stellar.toml' file"
    return answer
  try:
    stellar_toml = toml.loads(answer['toml'])
    answer['url'] = stellar_toml['FEDERATION_SERVER']
    if not url.startswith("https://"):
      answer['url_error'] = "URL is not a valid HTTP url"
  except:
    answer['url_error'] = "Could not find 'FEDERATION_SERVER' entry in stellar.toml file"
  return answer

# get response from federation server
def queryFederation(name, url):
  q = { 'q': name, 'type': 'name' }
  url2 = url + "?" + urllib.urlencode(q)
  try:
    response = urllib2.urlopen(url2)
    return json.loads(response.read())
  except:
    answer = {
     'error': "Could not query Federation server"
    }
    return answer

# validate signature with key
def validateSignature(response, keys):
  answer = {}
  args = ['stellar_address', 'account_id', 'memo_type', 'memo']
  resp_filtered = {k:v for k,v in response.iteritems() if k in args}
  try:
    fedResp = FederationResponse(**resp_filtered)
  except:
    return {'error': 'invalid Federation response'}
  if 'signature' not in response:
    answer['verified'] = False
    answer['error'] = "No signature in response"
    return answer
  signature = response['signature']
  signature = base64.b64decode(signature)
  hash = hashlib.sha256(fedResp.xdr).digest()
  for key in keys:
    try:
      pubkey = base64.b32decode(key)
      pubkey = ed25519.VerifyingKey(pubkey[1:-2])
      pubkey.verify(signature, hash)
      # throws exception if fails
      answer['signed'] = key
      return answer
    except:
      pass
  return answer

# endpoint: validate a domain
@app.route("/<domain>")
def verifyDomain(domain):
  info = getFederationInfo(domain)
  info['keys'] = getTXT(domain)
  return jsonify(info)

# endpoint: validate a record
@app.route("/<user>*<domain>")
def verifyAccount(user, domain):
  info = getFederationInfo(domain)
  info['keys'] = getTXT(domain)
  if 'url' in info:
    record = queryFederation(user + "*" + domain, info['url'])
    if 'stellar_address' in record or 'account_id' in record:
      info['record'] = record
  if 'record' in info and 'keys' in info:
    info['validate'] = validateSignature(info['record'], info['keys'])
  return jsonify(info)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
