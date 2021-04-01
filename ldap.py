#! /usr/bin/env python3
#
# Python module "ldap"
# TANAKA Satoshi <tanaka@cis.twcu.ac.jp>

import radiusd
#from ldapsh import ldapAuthorize, ldapAuthenticate
from ldappy import ldapAuthorize, ldapAuthenticate

### utility functions for freeraduis

def getvalue(p,name):
  try:
    for i in p:
      if i[0] == name:
        return i[1]
  except e:
    radiusd.radlog(radiusd.L_INFO, "python3/ldap:" + str(e) + ":" + str(p))
  return None

def getuser(p):
  try:
    n = getvalue(p, 'User-Name')
    if n:
      return n.split('@')[0]
  except:
    pass
  return None

def getpassword(p):
  return getvalue(p, 'User-Password')

### for python3 modules

def instantiate(p):
  radiusd.radlog(radiusd.L_INFO, "python3/ldap instantiate")
  # return 0 for success or -1 for failure
  ## we cannot return

def authorize(p):
  radiusd.radlog(radiusd.L_INFO, "python3/ldap authorize")

  user=getuser(p)
  password=getpassword(p)
  if ldapAuthorize(user,password):
    return (radiusd.RLM_MODULE_UPDATED,
            (),
            (('Auth-Type', 'python3'),))
  return radiusd.RLM_MODULE_NOTFOUND

def authenticate(p):
  radiusd.radlog(radiusd.L_INFO, "python3/ldap authenticate")

  user=getuser(p)
  password=getpassword(p)
  if ldapAuthenticate(user,password):
    return radiusd.RLM_MODULE_OK
  else:
    return radiusd.RLM_MODULE_FAIL

# below functions is never called.
# for the sake of /etc/freeradius/3.0/mods-enable/python3 config.

def preacct(p):
  return radiusd.RLM_MODULE_OK

def accounting(p):
  return radiusd.RLM_MODULE_OK

def pre_proxy(p):
  return radiusd.RLM_MODULE_OK

def post_proxy(p):
  return radiusd.RLM_MODULE_OK

def post_auth(p):
  return radiusd.RLM_MODULE_OK

def recv_coa(p):
  return radiusd.RLM_MODULE_OK

def send_coa(p):
  return radiusd.RLM_MODULE_OK

def detach(p):
  return radiusd.RLM_MODULE_OK

