import os
import ldap
import datetime

import radiusd

#### ldap constants

my_trace_level=0

dom1 = { "name" : "DOM1",
        "basedn" : "ou=People,dc=dom1,dc=example,dc=com",
        "uri": "ldaps://ldap.dom1.example.com", }
dom2 { "name" : "DOM2",
        "basedn" : "ou=People,dc=dom2,dc=example,dc=com",
        "uri": "ldaps://ldap.dom2.example.com", }

#grace = datetime.timedelta(days=0)
#grace = datetime.timedelta(days=365)
#grace = datetime.timedelta(days=548) # 365*1.5=547.5
grace = datetime.timedelta(days=730) # 365*2=730

### interface functions

def ldapAuthorize(user, password):
  return True

def ldapAuthenticate(user, password):
  if ldapBind(user, password, dom1):
    return True
  if ldapBind(user, password, dom2):
    return True
  return False

### test functions

def execBinddom1(user, password):
  try:
    if os.system("/etc/freeradius/3.0/mods-config/python3/execBinddom1.sh '" + user + "' '" + password + "'") == 0:
      return True
  except:
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/execBinddom1:" + user + "@" + "DOM1") # CHECKME DOM1
  return False

### utility functions
    
def checkExpired(l, user, password, domain):
  try:
    b = getPwdChangedTime(ldapSearch(user, domain,["pwdChangedTime"]))[0]
    t = b.decode("utf-8")
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/checkExpired:" + user + "@" + domain["name"] + ":==:" + t)
    dt = datetime.datetime.strptime(t, '%Y%m%d%H%M%SZ')
    now = datetime.datetime.utcnow()
    if dt + grace > now:
      if execBinddom1(user, password):
        return True
    return False
  except ldap.LDAPError as e:
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/checkExpired:" + user + "@" + domain["name"] + ":" + str(e) + ":" + t)
  else:
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/checkExpired:" + user + "@" + domain["name"] + ":" + "unknow error" + ":" + t)
  return False

def ldapBind(user, password, domain):
  checkExpiredP = False
  try:
    control = [ ldap.controls.LDAPControl('1.3.6.1.4.1.42.2.27.8.5.1', True, None) ]
    l = ldap.initialize(domain["uri"], trace_level=my_trace_level)
    l.protocol_version = ldap.VERSION3
    l.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    userdn = "uid=" + user + "," + domain["basedn"]
    r = l.simple_bind_s(userdn, password, control, None)
    return True
  except ldap.INVALID_CREDENTIALS as e:
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/ldapBind:invalid credential:" + user + "@" + domain["name"])
    checkExpiredP = True
  except Exception as e:
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/ldapBind:" + str(e) + ":" + user + "@" + domain["name"])
  else:
    pass
  if checkExpiredP:
    if checkExpired(l,user,password,domain):
      return True
  return False

def ldapSearch(user, domain, attrs=None):
  try:
    l = ldap.initialize(domain["uri"], trace_level=my_trace_level)
    l.protocol_version = ldap.VERSION3
    l.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    r = l.search_s(domain["basedn"], ldap.SCOPE_ONELEVEL, filterstr="uid=" + user, attrlist=attrs)
    return r
  except ldap.LDAPError as e:
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/ldapSearch:" + user + "@" + domain["name"])
    return False
  else:
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/ldapSearch:" + "unknown error" + user + "@" + domain["name"])
    return False

def selectAttribute(r,name):
  try:
    return r[0][1][name]
  except ldap.LDAPError as e:
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/selectAttribute:" + "unknown ldap error" + name)
  else:
    radiusd.radlog(radiusd.L_ERR, "python3/ldap/selectAttribute:" + "cannot get " + name)
  return None

def getPwdChangedTime(r):
  return selectAttribute(r, "pwdChangedTime")
