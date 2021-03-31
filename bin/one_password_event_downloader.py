#!/usr/bin/env python3

"""
1password_event_downloader - Script to download events using the 1password CLI

script flow:
    + login to the 1password environment
    + get a session token
    + use the session token to invoke the CLI
    + output the events in JSON format
    + persists the data locally or publish to a Sumo Endpoint

note: events can be pulled down 100 events at a time
"""

import os
import sys
import json
import datetime
import logging
import argparse
import configparser
import pexpect
import dateutil.parser
import requests

logging.basicConfig(level=logging.INFO)

PARSER = argparse.ArgumentParser(description="""
Collect events and other items from the 1Password vault
""")

PARSER.add_argument("-b", metavar='<domain>', dest='DOMAIN', \
                    help="set domain")

PARSER.add_argument("-p", metavar='<passwd>', dest='PASSWD', \
                    help="set passphrase")

PARSER.add_argument("-a", metavar='<apikey>', dest='APIKEY', \
                    help="set apikey")

PARSER.add_argument("-m", metavar='<email>', dest='EMAILS', \
                    help="set email")

PARSER.add_argument("-c", metavar='<cfgfile>', dest='CFGFILE', \
                    help="use config file")

PARSER.add_argument("-o", metavar='<older>', dest='OLDER', \
                    help="set limit to collect in days")

PARSER.add_argument("-s", metavar='<source>', dest='SOURCE', \
                    help="specify Sumo Source to publish data to")

PARSER.add_argument("-d", metavar='<cached>', dest='CACHED', \
                    help="set cache directory")

PARSER.add_argument("-v", type=int, default=0, metavar='<verbose>', \
                    dest='VERBOSE', help="increase verbosity")

ARGS = PARSER.parse_args()

DOMAIN = 'UNSET'
PASSWD = 'UNSET'
APIKEY = 'UNSET'
EMAILS = 'UNSET'
SOURCE = 'UNSET'
CACHED = '/var/tmp/1password'

os.environ['OLDER']  = '1'

CMDSEP = ' '

if ARGS.CFGFILE:

    CFGFILE = os.path.abspath(ARGS.CFGFILE)
    CONFIG = configparser.ConfigParser()
    CONFIG.optionxform = str
    CONFIG.read(CFGFILE)
    if ARGS.VERBOSE > 9:
        print(dict(CONFIG.items('Default')))

    if CONFIG.has_option("Default", "DOMAIN"):
        DOMAIN = CONFIG.get("Default", "DOMAIN")
        os.environ['DOMAIN'] = DOMAIN

    if CONFIG.has_option("Default", "PASSWD"):
        PASSWD = CONFIG.get("Default", "PASSWD")
        os.environ['PASSWD'] = PASSWD

    if CONFIG.has_option("Default", "APIKEY"):
        APIKEY = CONFIG.get("Default", "APIKEY")
        os.environ['APIKEY'] = APIKEY

    if CONFIG.has_option("Default", "EMAILS"):
        EMAILS = CONFIG.get("Default", "EMAILS")
        os.environ['EMAILS'] = EMAILS

    if CONFIG.has_option("Default", "OLDER"):
        os.environ['OLDER'] = CONFIG.get("Default", "OLDER")

    if CONFIG.has_option("Default", "SOURCE"):
        SOURCE = CONFIG.get("Default", "SOURCE")
        os.environ['SOURCE'] = SOURCE

    if CONFIG.has_option("Default", "CACHED"):
        CACHED = CONFIG.get("Default", "CACHED")
        os.environ['CACHED'] = CACHED

    if ARGS.DOMAIN:
        os.environ['DOMAIN'] = ARGS.DOMAIN

    if ARGS.PASSWD:
        os.environ['PASSWD'] = ARGS.PASSWD

    if ARGS.APIKEY:
        os.environ['APIKEY'] = ARGS.APIKEY

    if ARGS.EMAILS:
        os.environ['EMAILS'] = ARGS.EMAILS

    if ARGS.OLDER:
        os.environ['OLDER'] = ARGS.OLDER

    if ARGS.SOURCE:
        os.environ['SOURCE'] = ARGS.SOURCE

    if ARGS.CACHED:
        os.environ['CACHED'] = ARGS.CACHED
try:
    OPS_APIKEY = os.environ['APIKEY']
    OPS_EMAILS = os.environ['EMAILS']
    OPS_PASSWD = os.environ['PASSWD']
    OPS_DOMAIN = os.environ['DOMAIN']
except KeyError as myerror:
    print('Environment Variable Not Set :: {} '.format(myerror.args[0]))

if ARGS.VERBOSE > 7:
    print('Domain: {}'.format(os.environ['DOMAIN']))
    print('Passwd: {}'.format(os.environ['PASSWD']))
    print('ApiKey: {}'.format(os.environ['APIKEY']))
    print('Emails: {}'.format(os.environ['EMAILS']))
    print('Source: {}'.format(os.environ['SOURCE']))
    print('CacheD: {}'.format(os.environ['CACHED']))
    print('Older_: {}'.format(os.environ['OLDER']))

LOGDIR = os.path.join(CACHED, 'log')
VARDIR = os.path.join(CACHED, 'var')
CFGDIR = os.path.join(CACHED, 'etc')
CACHEDIR = os.path.join(VARDIR, 'cache')
MANIFEST = os.path.join(LOGDIR, 'manifest.log')

if ARGS.VERBOSE > 5:
    print('LogDir: {}'.format(LOGDIR))
    print('VarDir: {}'.format(VARDIR))
    print('CfgDir: {}'.format(CFGDIR))
    print('Events: {}'.format(CACHEDIR))
    print('Manifest: {}'.format(MANIFEST))

TODAYDATE = datetime.date.today().strftime('%Y%m%d')

def setup_directories():
    """
    Create directories if they do not already exist
    """
    for targetdir in ( CACHED, VARDIR, LOGDIR, CFGDIR, CACHEDIR):
        os.makedirs(targetdir, exist_ok=True)

def setup_commands():
    """
    Bootstrap the PATH to have /usr/local/bin, where the op command should be
    """
    os.environ["PATH"] += os.pathsep + '/usr/local/bin'
    basecmd = 'op'
    cmdpath = pexpect.which(basecmd)
    return cmdpath

def signin_to_vault():
    """
    Sign into the vault using the op login command. Note we are setting an ops session name
    """
    siginlist = [ opcmd, 'signin', DOMAIN, EMAILS, APIKEY, '-r', '--shorthand', 'eventlist']
    signincmd = CMDSEP.join(siginlist)

    oplogin = pexpect.spawn(signincmd, encoding='utf-8')
    oplogin.expect(r'.*:')
    oplogin.sendline(PASSWD)

    optoken = oplogin.read().strip()

    sessiontag = 'OP_SESSION_eventlist'
    os.environ[sessiontag] = optoken

def list_vault_events(lasttoken):
    """
    This lists the events of the vault using the op cmd line
    """
    if lasttoken == 'UNSET':
        eventlist = [ opcmd, 'list', 'events']
    else:
        eventlist = [ opcmd, 'list', 'events', '--older', '--eventid', lasttoken ]

    eventscmd = CMDSEP.join(eventlist)
    eventsout = pexpect.spawn(eventscmd, encoding='utf-8')

    eventsjson = eventsout.read().strip()
    myjsonarray = (json.loads(eventsjson))

    finalevent=lasttoken

    finalevent = enrich_and_publish_events(myjsonarray)
    return finalevent

def enrich_and_publish_events(jsonarray):
    """
    This looks up uuid in the users list and publishes
    Publishing the events could be to a file or a source
    This will also publish the results into a manifest file
    """

    session = requests.Session()

    for jsonobject in jsonarray:
        eventid = jsonobject['eid']
        jsondate = jsonobject['time']
        eventdate = dateutil.parser.parse(jsondate)
        bucket = eventdate.strftime('%Y%m%d')
        datedelta = int(TODAYDATE) - int(bucket)
        if datedelta >= int(os.environ['OLDER']):
            if ARGS.VERBOSE > 5:
                print('{} - {} = {}'.format(TODAYDATE, bucket, datedelta))
            sys.exit()
        bucket_dir = os.path.join(CACHEDIR, bucket)
        os.makedirs(bucket_dir, exist_ok=True)
        targetjsonfile = os.path.join(bucket_dir, str(eventid) + '.json' )

        with open(targetjsonfile, 'w', encoding="utf-8", newline='\n' ) as jsonfile:
            json.dump(jsonobject, jsonfile, indent=4, sort_keys=True, ensure_ascii=True)
        jsonfile.close()

        publish_mapitem(targetjsonfile,session,SOURCE)

        if eventid:
            finalevent = str(eventid)

    return finalevent

def publish_mapitem(localfile, session, url):
    """
    This is the wrapper for publishing to SumoLogic source
    """
    if ARGS.VERBOSE > 3:
        print('LOCALFILE: ' + localfile)
        print('SUMOLOGIC: ' + url)

    with open(localfile, encoding='utf-8' ) as srcfile:
        payload = json.load(srcfile)
        headers = {'Content-Type':'application/json'}
        response = session.post(url, data=json.dumps(payload), headers=headers).status_code
        if ARGS.VERBOSE > 5:
            print('RESPONSE: ' + str(response))

def signout_to_vault():
    """
    This signs out of the vault. This is necessary.
    """
    oplogoutlist = [ opcmd, 'signout', '--account', 'eventlist', '--forget' ]
    oplogoutcmd = CMDSEP.join(oplogoutlist)
    _oplogout = pexpect.run(oplogoutcmd, encoding='utf-8')

setup_directories()
opcmd = setup_commands()
signin_to_vault()
LAST_EVENT = list_vault_events('UNSET')
while LAST_EVENT != 'UNSET':
    signin_to_vault()
    LAST_EVENT = list_vault_events(LAST_EVENT)
    if ARGS.VERBOSE > 5:
        print('Lastevent: {}'.format(LAST_EVENT))
signout_to_vault()
