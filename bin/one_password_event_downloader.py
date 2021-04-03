#!/usr/bin/env python3

"""
1password_event_downloader - Script to download events using the 1password CLI

Software Process:

    + login to the 1password environment
    + get a session token
    + use the session token to invoke the CLI
    + output the events in JSON format
    + enriches the JSON output to resolve users and objects
    + persists the data locally
    + optionally publishes to a HTTPS web endpoint

Caveat:
    + Events can only be pulled down 100 events at a time
    + Older events need to be retrieved by specifying a specific Event ID (eid)
    + Session has to be set as an environment variable

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

PARSER.add_argument("-s", metavar='<secret>', dest='SECRET', \
                    help="set secret")

PARSER.add_argument("-m", metavar='<email>', dest='EMAILS', \
                    help="set email")

PARSER.add_argument("-c", metavar='<cfgfile>', dest='CFGFILE', \
                    help="use config file")

PARSER.add_argument("-o", metavar='<older>', dest='OLDER', \
                    help="set limit to collect in days")

PARSER.add_argument("-u", metavar='<srcurl>', dest='SRCURL', \
                    help="specify Sumo Source Data Target URL")

PARSER.add_argument("-d", metavar='<cached>', dest='CACHED', \
                    help="set cache directory")

PARSER.add_argument("-v", type=int, default=0, metavar='<verbose>', \
                    dest='VERBOSE', help="increase verbosity")

PARSER.add_argument("-i", "--initialize", action='store_true', default=False, \
                    dest='INITIALIZE', help="initialize config file")

PARSER.add_argument("-r", "--remove", action='store_true', default=False, \
                    dest='REMOVE', help="remove event files after publishing")

ARGS = PARSER.parse_args()

DOMAIN = 'UNSET'
PASSWD = 'UNSET'
SECRET = 'UNSET'
EMAILS = 'UNSET'
SRCURL = 'UNSET'
CACHED = '/var/tmp/1password'

os.environ['OLDER']  = '1'
os.environ['TOTALEVENTS']  = '0'

CMDSEP = ' '

def initialize_config_file():
    """
    Initialize configuration file, write output, and then exit
    """

    my_config='/var/tmp/one_password_event_downloader.initial.cfg'
    config = configparser.RawConfigParser()
    config.optionxform = str

    config.add_section('Default')

    domain_input = input ("Please enter your Domain: \n")
    config.set('Default', 'DOMAIN', domain_input )

    emails_input = input ("Please enter your Email Address: \n")
    config.set('Default', 'EMAILS', emails_input )

    apikey_input = input ("Please enter your Secret: \n")
    config.set('Default', 'SECRET', apikey_input )

    passwd_input = input ("Please enter your Pass Phrase: \n")
    config.set('Default', 'PASSWD', passwd_input )

    cached_input = input ("Please enter your desired Cache Directory: \n")
    config.set('Default', 'CACHED', cached_input )

    source_input = input ("Please enter the URL of the Sumologic Source: \n")
    config.set('Default', 'SRCURL', source_input )

    older_input = 3
    config.set('Default', 'OLDER', older_input )

    with open(my_config, 'w') as configfile:
        config.write(configfile)
    print('Complete! Written: {}'.format(my_config))
    sys.exit()

if ARGS.INITIALIZE:
    initialize_config_file()

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

    if CONFIG.has_option("Default", "SECRET"):
        SECRET = CONFIG.get("Default", "SECRET")
        os.environ['SECRET'] = SECRET

    if CONFIG.has_option("Default", "EMAILS"):
        EMAILS = CONFIG.get("Default", "EMAILS")
        os.environ['EMAILS'] = EMAILS

    if CONFIG.has_option("Default", "OLDER"):
        os.environ['OLDER'] = CONFIG.get("Default", "OLDER")

    if CONFIG.has_option("Default", "SRCURL"):
        SRCURL = CONFIG.get("Default", "SRCURL")
        os.environ['SRCURL'] = SRCURL

    if CONFIG.has_option("Default", "CACHED"):
        CACHED = CONFIG.get("Default", "CACHED")
        os.environ['CACHED'] = CACHED

    if ARGS.DOMAIN:
        os.environ['DOMAIN'] = ARGS.DOMAIN

    if ARGS.PASSWD:
        os.environ['PASSWD'] = ARGS.PASSWD

    if ARGS.SECRET:
        os.environ['SECRET'] = ARGS.SECRET

    if ARGS.EMAILS:
        os.environ['EMAILS'] = ARGS.EMAILS

    if ARGS.OLDER:
        os.environ['OLDER'] = ARGS.OLDER

    if ARGS.SRCURL:
        os.environ['SRCURL'] = ARGS.SRCURL

    if ARGS.CACHED:
        os.environ['CACHED'] = ARGS.CACHED
try:
    OPS_SECRET = os.environ['SECRET']
    OPS_EMAILS = os.environ['EMAILS']
    OPS_PASSWD = os.environ['PASSWD']
    OPS_DOMAIN = os.environ['DOMAIN']
except KeyError as myerror:
    print('Environment Variable Not Set :: {} '.format(myerror.args[0]))

if ARGS.VERBOSE > 7:
    print('Domain: {}'.format(os.environ['DOMAIN']))
    print('Passwd: {}'.format(os.environ['PASSWD']))
    print('ApiKey: {}'.format(os.environ['SECRET']))
    print('Emails: {}'.format(os.environ['EMAILS']))
    print('Source: {}'.format(os.environ['SRCURL']))
    print('CacheD: {}'.format(os.environ['CACHED']))
    print('Older_: {}'.format(os.environ['OLDER']))

TODAYDATE = datetime.date.today().strftime('%Y%m%d')

LOGDIR = os.path.join(CACHED, 'log')
VARDIR = os.path.join(CACHED, 'var')
CFGDIR = os.path.join(CACHED, 'etc')
CACHEDIR = os.path.join(VARDIR, 'cache')
MANIFEST = os.path.join(LOGDIR, '1password' + '.' + TODAYDATE + '.' + 'manifest.log')

USERDICT = dict()

if ARGS.VERBOSE > 5:
    print('LogDir: {}'.format(LOGDIR))
    print('VarDir: {}'.format(VARDIR))
    print('CfgDir: {}'.format(CFGDIR))
    print('Events: {}'.format(CACHEDIR))
    print('Manifest: {}'.format(MANIFEST))

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
    siginlist = [ opcmd, 'signin', DOMAIN, EMAILS, SECRET, '-r', '--shorthand', 'eventlist']
    signincmd = CMDSEP.join(siginlist)

    oplogin = pexpect.spawn(signincmd, encoding='utf-8')
    oplogin.expect(r'.*:')
    oplogin.sendline(PASSWD)

    optoken = oplogin.read().strip()

    sessiontag = 'OP_SESSION_eventlist'
    os.environ[sessiontag] = optoken

def populate_user_dict():
    """
    This collects the reference data for users
    """
    userlist = [ opcmd, 'list', 'users']
    userscmd = CMDSEP.join(userlist)
    usersout = pexpect.spawn(userscmd, encoding='utf-8')

    usersjson = usersout.read().strip()
    usersjsonarray = (json.loads(usersjson))
    for userjsonobject in usersjsonarray:
        user_name = userjsonobject['name']
        user_uuid = userjsonobject['uuid']
        user_mail = userjsonobject['email']
        USERDICT[user_uuid] = dict()
        USERDICT[user_uuid]['user_mail'] = user_mail
        USERDICT[user_uuid]['user_name'] = user_name

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

def build_bucket_dir(jsondate):
    """
    Calculate the bucket directory to write the JSON files
    """

    bucket = ( dateutil.parser.parse(jsondate)).strftime('%Y%m%d')
    bucket_dir = os.path.join(CACHEDIR, bucket)

    os.makedirs(bucket_dir, exist_ok=True)
    nowevent = (datetime.datetime.strptime(str(TODAYDATE),'%Y%m%d'))
    oldevent = (datetime.datetime.strptime(str(bucket),'%Y%m%d'))
    datediff = int ( ( nowevent - oldevent ).total_seconds() / 3600 / 24 )

    if ARGS.VERBOSE > 8:
        print('DAYS: {}'.format(datediff))

    return bucket, bucket_dir, datediff

def enrich_and_publish_events(jsonarray):
    """
    This looks up uuid in the users list and publishes
    Publishing the events could be to a file or a source
    This will also publish the results into a manifest file
    """

    session = requests.Session()
    manifestobject = open(MANIFEST, 'a')

    for jsonobject in jsonarray:
        eventid = jsonobject['eid']
        jsondate = jsonobject['time']
        actoruid = jsonobject['actorUuid']
        if actoruid in USERDICT:
            jsonobject['user_name'] = USERDICT[actoruid]['user_name']
            jsonobject['user_mail'] = USERDICT[actoruid]['user_mail']
        else:
            jsonobject['user_name'] = 'unresolved_name'
            jsonobject['user_mail'] = 'unresolved_mail'

        bucket, bucket_dir, datediff = build_bucket_dir(jsondate)

        targetjsonfile = os.path.join(bucket_dir, str(eventid) + '.json' )
        with open(targetjsonfile, 'w', encoding="utf-8", newline='\n' ) as jsonfile:
            json.dump(jsonobject, jsonfile, indent=4, sort_keys=True, ensure_ascii=True)
        jsonfile.close()

        manifestobject.write('{0},{1},{2},{3}\n'.format(TODAYDATE,bucket,eventid,targetjsonfile))

        if SRCURL != 'UNSET':
            publish_mapitem(targetjsonfile,session,SRCURL)

        totalevents = int(os.environ['TOTALEVENTS'])
        totalevents = totalevents + 1
        os.environ['TOTALEVENTS'] = str(totalevents)

        if datediff > int(os.environ['OLDER']):
            if ARGS.VERBOSE > 5:
                print('CollectionResults - TodayDate: {}'.format(TODAYDATE))
                print('CollectionResults - EventDate: {}'.format(bucket))
                print('CollectionResults - DateDelta: {}'.format(datediff))
                print('CollectionResults - AllEvents: {}'.format(os.environ['TOTALEVENTS']))
            sys.exit()

        if eventid:
            finalevent = str(eventid)

    manifestobject.close()
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
        if response == 200 and ARGS.REMOVE:
            os.remove(localfile)

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
populate_user_dict()
LAST_EVENT = list_vault_events('UNSET')
while LAST_EVENT != 'UNSET':
    signin_to_vault()
    LAST_EVENT = list_vault_events(LAST_EVENT)
    if ARGS.VERBOSE > 5:
        print('LastEvent: {}'.format(LAST_EVENT))
signout_to_vault()
