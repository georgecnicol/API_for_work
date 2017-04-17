# George Nicol
# python 2.7
# license: GNU GPLv3
# April 2017
# Notes:
#
# This script vcan be used in conjunction with ioc_feed_fetch
# or any of the IOC_xxx_fetch scripts, provided their output is truncated to just IOCs.
#
#
# To update a given IOC we need to know the associated intelligence ID of the IOC because that is what we reference
# using API v2. This script reads a file containing the value of the IOC, one IOC per line
# for example:
# 1.2.3.4
# http://a.b.com/php.exe
# foobarbaz.org
#
# the ids for each IOC in question are acquired and then an attempt is made to set the status to 'active'
# and set the 'expiration_ts' to some date based on user input.
# the date is computed based on number of days entered by user, default is 90.
#
# Notes about using patch to edit IOCs that have been added:
# valid JSON object is used and here are all the relevant variables
# -- id is the only required kv pair ---
#
# { 'id': id_of_ioc,
#   'status' : 'active/inactive',
#   'severity' : 'low/medium/high/very-high',
#   'itype': see Appendix A in Optic API reference guide,
#   'expiration_ts' : 'YYYY-MM-DDT00:00:00.000Z'
#   'confidence' : 0-100 }
#
# NOTE: order of kv pairs matters and it will fail if expiration_ts, comes prior to status. Yes, that is weird.
#
# In this script only status and expiration_ts are used (and they must be used in conjunction if setting
# status to 'active' and the expiration_ts has already passed.
#
# TODO check out the additional options on the edit page for a deeper understanding/ documentation
#
# When an IOC has multiple entries (yielding multiple IDs) only the ids that you have permission to change
# will be changed. If you have an id that you can change and it is already active, it will be updated to active again



import argparse
import json
import requests
import sys
import copy
import datetime

# ---------------------------------------------------------------------
# some constants

API_URL = "https://api.threatstream.com/api/v2/intelligence/"
HTTP_ACCEPT = [200,201,202]
API_AUTH = {
    "username"  : "",
    "api_key"   : ""
    }

EXPIRE_DATE = ''    # date IOC should be active until


# ---------------------------------------------------------------------
# parse dem args

parser = argparse.ArgumentParser(description="update IOC via API")

auth_group = parser.add_mutually_exclusive_group(required=True)
auth_group.add_argument("-c", dest = "creds", action = "store", nargs = 2, help = "username apikey")
auth_group.add_argument("-x", action = "store_true", help = "use YOURCOMANY.conf")
parser.add_argument("-d", dest = "days", action ="store", nargs = 1, type = int, help = "Days until expires, 90 is default, -1 is never.")
parser.add_argument("-f", dest = "file_name", action = "store", nargs = 1, required = True, help = "path/to/data")

args, unknown = parser.parse_known_args()


# ---------------------------------------------------------------------
# set up auth params

if args.x == True:
  try:
    with open('YOURCOMANY.conf') as fH:
      conf = fH.read()
    conf = conf.split()
    API_AUTH['username'] = conf[0].strip()
    API_AUTH['api_key'] = conf[1].strip()
  except:
    print("[!] Problem with YOURCOMPANY.conf file.")
    sys.exit()
else:
  API_AUTH['username'] = args.creds[0]
  API_AUTH['api_key'] = args.creds[1]


# ---------------------------------------------------------------------
# set up date params. if no date provided, add 90 days to current date
# for a "-1" set to never expire, for all other set accordingly
# include some minor error checking. Note the format required

if args.days == None:
  EXPIRE_DATE = (datetime.date.today() + datetime.timedelta(days=90)).strftime('%Y-%m-%d') + "T00:00:00.000Z"
elif args.days[0] == -1:
  EXPIRE_DATE = "9999-12-31T00:00:00.000Z"
elif args.days[0] < 1:
  print("[!] Invalid number of days. -1 is only acceptable non-positive number. All other numbers must be greater than 0")
  sys.exit()
else:
  EXPIRE_DATE = (datetime.date.today() + datetime.timedelta(days=args.days[0])).strftime('%Y-%m-%d') + "T00:00:00.000Z"


# ---------------------------------------------------------------------
# An IOC value has an "id" associated with it as multiple IOCs of the same value can exist in the platform -
# consider the case where two orgs or a premium feed import the same IOC ...
# So we need to get a list of those ids for a given IOC because ultimately the change
# made references the id, not the IOC value itself

def get_ids(ioc_value):

  params = copy.deepcopy(API_AUTH)
  params['value'] = ioc_value.strip()
  id_list=[]                        # list of IDs for the ioc. recall, update goes against ID, not IOC value
                                    # and an IOC value can have multiple entries (private, public, etc)

  response = requests.get(API_URL, params = params)
  if response.status_code not in HTTP_ACCEPT:
    print("[!] http status: {} for ioc: {}".format(response.status_code, ioc_value))
  elif response.text is not None:
    result=response.text.encode("utf-8")
    result=json.loads(str(result))
    # process the json object to obtain any IDs
    if len(result['objects']) > 0:
      for item in result['objects']:
        id_list.append(item['id'])
    else:
      pass
      # print("[!] No data for {}".format(ioc_value))
  else:
    pass
    # print("[!] None result at {}". format(ioc_value))
  return id_list


# ---------------------------------------------------------------------
# given a list of ID for intel, we attempt to set the status to active and the date of expiration
# to the date provided from the date given on the commmand line.
# there may be a list of ids, and likely only one (or none) of them can be edited. We don't want to track
# all the fails that should fail, just the ones were the whole list fails.
# this is the purpose of the count and entries variables

def update_active(id_list, ioc_value):
  fail_count = 0
  list_len = len(id_list)
  api_params = copy.deepcopy(API_AUTH)
  for id_num in id_list:
    payload ={}
    payload["status"] = "active"
    payload["expiration_ts"] = EXPIRE_DATE
    payload["id"] = str(id_num)
    api_url = API_URL  + str(id_num) + '/'
    result = requests.patch(api_url, params = api_params, data=json.dumps(payload), headers = { 'Content-Type' : 'application/json' })
    if result.status_code not in HTTP_ACCEPT:
      fail_count += 1
  if fail_count == list_len:
    print("[!] Failed to update IOC {}.".format(ioc_value.strip()))
  else:
    print("[*] Updated IOC {} to active status with expiration of {}.".format(ioc_value.strip(), EXPIRE_DATE))



# --------------------------------------------------------------------
# main

if __name__ == "__main__":
  with open(args.file_name[0]) as fH:
    for line in fH:
      update_active(get_ids(line), line)
