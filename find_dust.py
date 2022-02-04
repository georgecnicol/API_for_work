# use an unpublished endpoints for a web based app to perform a depth first traversal of a graph
# starting at a particular wallet address. Stopping conditions are depth met or something interesting found
# in this instance we started with an address that made a dusting attack on our wallet, and we want to
# map backwards from that attack wallet looking at wallets that made deposits.
# In this scenario we don't care about outbound transacitons, we want to find who is funding the attacks.
# ... or at least trace funds back to something of interest.
# the reason for doing so is to automate the manual search in the UI for things that are interesting.
# This automation could easily save 100 clicks for the end user

import requests, argparse
import time # rate limiting

######## vars #####################
wallet_address = ''
coin = ''
auth = ''
false = 'false'
date_min = '2021-01-01T00:00:00.000Z'
date_max = '2022-01-08T00:00:00.000Z'
viewed_addresses = set()
headers = {"Content-Type": "application/json"}


######## api endpoints used ###########
screen_url = "https://xxx.com/api/xxx/v1/xxx/addresses"
# payload = [{"address": "xxx", "chain": "xxx"}]
# payload = [{"address": x, "chain": args.coin[0]} for x in wallet_address]
transaction_url = "https://xxx.com/api/xxx/v3/xxx/address"


######### parse args #######
parser = argparse.ArgumentParser()
parser.set_defaults(cred_path = './creds.txt')
parser.add_argument('-c', dest = 'coin', nargs = 1, required = True, help = "coin, eg: bitcoin, stellar")
parser.add_argument('-d', dest = 'depth', nargs = 1, required = True, type = int, choices = range(1,5) , help = "depth first traversal max depth")
group = parser.add_mutually_exclusive_group(required = True)
group.add_argument('-a', dest = 'address',  help = "Either an address or a file containing multiple addresses")
group.add_argument('-f', dest = 'file_path', help = "But not both. Addresses must all be of same asset type")

args = parser.parse_args()


######## handle auth ##############
with open(args.cred_path, 'r') as fh:
  creds = fh.read()
  creds = creds.split(',')
  auth = (creds[0],creds[1])


######## set the coin chain ##############
coin = args.coin[0]


######## set the depth ##############
depth = args.depth[0]


######## get the address(es) #############
if args.address:
  wallet_address = [args.address]
else:
  with open(args.file_path, 'r') as fh:
    wallet_address = fh.read().strip()
    wallet_address = wallet_address.split('\n')


def screen_address(address):
  time.sleep(1)
  payload = [{"address": address, "chain": coin}]
  response = requests.post(screen_url, json=payload, headers=headers, auth=auth)
  screen_result = ''
  for result in response.json():
    if len(result['xxx']) > 0 or len(result['xxx']) > 0:  # redacted
      screen_result = f'endpoint:\n'
      if len(result['xxx']) > 0:
        screen_result += f"{result['address']}  Risk: "
        for indicator in result['xxx']:
          screen_result += f"{indicator['xxx']} risk of {indicator['xxx']} due to/ from {indicator['xxx']}.\n"

      if len(result['xxx']) > 0:
        screen_result += f"{result['address']} Entities: "
        for entity in result['xxx']:
          screen_result += f"{entity['xxx']} risk of {entity['xxx']} due to/from {entity['xxx']}.\n"

  return screen_result


def get_transactions(address):
  time.sleep(1) # rate limit
  next_set = set()
  payload2 = {"address": {"address": address, "chain": coin}, "limit":25,"offset":0, "fromDate":date_min,"tillDate":date_max}
  response2 = requests.post(transaction_url, json=payload2, headers=headers, auth=auth)
  for transaction in response2.json()['data']['xxx']:
    next_set.add(f"{transaction['from']['address']}")
  return next_set

# screen results are a stop condition
def addr_recurse(depth, addr_set):
  result = ''
  count = 0

  for addr in addr_set:
    count += 1
    if count % 3 == 0:  #rate limit
      time.sleep(1)
    if addr not in viewed_addresses:  # first check to see if going in circles
      viewed_addresses.add(addr)
      intermediate_result = screen_address(addr)
      if intermediate_result != '':   #we have a stopping condition
        result += intermediate_result
      elif depth < 1:  # we are at max depth so we are done
        result += intermediate_result
      else: # ok, now you can do recursive things
        intermediate_result = addr_recurse(depth-1, (get_transactions(addr)))
        if intermediate_result != '':
          result += addr + ' --> ' + intermediate_result

  return result

if __name__ == '__main__':
  print(addr_recurse(depth, wallet_address))
  print(f'Total number of unqiue addresses scanned: {len(viewed_addresses)}')
