from utils import configfile
import requests
from elasticsearch import Elasticsearch, logger
from time import sleep
import json
from utils.helpers import *
from pprint import pprint

if configfile.deployment_type == "cloud":
  es = Elasticsearch(
      cloud_id = configfile.cloud_id,
      http_auth=(configfile.http_auth_user, configfile.http_auth_pass))
  kibana_url = configfile.kibana_host
elif configfile.deployment_type == "onprem":
  es = Elasticsearch(
    [configfile.elasticsearch_onprem],api_key=(configfile.api_base64), verify_certs=False
  )
  kibana_url = configfile.kibana_onprem

logger.setLevel(logging.WARNING)

execution_time = 0

def get_abilities(paw, logger):
  try:
    pass_agent = {
        "paw": paw
    }
    req_headers = {
        'KEY': configfile.CALDERA_API_KEY
    }
    response = requests.post(configfile.CALDERA_ACCESS_URL, headers=req_headers, json=pass_agent).json()
    dict_abilities = dict()
    num = 0
    for item in response:
      dict_abilities[num] = {}
      dict_abilities[num]['Name'] = item["name"]
      dict_abilities[num]['id'] = item["ability_id"]
      try:
        dict_abilities[num]['rules'] = item['additional_info']['rules']
      except:
        pass
      num += 1
    return dict_abilities
  except requests.exceptions.ConnectionError:
    logger.error("Failed to connect to the Caldera Server. Exiting...")
    exit()

def execute_ability(paw, ability_id, logger, ability_args=None):
  # default JSON format for basic abilities that do not require any arguments to be passed
  temp = {
      "paw": paw,
      "ability_id": ability_id,
      "obfuscator": "plain-text"
  }
  if ability_args is not None:
    # default JSON format for advanced abilities that require arguments to be passed
    logger.info('Passing ability_args to caldera:')
    pprint(ability_args)
    temp = {
      "paw": paw,
      "ability_id": ability_id,
      "obfuscator": "plain-text",
      "facts": ability_args
    }
  execute_json = temp
  req_headers = {
    'KEY': configfile.CALDERA_API_KEY
  }
  response = requests.post(configfile.CALDERA_ACCESS_XPL_URL, headers=req_headers, json=execute_json).json()
  if response == 'complete':
    logger.info("Agent {} Tasked with the ability_id {}".format(paw, ability_id))
  return response
  
def check_on_caldera(ids, ability_pool, sigmafolder):
  ready_to_use = {}
  num = 0
  for i in range(0,len(ability_pool)):
    if ability_pool[i]['id'] in ids and 'rules' in ability_pool[i].keys():
      ready_to_use[num] = {}
      ready_to_use[num]['Name'] = ability_pool[i]["Name"]
      ready_to_use[num]['id'] = ability_pool[i]["id"]
      ready_to_use[num]['rule'] = eval((ability_pool[i]["rules"]))
      for i in range(0, len(ready_to_use[num]['rule'])):
        ready_to_use[num]['rule'][i] = (set_get_correct_slash(sigmafolder) + set_get_correct_slash(ready_to_use[num]['rule'][i]))
      num += 1
  return ready_to_use

def check_single_on_caldera(id, ability_pool, logger):
  ret = False
  for i in range(0,len(ability_pool)):
    if id == ability_pool[i]['id']:
      ret = True
      logger.info('Ability ID: {} found in caldera'.format(id))
      break
  if ret == False:
    logger.warning('Ability ID: {} not found in caldera'.format(id))
  return ret
  

def get_detection_rules():
  page_num = 1
  num = 0
  retry = 0
  rulenamedict = dict()
  while(True):
    detection_engine = kibana_url + '/api/detection_engine/rules/_find?per_page=600&page={}'.format(page_num)
    response = requests.get(detection_engine, auth=(configfile.http_auth_user,configfile.http_auth_pass)).json()
    for item in response['data']:
        rulenamedict[num] = {}
        rulenamedict[num]['Name'] = item['name']
        rulenamedict[num]['RuleID'] = item['rule_id']
        num += 1
    # when last page or ids greater than the ones on last page
    if page_num * response.get('perPage') >= response.get('total'): break
    else: page_num += 1
  return rulenamedict

def elastic_get_exec_status(rule_id):
    detection_engine = kibana_url + '/api/detection_engine/rules?rule_id=' + rule_id
    response = requests.get(detection_engine, auth=(configfile.http_auth_user,configfile.http_auth_pass)).json()
    status = response['status']
    return status

def elastic_get_rule_status(rule_id):
    if rule_id == None: return
    detection_engine = kibana_url + '/api/detection_engine/rules?rule_id=' + rule_id
    response = requests.get(detection_engine, auth=(configfile.http_auth_user,configfile.http_auth_pass)).json()
    status = response['enabled']
    execstatus = response['status']
    return status, execstatus

def elastic_rule_health(enabled, execstatus, csv_output, alertname, abilityid):
  if enabled != True or execstatus != "succeeded":
    result = "Bad Rule Health"
    alertdata = "N/A"
    export_results(csv_output, alertname, alertdata, result, abilityid)
    return False
  else:
    return True

def check_if_exists_on_elastic(rulenamedict, rulenamed):
  for i in range(0,len(rulenamedict)):
    for rulename in rulenamed:
      if rulename in rulenamedict[i]["Name"]:
          return True

def get_elastic_alerts(rulenamedict, rule_lookup_time="5m"):
  rule_lookup_time_for_dict = "now-" + rule_lookup_time
  condition = { 
    "match": { 
      "signal.rule.name": rulenamedict if type(rulenamedict) == str else rulenamedict[0]
    }
  }
  query_body = {
    "query": {
      "bool": {
        "should": [
            condition
        ],
        "minimum_should_match" : 1,
        "filter": [
          {
            "range": {
              "@timestamp": {
                "gte": rule_lookup_time_for_dict
              }
            }
          }
        ]
      }
    },
    "fields": ["signal.rule.name","@timestamp"],
    "_source": "false",
    "sort": [
      {
        "@timestamp": {
          "order": "desc"
        }
      }
    ]
  }
  alerts = es.search(index=".siem-signals-default*", body=query_body, size=1000)
  hits = alerts["hits"]["total"]["value"]
  if hits > 1:
      alert_list = []
      for hit in range(hits):
          alert_name = alerts["hits"]["hits"][hit]["fields"]["signal.rule.name"]
          timestamp = alerts["hits"]["hits"][hit]["fields"]["@timestamp"]
          alert_list.append([alert_name,timestamp])
      return alert_list
  elif hits == 0:
      return None
  else:
      alert_name = alerts["hits"]["hits"][0]["fields"]["signal.rule.name"]
      timestamp = alerts["hits"]["hits"][0]["fields"]["@timestamp"]
      return [[alert_name,timestamp]]

def elastic_on_demand_exec(rule_id, logger):
  enable_data = json.dumps([{"rule_id":rule_id,"enabled":True}])
  disable_data = json.dumps([{"rule_id":rule_id,"enabled":False}])
  logger.debug("RuleID: " + rule_id)
  detection_engine = kibana_url + '/api/detection_engine/rules/_bulk_update'
  headers = {
      "kbn-xsrf": "true"
  }
  requests.patch(detection_engine, data=disable_data, headers=headers, auth=(configfile.http_auth_user,configfile.http_auth_pass))
  logger.info("On-demand rule execution in progress")
  requests.patch(detection_engine, data=enable_data, headers=headers, auth=(configfile.http_auth_user,configfile.http_auth_pass))
  return True

def callelastic(Interval, alert, rule_id, limit_time, abilityid, csvpath, rule_lookup_time, logger):
  logger.info("Querying Elastic for the Corresponding Alert")
  data = get_elastic_alerts(alert, rule_lookup_time=rule_lookup_time)
  global execution_time
  if isinstance(data, list):
    logger.info("Alert fired, Detection is working Properly!")
    logger.info("Alert Data: \n\tAlert Name: {}\n\tAlert Fired at: {}".format(data[0][0], data[0][1]))
    export_results(csvpath, alert, data, "Success", abilityid)
  else:
    if execution_time < limit_time:
      logger.info("No results found yet, gonna try again in {} secs".format(Interval))
      if elastic_get_exec_status(rule_id) == 'succeeded': elastic_on_demand_exec(rule_id, logger)
      sleep(Interval)
      execution_time += Interval
      callelastic(Interval, alert, rule_id, limit_time, abilityid, csvpath, rule_lookup_time, logger)
    else:
      logger.warning("No results found in the defined Limit time, Detection needs manual Review!")
      export_results(csvpath, alert, data, "Failed", abilityid)
      execution_time = 0

def batch_execution(abilities, ruleset, target, bypass_ability_execution, initial_sleep_time, sleep_interval, limit_time, csvpath, rule_lookup_time, logger):
  ability_num = len(abilities)
  for i in range(0, ability_num):
    abilityid = abilities[i]["id"]
    alertname = get_alert_name(abilities[i]["rule"])
    if alertname == None:
      continue
    rule_id = get_rule_id(ruleset, alertname)
    enabled, execstatus = elastic_get_rule_status(rule_id)
    if elastic_rule_health(enabled, execstatus, csvpath, alertname, abilityid) == False:
      logger.warning("The detection '{}' is disabled or having errors on execution. Skipping".format(alertname))
      continue
    if check_if_exists_on_elastic(ruleset, alertname):
      execute_ability(target, abilityid, logger)
      logger.info("Sleeping {} secs before calling elastic".format(initial_sleep_time))
      sleep(initial_sleep_time)
      callelastic(sleep_interval, alertname, rule_id, limit_time, abilityid, csvpath, rule_lookup_time, logger)
    else:
      logger.warning("Alert not found on Elastic")


def callelastic_for_parallel_batch_execution(Interval, alert, rule_id, limit_time, abilityid, csvpath, rule_lookup_time, logger):
  is_rule_triggered = False
  logger.info("Querying Elastic for the Alert {}".format(alert))
  data = get_elastic_alerts(alert, rule_lookup_time=rule_lookup_time)
  if isinstance(data, list):
    is_rule_triggered = True
    logger.info("Alert fired, Detection is working Properly!")
    logger.info("Alert Data: \n\tAlert Name: {}\n\tAlert Fired at: {}".format(data[0][0], data[0][1]))
    export_results(csvpath, alert, data, "Success", abilityid)
  else:
    if execution_time < limit_time:
      logger.warning("No results found yet, gonna try again in {} secs".format(Interval))
      if elastic_get_exec_status(rule_id) == 'succeeded': elastic_on_demand_exec(rule_id, logger)
    else:
      logger.warning("No results found in the defined Limit time, Detection needs manual Review!")
      export_results(csvpath, alert, data, "Failed", abilityid)
  return is_rule_triggered


def batch_execution_in_parallel(abilities, ruleset, target, bypass_ability_execution, initial_sleep_time, sleep_interval, limit_time, rule_lookup_time, ability_args_dict, csvpath, logger):
  global execution_time
  already_triggered_rule_idx = []
  all_abilities_status = {}
  execution_time = 0
  ability_num = len(abilities)
  # execute all abilities...
  for i in range(0, ability_num):
    abilityid = abilities[i]["id"]
    abilityname = abilities[i]["Name"]
    alertname = get_alert_name(abilities[i]["rule"])
    rule_id = get_rule_id(ruleset, alertname)
    enabled, execstatus = elastic_get_rule_status(rule_id)
    if elastic_rule_health(enabled, execstatus, csvpath, alertname, abilityid) == False:
      logger.warning("The detection '{}' is disabled or having errors on execution. Skipping".format(alertname))
      continue
    all_abilities_status[abilityid] = {
        'Ability': {
          'ID': abilityid, 'Name': abilityname
          },
        'Rule': {
          'ID': rule_id, 'Name': alertname, 'Success': 'No'
          }
        }
    if check_if_exists_on_elastic(ruleset, alertname):
      execute_ability(target, abilityid, logger, ability_args=ability_args_dict.get(abilityid))
      logger.info(f'Ability {i+1} (named: {abilityname}) out of {ability_num} executed...')
    else:
      logger.warning('Ability not found on caldera...')
      logger.warning(f'Ability {i+1} (named: {abilityname}) out of {ability_num} could not be executed...')
  sleep(initial_sleep_time)
  while(execution_time <= limit_time):
    for i in range(0, ability_num):
      if len(already_triggered_rule_idx) == ability_num:
        # if all abilities executions have already returned results, then "for" loop as well as "while" loop would be needed to be broken
        execution_time += limit_time
        break
      if i in already_triggered_rule_idx: 
        # if rule is already triggered, then skip rechecks of that
        logger.info('Corresponding alert rule {} for ability {} ({}) already executed & returned result...'.format(alertname, abilityid, abilityname))
        continue
      abilityid = abilities[i]["id"]
      abilityname = abilities[i]["Name"]
      alertname = get_alert_name(abilities[i]["rule"])
      rule_id = get_rule_id(ruleset, alertname)
      if check_if_exists_on_elastic(ruleset, alertname):
        is_rule_triggered = callelastic_for_parallel_batch_execution(sleep_interval, alertname, rule_id, limit_time, abilityid, csvpath, rule_lookup_time, logger)
        if is_rule_triggered: 
          # if rule has triggered, add it to the list of rules that no longer need to be checked
          all_abilities_status[abilityid]['Rule']['Success'] = 'Yes'
          already_triggered_rule_idx.append(i)
      else:
        logger.warning('Corresponding alert rule {} for ability {} not found on elastic...'.format(alertname, abilityname))
    execution_time += sleep_interval
    logger.info("Sleeping {} secs before calling elastic".format(sleep_interval))
    sleep(sleep_interval)
  logger.info('{} out of {} rules were successfully triggered...'.format(len(already_triggered_rule_idx), ability_num))
  for ab, ab_vals in all_abilities_status.items():
    if ab_vals.get('Rule').get('Success') == 'Yes':
      logger.info('Ability ID {} ({}) were successful...'.format(ab_vals.get('Ability').get('ID'), ab_vals.get('Ability').get('Name')))
    else:
      logger.warn('Ability ID {} ({}) were unsuccessful...'.format(ab_vals.get('Ability').get('ID'), ab_vals.get('Ability').get('Name')))
  pprint(all_abilities_status)


def update_ability_args(ability_args):
    # restructure ability_args internal items to dicts
    # schema
    # [{"trait": "variable_name", "value": "variable_value"}]
    result = []
    if ability_args is None: return None
    #pprint(ability_args)
    # first split multiple ability args / traits
    for kv in ability_args.split(','):
        # split individual arg into trait and value
        kvs = kv.split('=')
        result.append({"trait": kvs[0], "value": kvs[1]})
    #pprint(result)
    return result


def ability_args_file_to_usable_data(ability_args_file, logger):
    ability_args_dict = None
    try:
        with open(ability_args_file) as fh:
            ability_args_dict = json.load(fh)
            # for k, v in ability_args_dict.items():
            #     ability_args_dict[k] = update_ability_args(v)
    except Exception as e:
        logger.error('Exception {} occurred in ability_args_file_to_usable_data...'.format(e))
    return ability_args_dict


def get_ability_from_ability_pool(id, abilitypool):
    ret = None
    for i in range(0,len(abilitypool)):
        if id == abilitypool[i]['id']:
            ret = abilitypool[i]
            break
    return ret