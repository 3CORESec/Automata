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

def get_rules(relationfile):
  rules = []
  with open(relationfile) as j:
    data = json.load(j)
    for i in data['Automata']:
        rules.append(i["RuleID"])
  return rules

def get_rule_id(relationfile, abilityid):
  with open(relationfile) as j:
    data = json.load(j)
    for i in data['Automata']:
        if i["AbilityID"] == abilityid:
            return i["RuleID"]
        else:
            return

def check_on_caldera(ids, ability_pool, relationfile, ruleset):
  ready_to_use = {}
  num = 0
  for i in range(0,len(ability_pool)):
    if ability_pool[i]['id'] in ids:
      ready_to_use[num] = {}
      ready_to_use[num]['Name'] = ability_pool[i]["Name"]
      ready_to_use[num]['id'] = ability_pool[i]["id"]
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
  detection_engine = kibana_url + '/api/detection_engine/rules?rule_id=' + rule_id
  response = requests.get(detection_engine, auth=(configfile.http_auth_user,configfile.http_auth_pass)).json()
  if 'status_code' in response:
    status = False
    execstatus = "Detection not found"
    return status, execstatus
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

def batch_execution(rules, abilities, ruleset, target, bypass_ability_execution, initial_sleep_time, sleep_interval, limit_time, csvpath, rule_lookup_time, logger, relationfile):
  for rule in rules:
    abilityid = get_rule_ability_id(relationfile, rule)
    alertname = get_alert_name(ruleset, rule)
    if alertname == "Detection not found":
      logger.warning("Detection not found on Elastic: '{}'. Skipping".format(rule))
      continue
    enabled, execstatus = elastic_get_rule_status(rule)
    if elastic_rule_health(enabled, execstatus, csvpath, alertname, abilityid) == False:
      if enabled == False:
        logger.warning("The detection '{}' is disabled. Skipping".format(rule))
      elif execstatus != "succeeded":
        logger.warning("The detection '{}' is having errors on execution. Skipping".format(alertname))
      continue
    elif not check_single_on_caldera(abilityid, abilities, logger):
      export_results(csvpath, alertname, "N/A", "Ability not found", abilityid)
      continue
    else:
      execute_ability(target, abilityid, logger)
      logger.info("Sleeping {} secs before calling elastic".format(initial_sleep_time))
      sleep(initial_sleep_time)
      callelastic(sleep_interval, alertname, rule, limit_time, abilityid, csvpath, rule_lookup_time, logger)


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


def batch_execution_in_parallel(rules, abilities, ruleset, target, bypass_ability_execution, initial_sleep_time, sleep_interval, limit_time, rule_lookup_time, ability_args_dict, csvpath, logger, relationfile):
  global execution_time
  finished_rules = []
  success_rules = []
  all_rules_status = {}
  execution_time = 0
  counter = 0
  rule_num = len(rules)
  for rule in rules:
    abilityid = get_rule_ability_id(relationfile, rule)
    abilityname = get_rule_ability_name(abilities, abilityid)
    alertname = get_alert_name(ruleset, rule)
    enabled, execstatus = elastic_get_rule_status(rule)
    if elastic_rule_health(enabled, execstatus, csvpath, alertname, abilityid) == False:
      if enabled == False:
        logger.warning("The detection '{}' is disabled. Skipping".format(rule))
        finished_rules.append(rule)
      elif execstatus != "succeeded":
        logger.warning("The detection '{}' is having errors on execution. Skipping".format(alertname))
        finished_rules.append(rule)
      continue
    elif not check_single_on_caldera(abilityid, abilities, logger):
      export_results(csvpath, alertname, "N/A", "Ability not found", abilityid)
      continue
    else:
      if ability_args_dict == None:
        execute_ability(target, abilityid, logger)
      else:
        execute_ability(target, abilityid, logger, ability_args=ability_args_dict.get(abilityid))
      logger.info('Executing Ability {} out of {} (Named: {})'.format(counter, rule_num, abilityname))
    all_rules_status[rule] = {
      'Ability': {
        'ID': abilityid, 'Name': abilityname
      },
      'Rule': {
        'ID': rule, 'Name': alertname, 'Success': 'No'
      }
    }
  sleep(initial_sleep_time)
  while(execution_time <= limit_time):
    for rule in rules:
      if len(finished_rules) == rule_num:
        # if all abilities executions have already returned results, then "for" loop as well as "while" loop would be needed to be broken
        execution_time += limit_time
        break
      if rule in finished_rules: 
        # if rule is already triggered, then skip rechecks of that
        logger.info('Corresponding alert rule {} for ability {} ({}) already executed & returned result...'.format(alertname, abilityid, abilityname))
        continue
      abilityid = get_rule_ability_id(relationfile, rule)
      abilityname = get_rule_ability_name(abilities, abilityid)
      alertname = get_alert_name(ruleset, rule)
      enabled, execstatus = elastic_get_rule_status(rule)
      is_rule_triggered = callelastic_for_parallel_batch_execution(sleep_interval, alertname, rule, limit_time, abilityid, csvpath, rule_lookup_time, logger)
      if is_rule_triggered: 
        # if rule has triggered, add it to the list of rules that no longer need to be checked
        all_rules_status[rule]['Rule']['Success'] = 'Yes'
        finished_rules.append(rule)
        success_rules.append(rule)
    execution_time += sleep_interval
    logger.info("Sleeping {} secs before calling elastic".format(sleep_interval))
    if len(finished_rules) == rule_num:
      break
    sleep(sleep_interval)
  logger.info('{} out of {} rules were successfully triggered...'.format(len(success_rules), rule_num))
  for ab, ab_vals in all_rules_status.items():
    if ab_vals.get('Rule').get('Success') == 'Yes':
      logger.info('Ability ID {} ({}) were successful...'.format(ab_vals.get('Ability').get('ID'), ab_vals.get('Ability').get('Name')))
    else:
      logger.warn('Ability ID {} ({}) were unsuccessful...'.format(ab_vals.get('Ability').get('ID'), ab_vals.get('Ability').get('Name')))


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