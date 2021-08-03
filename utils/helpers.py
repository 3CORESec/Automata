import os
import yaml
import logging
import colorlog
from utils.back import *


# Global Vars
color = {
	"green": "#61ff33",
	"yellow": "#ecff33",
	"red": "#D00000"
}
#############


def create_log_file(log_file_name):
	with open(log_file_name, 'w') as o: pass


def setup_logger(log_fmt="%(log_color)s%(asctime)s:%(levelname)s:%(message)s", log_file_name=".output.log", level='INFO'):

	# a new log file is created each time.
	# no space issues are caused.
	create_log_file(log_file_name)

	formatter = colorlog.ColoredFormatter(
		log_fmt,
		datefmt='%DT%H:%M:%SZ'
	)

	logger = logging.getLogger()

	handler2 = logging.FileHandler(log_file_name)
	handler = logging.StreamHandler()
	handler.setFormatter(formatter)
	logger.addHandler(handler)
	logger.addHandler(handler2)
	logger.setLevel(level)

	return logger


def get_correct_slash():
  if os.name == 'nt': return '\\'
  else: return '/'


def set_get_correct_slash(mstring):
  if mstring is None: return ''
  if os.name == 'nt': return mstring.replace('/', '\\')
  else: return mstring.replace('\\', '/')


def list_ability_files(path):
    return os.listdir(path)

def parse_yaml(yamlfile):
  ret = None
  if yamlfile.endswith(".yml"): pass
  else: return
  try:
    with open(yamlfile, 'r') as file:
        ret = yaml.full_load(file)
  except Exception as e:
    print('Exception {} occurred in parse_yaml for file {}...'.format(e, yamlfile))
  return ret

def get_rule_id(ruleset, rulename):
    if rulename[0] == None: return
    for i in range(0,len(ruleset)):
      
      temp = rulename
      if type(rulename) == list: temp = rulename[0]
      
      if temp in ruleset[i]["Name"]:
          return ruleset[i]["RuleID"]

def get_rule_ids(ruleset, rulenamedict):
    if rulename == None: return
    for i in range(0,len(ruleset)):
      for rulename in rulenamedict:
        if rulename in ruleset[i]["Name"]:
            return ruleset[i]["RuleID"]

def get_ability_ids_from_file(abilitylist, abilityfolder):
  ability_ids = []
  for ability in abilitylist:
    file_path = abilityfolder + ability
    parsed = parse_yaml(file_path)
    if type(parsed) == list:
      ability_ids.append(parsed[0]['id'])
    elif type(parsed) == dict:
      ability_ids.append(parsed['id'])
    elif parsed is None: continue
    else: pass
  return ability_ids


def get_object_from_yml_ability_file(ability_file_path, object='id'):
  ability_id = None
  parsed = parse_yaml(ability_file_path)
  if type(parsed) == list:
    ability_id = parsed[0][object]
  elif type(parsed) == dict:
    ability_id = parsed[object]
  else: pass
  return ability_id


def get_alert_name(sigmarule):
  alertnamedict = []
  if type(sigmarule) == list:
    for rule in sigmarule:
      try:
        parsed = parse_yaml(rule)
        alertnamedict.append(parsed['title'])
      except TypeError:
        print("Error in the: " + rule)
        return
  elif type(sigmarule) == str:
    try:
      parsed = parse_yaml(sigmarule)
      alertnamedict.append(parsed['title'])
    except TypeError:
      print("Error in the: " + sigmarule)
      return
  else: pass
  return alertnamedict

def initialize_csv(csv_output):
  open(csv_output, 'w+')

def export_results(csv_output, alertname, alertdata, result, abilityid):
  try:
    temp = ''
    if type(alertname) == str: temp = alertname
    elif type(alertname) == list: temp = alertname[0]
    else: pass

    if result == 'Success':
      file = open(csv_output, 'a+')
      out = '"{}","{}","{}","{}"'.format(temp,alertdata[0][1],result,abilityid)
      file.write(out + "\n")
    else:
      file = open(csv_output, 'a+')
      out = '"{}","N/A","{}","{}"'.format(temp,result,abilityid)
      file.write(out + "\n")
  except Exception as e:
    print('Exception {} occurred in export_results...'.format(e))

def export_metrics(csv_metric, deployment_type, success_count, fail_count):
  file = open(csv_metric, 'a+')
  out = '"{}","{}","{}"'.format(deployment_type,success_count,fail_count)
  file.write(out + "\n")

def metric_gen(csv_metric, csv_output, deployment_type):
  successcounter = 0
  failcounter = 0
  with open(csv_output) as cm:
    for i in cm:
      i = i.replace('\n', '').replace('\"', '').split(',')
      op_result = i[2]
      if op_result == "Success": successcounter += 1
      else: failcounter += 1
  export_metrics(csv_metric, deployment_type, successcounter, failcounter)