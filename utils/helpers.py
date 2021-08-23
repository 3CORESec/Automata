import os
import yaml
import logging
import colorlog
import json
import random
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

def get_alert_name(ruleset, ruleid):
  for i in range(0,len(ruleset)):
    if ruleset[i]["RuleID"] == ruleid:
      return ruleset[i]["Name"]
  return "Detection not found"


def get_ability_ids_from_relations_file(relationfile):
  ability_ids = []
  with open(relationfile) as j:
    data = json.load(j)
    for i in data['Automata']:
      if type(i["AbilityID"]) == list:
        for i in i["AbilityID"]:
          ability_ids.append(i)
      else:
        ability_ids.append(i["AbilityID"])
  return ability_ids

def get_rule_ability_id(relationfile, ruleid):
  with open(relationfile) as j:
    data = json.load(j)
    for i in data['Automata']:
      if ruleid == i["RuleID"]:
        if type(i["AbilityID"]) == list:
          n = random.randint(0,len(i["AbilityID"]) - 1)
          return i["AbilityID"][n]
        else:
          return i["AbilityID"]

def get_rule_ability_name(abilities, abilityid):
  for i in range(0,len(abilities)):
    if abilities[i]["id"] == abilityid:
      return abilities[i]["Name"]

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