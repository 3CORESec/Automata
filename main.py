from utils.back import *
from utils.helpers import *
from utils.report import *
import argparse
from time import sleep
from utils import configfile
import os
import json


def setup_args():
    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument('-afp', '--ability_file_path', help='Path to local ability file. Eg: /path/to/ability/file.yml')
    parser.add_argument('-af', '--abilityfolder', help='The folder containing the ability files')
    parser.add_argument('-t', '--target', help='The target agent')
    parser.add_argument('-beip', '--batch_execution_in_parallel', dest='batch_execution_in_parallel', action='store_true', help='A switch that enabled batch execution of the abilities contained on the specified ability folder and caldera in a parallel fashion where all abilities are executed at once and checks for their triggers are also executed in parallel...')
    parser.add_argument('-o', '--output', help='File to Output CSV results', default='automata.csv')
    parser.add_argument('-m', '--metrics', help='File to metrics', default='info.csv')
    parser.add_argument('-p', '--pdf', help='File to Output PDF Report', default='automata.pdf')
    parser.add_argument('-b', '--batch', help='Batch Execution of the abilities contained on the specified folder and caldera, that contains correponding alerts on the SIEM')
    parser.add_argument('-ie', '--individual_easy', dest='individual_easy', action='store_true', help='A switch that enables easier individual execution of an ability by just pointing to ability file, ability_args file and sigma rules folder...')
    parser.add_argument('-s', '--sigmafolder', help='The folder containing the sigma rules')
    parser.add_argument('-bae', '--bypass_ability_execution', dest='bypass_ability_execution', action='store_true', help='Switch to bypass ability execution phase and directly query elastic.')
    parser.add_argument('-ist', '--initial_sleep_time', type=int, default=120, help='Initial sleep time in seconds before making first call to elastic to check for detection...')
    parser.add_argument('-ilt', '--initial_limit_time', type=int, default=300, help='Limit execution time in seconds before skiping to the next test')
    parser.add_argument('-si', '--sleep_interval', type=int, default=30, help='Sleep time in seconds before making calls after the first one, to elastic to check for detection...')
    parser.add_argument('-rlt', '--rule_lookup_time', type=str, default="5m", help='Rule lookup time to check elastic rules triggered in the past. Eg: -rlt 5m...')
    parser.add_argument('-aa', '--ability_args', help='Arguments that are required by advanced abilities to be passed as variables for successful execution. Eg: field_name=value,field_name_2=value_2,...')
    parser.add_argument('-aaf', '--ability_args_file', help='Path to JSON file that contains arguments that are required by advanced abilities to be passed as variables for successful execution. Eg: helpers/ability_args_file.json...')
    parser.add_argument('-v', '--verbosity', metavar='<verbosity_level>', type=str, default='INFO', help='Execution verbosity level. Eg: SUCCESS|WARN|INFO|DEBUG.')
    args = parser.parse_args()
    args.ability_args = update_ability_args(args.ability_args)
    return args


args = setup_args()
logger = setup_logger(level=args.verbosity)
ExecutionType = None
ruleset = get_detection_rules()
initialize_csv(args.output)
initialize_csv(args.metrics)
if args.ability_args_file:
    args.ability_args_file = ability_args_file_to_usable_data(args.ability_args_file, logger)


if args.batch_execution_in_parallel:
    # execute all abilities at once.
    # then sleep for some time.
    # then start looking for elastic rule triggers for all rules in every iteration until execution_time crosses limit_time.
    ExecutionType = "batch_execution_in_parallel"
    abilities = list_ability_files(args.abilityfolder)
    abilitypool = get_abilities(args.target, logger)
    ids = get_ability_ids_from_file(abilities, args.abilityfolder)
    avail = check_on_caldera(ids, abilitypool, args.sigmafolder)
    if args.bypass_ability_execution is None or not args.bypass_ability_execution:
        batch_execution_in_parallel(avail, ruleset, args.target, args.bypass_ability_execution, args.initial_sleep_time, args.sleep_interval, args.initial_limit_time, args.rule_lookup_time, args.ability_args_file, args.output, logger)
    metric_gen(args.metrics, args.output, configfile.deployment_type)
    generate_report(args.output, args.pdf, args.metrics, logger)
elif args.batch:
    ExecutionType = "Batch"
    abilities = list_ability_files(args.abilityfolder)
    abilitypool = get_abilities(args.target, logger)
    ids = get_ability_ids_from_file(abilities, args.abilityfolder)
    avail = check_on_caldera(ids, abilitypool, args.sigmafolder)
    batch_execution(avail, ruleset, args.target, args.bypass_ability_execution, args.initial_sleep_time, args.sleep_interval, args.initial_limit_time, args.output, args.rule_lookup_time, logger)
    metric_gen(args.metrics, args.output, configfile.deployment_type)
    generate_report(args.output, args.pdf, args.metrics, logger)
elif args.individual_easy:
    ExecutionType = "Individual Easy"
    logger.info('Execution type: {}...'.format(ExecutionType))
    abilitypool = get_abilities(args.target, logger)
    abilityid = get_object_from_yml_ability_file(args.ability_file_path, object='id')
    ability = get_ability_from_ability_pool(abilityid, abilitypool)
    sigma_rule_file = args.sigmafolder + get_correct_slash() + get_object_from_yml_ability_file(args.ability_file_path, object='rules')[0]
    sigma_rule_name = get_object_from_yml_ability_file(sigma_rule_file, object='title')
    if check_single_on_caldera(abilityid, abilitypool, logger) and check_if_exists_on_elastic(ruleset, sigma_rule_name) and (args.bypass_ability_execution is None or not args.bypass_ability_execution):
        logger.info("Ability Found in the Caldera Server and Alert Found in the Elastic Cluster")
        rule_id = get_rule_id(ruleset, sigma_rule_name)
        alertname = get_alert_name((set_get_correct_slash(args.sigmafolder) + set_get_correct_slash(eval(ability["rules"])[0])))
        enabled, execstatus = elastic_get_rule_status(rule_id)
        if elastic_rule_health(enabled, execstatus, args.output, alertname, abilityid) == False:
            logger.warning("The detection '{}' is disabled or having errors on execution. Skipping".format(alertname))
            exit

        # configure ability args from file or CLI
        ability_args = None
        if args.ability_args is not None:
            # if ability args are set in command line
            ability_args = args.ability_args
        elif args.ability_args_file is not None:
            # if ability_args are set in file
            ability_args = args.ability_args_file.get(abilityid)
        else:
            # If ability_args are not set
            ability_args = None

        execute_ability(args.target, abilityid, logger, ability_args=ability_args)
        logger.info("Sleeping {} secs before calling elastic".format(args.initial_sleep_time))
        sleep(args.initial_sleep_time)
        callelastic(args.sleep_interval, sigma_rule_name, rule_id, args.initial_limit_time, abilityid, args.output, args.rule_lookup_time, logger)
else:
    logger.error("Ability ID or Ability Folder must be specified on the command line")
