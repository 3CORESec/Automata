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
    parser.add_argument('-rf', '--relationfile', help='The file that contains the relations between Detection Rules and Abilities')
    parser.add_argument('-t', '--target', help='The target agent')
    parser.add_argument('-beip', '--batch_execution_in_parallel', dest='batch_execution_in_parallel', action='store_true', help='A switch that enabled batch execution of the abilities contained on the specified ability folder and caldera in a parallel fashion where all abilities are executed at once and checks for their triggers are also executed in parallel...')
    parser.add_argument('-o', '--output', help='File to Output CSV results', default='automata.csv')
    parser.add_argument('-m', '--metrics', help='File to metrics', default='info.csv')
    parser.add_argument('-p', '--pdf', help='File to Output PDF Report', default='automata.pdf')
    parser.add_argument('-b', '--batch', help='Batch Execution of the tests on Rules specified in the relations file')
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
    rulepool = get_rules(args.relationfile)
    abilitypool = get_abilities(args.target, logger)
    ids = get_ability_ids_from_relations_file(args.relationfile)
    avail = check_on_caldera(ids, abilitypool, args.relationfile, ruleset)
    if args.bypass_ability_execution is None or not args.bypass_ability_execution:
        batch_execution_in_parallel(rulepool, avail, ruleset, args.target, args.bypass_ability_execution, args.initial_sleep_time, args.sleep_interval, args.initial_limit_time, args.rule_lookup_time, args.ability_args_file, args.output, logger, args.relationfile)
    metric_gen(args.metrics, args.output, configfile.deployment_type)
    generate_report(args.output, args.pdf, args.metrics, logger)
elif args.batch:
    ExecutionType = "Batch"
    rulepool = get_rules(args.relationfile)
    abilitypool = get_abilities(args.target, logger)
    ids = get_ability_ids_from_relations_file(args.relationfile)
    avail = check_on_caldera(ids, abilitypool, args.relationfile, ruleset)
    batch_execution(rulepool, avail, ruleset, args.target, args.bypass_ability_execution, args.initial_sleep_time, args.sleep_interval, args.initial_limit_time, args.output, args.rule_lookup_time, logger, args.relationfile)
    metric_gen(args.metrics, args.output, configfile.deployment_type)
    generate_report(args.output, args.pdf, args.metrics, logger)
