import yaml
import glob
import json

sigmadir = "C:\\Sigma\\Rules\\Dir\\"
sigmarules = glob.glob(sigmadir + '/**/*.yml', recursive=True)

relations = {
    "Automata": []
}

for rule in sigmarules:
    with open(rule, 'r') as file:
        try:
            ret = yaml.full_load(file)
            id = ret['id']
            abilities = ret['simulate']
        except:
            pass
    skeleton = {
        "RuleID": id,
        "AbilityID": abilities
    }
    relations['Automata'].append(skeleton)

with open('relations.json', 'w+') as f:
    json.dump(relations, f, indent=2)