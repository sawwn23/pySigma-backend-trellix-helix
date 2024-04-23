import sys
import os
from sigma.collection import SigmaCollection
from sigma.backends.trellixhelix import tqlBackend

# create pipeline and backend
trellixhelix_backend = tqlBackend()

def getFilesListFromInputDir(filedir):
    tmp= []
    filelist = []
    for root, dirs, files in os.walk(filedir):
        for file in files:
            filelist.append(os.path.join(root, file))

    for name in filelist:
        if name.endswith(".yml"):
            tmp.append(name)
    return tmp 

# load a ruleset
process_start_rules = getFilesListFromInputDir(sys.argv[1])
process_start_rule_collection = SigmaCollection.load_ruleset(process_start_rules)

# convert the rules
for rule in process_start_rule_collection.rules:
    print(rule.title + " conversion:")
    try:
        result = trellixhelix_backend.convert_rule(rule)[0]
        print(result)
    except Exception as e:  # Catch any potential exception
        print(f"Error converting rule: {e}") 
    print("\n")  