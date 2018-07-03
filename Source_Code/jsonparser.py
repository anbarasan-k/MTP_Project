import json
from pprint import pprint
import re

with open('result.json') as data_file:    
    data = json.load(data_file)

mystring= data["statistics"]["stateStats"]["urls"]

with open('states.txt', 'w') as outfile:
    json.dump(mystring, outfile)


with open('states.txt') as states:
	for line in states:
		urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)
		for row in urls:
			print row