import sys

header = '<!DOCTYPE html><html><head><link rel="stylesheet" type="text/css" href="style.css"></head><body><!doctyle html><html><head><title>Model Based Test Results</title></head><body>'
body = '<table><thead><tr><th>XSS Test Results</th></tr>'
footer = '</table></body></html>'

with open('output/report.txt', 'r') as input, open('report.html', 'w') as output:
   output.write(header)
   output.write(body)
   for line in input:
       output.write('<tr><td>{}</td></tr>\n'.format(line))
   output.write(footer)	


with open('output/summary.txt', 'r') as input, open('summary.html', 'w') as output:
   output.write(header)
   output.write(body)
   for line in input:
       output.write('<tr><td>{}</td><tr>\n'.format(line))
   output.write(footer)	  