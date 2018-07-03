import sys
import mechanize
import requests
from bs4 import BeautifulSoup
import urllib3
import mechanize
from pprint import pprint
import re
import json
import time
from pprint import pprint
from os import walk

urllib3.disable_warnings()

header = '<!DOCTYPE html><html><head><link rel="stylesheet" type="text/css" href="style.css"></head><body><!doctyle html><html><head><title>Model Based Test Results from Browser</title></head><body>'
body = '<table><thead><tr><th>XSS and SQL Injection Test Results</th></tr>'
footer = '</table></body></html>'
header_model= '<!DOCTYPE html><html><head><link rel="stylesheet" type="text/css" href="style.css"></head><body><!doctyle html><html><head><title>Vulnerability Model</title></head><body>'
body_model = '<table><thead><tr><th>Vulnerability Model Report using State Machine</th></tr>'


db=open("output/"+"debug"+".log", "a+")
		

def ModelApp(url):
	#print Test_script

	Vulnerable_elements = []

	soup = BeautifulSoup(open("Model/doms/"+url), 'html.parser')

	DOM_data = soup.form

	try:
		DOM_input_data = DOM_data.find_all('input')	
	except:
		return

	try:	
		DOM_TextArea_data=DOM_data.find_all('textarea')	
	except:
		DOM_TextArea_data=[]

	form = DOM_data.find_all('form')
	
	action_type = soup.find('form').get('action')
	
	#print action_type

	fp=open("output/"+"Vulnerability_Model"+".txt", "a+")
		
	fp.write("<b>" + url + "</b> \n")
	
	if not DOM_input_data:
		fp.write("No candidate elements for vulnerability \n"  )
	else:
		fp.write("Vulnerability points for XSS and SQL \n")

		for tag in DOM_input_data:
			fp.write("<xmp>")
			fp.write(str(tag))
			fp.write("</xmp>")
			fp.write("\n")
			fp.write(str(tag))
			fp.write("\n")	

			if tag.has_attr('name'):
				Vulnerable_elements.append(tag['name'])
			elif tag.has_attr('id'):
				Vulnerable_elements.append(tag['id'])
			else:
				tag.has_attr('value')
				Vulnerable_elements.append(tag['value'])
			
		for tag in DOM_TextArea_data:
			fp.write("<xmp>")
			fp.write(str(tag))
			fp.write("</xmp>")
			fp.write("\n")
			fp.write(str(tag))
			fp.write("\n")	

			if tag.has_attr('name'):
				Vulnerable_elements.append(tag['name'])
			elif tag.has_attr('id'):
				Vulnerable_elements.append(tag['id'])
			else:
				tag.has_attr('value')
				Vulnerable_elements.append(tag['value'])
	fp.close()	

	with open("output/"+"Vulnerability_Model"+".txt", 'r') as input, open("output/"+"Vulnerability_Model"+".html", 'w') as output:
		output.write(header_model)
		output.write(body_model)
		for line in input:
			output.write('<tr><td>{}</td></tr>\n'.format(line))
		output.write(footer)	



def reflected_xsstest(Test_script, url):
	#print Test_script

	Vulnerable_elements = []


	db.write("URL under Test" + url+"\n")
	db.write("Testing Test_script" + Test_script+"\n")

	#print url

	
	request = requests.get(url,verify=True)

	if not request.ok:
		print "Page Not found or unauthorized to view"
		return

	soup = BeautifulSoup(request.text, 'html.parser')

	DOM_data = soup.form

	Browser_obj = mechanize.Browser()

	Browser_obj.open(url)

	#print [form for form in Browser_obj.forms()][0]	
	vulnerability_count=0

	fs=open("output/"+"report.txt", "a+")

	try:
		DOM_input_data = DOM_data.find_all('input')	
	except:
		return

	if not DOM_input_data:
		print "No candidate elements for Reflected XSS vulnerability"
		fs.write("No candidate elements for Reflected XSS vulnerability" + "\n")
		db.write("No candidate elements for Reflected XSS vulnerability" + "\n")

	else:
		try:	
			DOM_TextArea_data=DOM_data.find_all('textarea')	
		except:
			DOM_TextArea_data=[]

		forms = DOM_data.find_all('form')
		action_type = soup.find('form').get('action')
	
		#print action_type
					
		for tag in DOM_input_data:
			if tag.has_attr('name'):
				Vulnerable_elements.append(tag['name'])
			else:
				if tag.has_attr('id'):
					Vulnerable_elements.append(tag['id'])

		for tag in DOM_TextArea_data:
			if tag.has_attr('name'):
				Vulnerable_elements.append(tag['name'])
			elif tag.has_attr('id'):
				Vulnerable_elements.append(tag['id'])
			else:
				tag.has_attr('value')
				Vulnerable_elements.append(tag['value'])
			
	#print Vulnerable_elements

		Browser_obj.select_form(nr=0)

#	Browser_obj.set_value("Text Area content", kind="text", nr=0)

	

		for i in range(0,len(Vulnerable_elements)):
	#for i in range(0,1):
			try:
				Browser_obj.form[Vulnerable_elements[i]] = Test_script
			except ValueError:
				fs.write(Vulnerable_elements[i] + "Input field is read only"+"\n")
				print Vulnerable_elements[i] + "Input field is read only"
			except TypeError:
				fs.write(Vulnerable_elements[i] + "Input field is read only"+"\n")
				print Vulnerable_elements[i] + "Input field is read only"		
			else:
				Browser_obj.form[Vulnerable_elements[i]] = Test_script

		Browser_obj.submit()

		Browser_Exec_resp = Browser_obj.response().read()
		db.write(Browser_Exec_resp.encode('utf-8')+"\n")
		#print Browser_Exec_resp


		#print Test_script
		
		if(Test_script.find('-alert(3)-')>0):
			#print("Entered Logic")
			if(Browser_Exec_resp.find(Test_script)>0):
				print "Test_script Reflected in Response. Reflected XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"
				fs.write("Test_script Reflected in Response. Reflected XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"+"\n")
				vulnerability_count+=1
			elif(Browser_Exec_resp.find("&#39;-alert(3)-&#39;")):
				print "Test_script Reflected in Response. Reflected XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"
				fs.write("Test_script Reflected in Response. Reflected XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"+"\n")
				vulnerability_count+=1
			else:	
				print "No Reflected XSS Vulnerability not found for script" + "<xmp>" + Test_script.strip() + "</xmp>"
				fs.write("No Reflected XSS Vulnerability not found for script" + "<xmp>" + Test_script.strip() + "</xmp>" + "</xmp>"+"\n")
		elif(Browser_Exec_resp.find(Test_script))>0:
			print "Test_script Reflected in Response. Reflected XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"
			fs.write("Test_script Reflected in Response. Reflected XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"+"\n")
			vulnerability_count+=1
		else:
			#print("Not Entered Logic")
			print "No Reflected XSS Vulnerability not found for script" + "<xmp>" + Test_script.strip() + "</xmp>"
			fs.write("No Reflected XSS Vulnerability not found for script" + "<xmp>" + Test_script.strip() + "</xmp>" + "</xmp>"+"\n")

	fs.close();

	fp=open("output/"+"report.txt", "a+")

	fp.write("<b>State: " + url + "</b> \n")

	if vulnerability_count>0:
		fp.write("Test_script Reflected in Response. Reflected XSS Vulnerability found \n" )
	else:
		fp.write("No Reflected XSS Vulnerability not found for script \n")

	fp.close()	



def storedxsstest(Test_script, url):
	
	db.write("URL under Test" + url+"\n")
	db.write("Testing Test_script" + Test_script+"\n")



	#print Test_script
	#print url

	request = requests.get(url,verify=False)

	if not request.ok:
		print "Page Not found or unauthorized to view"
		return

	soup = BeautifulSoup(request.text, 'html.parser')


	DOM_data = soup.form

	Browser_obj = mechanize.Browser()

	Browser_obj.open(url)

	Vulnerable_elements = []

	#print [form for form in Browser_obj.forms()][0]	
	vulnerability_count=0


	fs=open("output/"+"report.txt", "a+")

	try:
		DOM_input_data = DOM_data.find_all('input')	
	except:
		return

	if not DOM_input_data:
		print "No candidate elements for stored XSS vulnerability"
		fs.write("No candidate elements for stored XSS vulnerability" + "\n")
		db.write("No candidate elements for Reflected XSS vulnerability" + "\n")
	else:
		forms = DOM_data.find_all('form')
					
		try:	
			DOM_TextArea_data=DOM_data.find_all('textarea')	
		except:
			DOM_TextArea_data=[]

		forms = DOM_data.find_all('form')
		action_type = soup.find('form').get('action')
	
		#print action_type
					
		for tag in DOM_input_data:
			if tag.has_attr('name'):
				Vulnerable_elements.append(tag['name'])
			else:
				if tag.has_attr('id'):
					Vulnerable_elements.append(tag['id'])

		for tag in DOM_TextArea_data:
			if tag.has_attr('name'):
				Vulnerable_elements.append(tag['name'])
			elif tag.has_attr('id'):
				Vulnerable_elements.append(tag['id'])
			else:
				tag.has_attr('value')
				Vulnerable_elements.append(tag['value'])
			
	#print Vulnerable_elements

		Browser_obj.select_form(nr=0)

#	Browser_obj.set_value("Text Area content", kind="text", nr=0)
		

		for i in range(0,len(Vulnerable_elements)):
	#for i in range(0,1):
			try:
				Browser_obj.form[Vulnerable_elements[i]] = Test_script
			except ValueError:
				fs.write(Vulnerable_elements[i]+"Input field is read only" + "\n")
				print Vulnerable_elements[i]+"Input field is read only"
			except TypeError:
				fs.write(Vulnerable_elements[i] + "Input field is read only"+"\n")
				print Vulnerable_elements[i] + "Input field is read only"		
			else:
				Browser_obj.form[Vulnerable_elements[i]] = Test_script

		Browser_obj.submit()

		#print url

		request = requests.get(url,verify=False)

		Browser_Exec_resp = request.text
		
		db.write(Browser_Exec_resp.encode('utf-8') + "\n")

		if(Test_script.find('-alert(3)-')>0):
			#print("Entered Logic")
			if(Browser_Exec_resp.find(Test_script)>0):
				print "Test_script stored in Response. stored XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"
				fs.write("Test_script stored in Response. stored XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"+"\n")
				vulnerability_count+=1
			elif(Browser_Exec_resp.find("&#39;-alert(3)-&#39;")):
				print "Test_script stored in Response. stored XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"
				fs.write("Test_script stored in Response. stored XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"+"\n")
				vulnerability_count+=1
			else:	
				print "No stored XSS Vulnerability not found for script" + "<xmp>" + Test_script.strip() + "</xmp>"
				fs.write("No stored XSS Vulnerability not found for script" + "<xmp>" + Test_script.strip() + "</xmp>" + "</xmp>"+"\n")
		elif(Browser_Exec_resp.find(Test_script))>0:
			print "Test_script stored in Response. stored XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>"
			fs.write("Test_script stored in Response. stored XSS Vulnerability found for script" + "<xmp>" + Test_script.strip() + "</xmp>" + "\n")
			vulnerability_count+=1
		else:
			#print("Not Entered Logic")
			print "No stored XSS Vulnerability not found for script" + "<xmp>" + Test_script.strip() + "</xmp>"

	fs.close()
			
	fp=open("output/"+"summary.txt", "a+")

	fp.write("<b>State: " + url + "</b> \n")

	if vulnerability_count>0:
		fp.write("Test_script loaded from webapplication. Stored XSS Vulnerability found \n" )
	else:
		fp.write("No stored XSS Vulnerability not found for script \n")

	fp.close()	

def sqltest(Test_script,url):
	#print(Test_script)

	request = requests.get(url)

	if not request.ok:
		print "Page Not found or unauthorized to view"
		return

	soup = BeautifulSoup(request.text, 'html.parser')

	Browser_obj = mechanize.Browser()

	DOM_data = soup.form

	vulnerability_count=0

	Vulnerable_elements = []

	try:
		DOM_input_data = DOM_data.find_all('input')	
	except:
		return

	try:	
		DOM_TextArea_data=DOM_data.find_all('textarea')	
	except:
		DOM_TextArea_data=[]
	
	fs=open("output/"+"report.txt","a+")	

	if not DOM_input_data:
		print "No candidate elements for SQL Injection"
		fs.write("No candidate elements for SQL Injection" + "\n")
	else:
		forms = DOM_data.find_all('form')

		action_type = soup.find('form').get('action')

	

		for tag in DOM_input_data:
			if tag.has_attr('name'):
				Vulnerable_elements.append(tag['name'])
			elif tag.has_attr('id'):
					Vulnerable_elements.append(tag['id'])
			else:
				tag.has_attr('value')
				Vulnerable_elements.append(tag['value'])

		for tag in DOM_TextArea_data:
			if tag.has_attr('name'):
				Vulnerable_elements.append(tag['name'])
			elif tag.has_attr('id'):
				Vulnerable_elements.append(tag['id'])
			else:
				tag.has_attr('value')
				Vulnerable_elements.append(tag['value'])
			

	#print Vulnerable_elements

#	Browser_obj.set_value("Text Area content", kind="text", nr=0)

		Browser_obj.open(url)

		Browser_obj.select_form(nr=0)

		for i in range(0,len(Vulnerable_elements)):
		#for i in range(0,1):
			try:
				Browser_obj.form[Vulnerable_elements[i]] = Test_script
			except ValueError:
				print Vulnerable_elements[i] + 'Input field is read only'
				fs.write(Vulnerable_elements[i] + 'Input field is read only' + "\n")
			except TypeError:
				fs.write(Vulnerable_elements[i] + "Input field is read only"+"\n")
				print Vulnerable_elements[i] + "Input field is read only"	
			else:
				Browser_obj.form[Vulnerable_elements[i]] = Test_script

		Browser_obj.submit()

		Browser_Exec_resp = Browser_obj.response().read()

	#	print Browser_Exec_resp

		db.write(Browser_Exec_resp.encode('utf-8') + "\n")

		if (Browser_Exec_resp.find("error")>0):
			print('SQL Injection Vulnerability found' + 'for Test_script ' + Test_script)
			fs.write('SQL Injection Vulnerability found' + 'for Test_script ' + Test_script + "\n")
			vulnerability_count+=1
		elif (Browser_Exec_resp.find("MySQL")>0):
			print('SQL Injection Vulnerability found' + 'for Test_script ' + Test_script)
			fs.write('SQL Injection Vulnerability found' + 'for Test_script ' + Test_script + "\n")	
			vulnerability_count+=1
		elif (Browser_Exec_resp.find("syntax")>0):
			print('SQL Injection Vulnerability found' + 'for Test_script ' + Test_script)
			fs.write('SQL Injection Vulnerability found' + 'for Test_script ' + Test_script + "\n")	
			vulnerability_count+=1	
		else:
			print('SQL Injection Vulnerability not found' + 'for Test_script ' + Test_script)
			fs.write('SQL Injection Vulnerability not found' + 'for Test_script ' + Test_script + "\n")

	fp=open("output/"+"summary.txt", "a+")

	fp.write("<b>State: " + url + "</b> \n")

	if vulnerability_count>0:
		fp.write("SQL Query Executed. SQL Injection Vulnerability found \n" )
	else:
		fp.write("SQL Query not Executed. SQL Injection Vulnerability not found \n")

	fp.close()	

with open('Model/result.json') as data_file:    
    data = json.load(data_file)

mystring= data["statistics"]["stateStats"]["urls"]

with open('states.txt', 'w') as outfile:
	json.dump(mystring, outfile)

f = []
for (dirpath, dirnames, filenames) in walk("Model/doms"):
	f.extend(filenames)
	break

db.write("States from Model" + "\n")

for files in f:
	#print files
	db.write(files + "\n")
	ModelApp(files)


def testurl(url):
	with open('XSS_TestSuite.txt') as f:
		for line in f:
			Test_script = line
			reflected_xsstest(Test_script,url)
			storedxsstest(Test_script,url)

	with open('SQL_TestSuite.txt') as f:
		for line in f:
			Test_script = line
			sqltest(Test_script,url)		

with open('states.txt') as states:
	for line in states:
		urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)
		for row in urls:
			print "<b>State: " + row + "</b>"
			testurl(row)
