# MTP_Project
Model Based Security Testing for Web Applications
lib
Modern web applications are dynamic in nature due to AJAX technology. Our
approach, uses crawljax, a open source modelling tool, and generates a model based on
dynamic event handler, then generates test cases for security based on the model of the
web application, and execute them in a browser to validate the model for security vul-
nerabilities. Our case study of DVWA-Damn Vulnerable Web Application that contains
security vulnerabilities has shown advantages of our tool approach. We have performed
experiments with our test framework in a sample space of 15 web applications. We opine
that our testing tool is capable of capturing security vulnerabilities like XSS and SQL
Injection in the tested web applications in an automated manner.

Dependancies:

Crawljax, Python libraries Beautifulsoup, Mechanize, requests

Download crawljax CLI version from crawljax.com. Extract the binaries.
Download our tool source from Source_Code folder and then extract the binaries inside crawljax folder.
Install BS4 library for Beautifulsoup library using the following command.
apt-get install python-bs4
Install Mechanize library using the following command.
pip install mechanize
Install requests library using the following command.
pip install requests

To run the Security Testing Tool configure the following parameters in ModelTest.sh file

depth-Crawling depth for Modelling web application.
URL- URL of web application being tested.

Run ModelTest.sh shell script file after configuration.

The State Machine model of web application will be stored in Model Folder.
Output folder will contain the following files

Vulnerability Model- Vulnerable parameters for XSS and SQL Injection.
Output.html- Detailed HTML report of SQLI and XSS Testing of web application.
Summary.html- Summary report of SQLI and XSS Testing of web application.

Files and Folders in the Repository

Source_Code - Source of the Security Testing Framework.
Thesis_Latex_Code - Latex source code of the Thesis Report.
Presentation_Latex_Code - Latex source code of the Presentation.
Thesis.pdf - Dissertation Report of the MTP
Presentation.pdf - Presentation of the MTP
