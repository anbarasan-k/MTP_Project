#Generate Test Suite from Model and Test

java -jar crawljax-cli-3.5.1.jar http://testfire.net Model -depth 1

python ModelTest.py

python Report.py
