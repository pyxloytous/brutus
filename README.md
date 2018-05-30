# BRUTOUS
A web security assessment tools to crawl over given domain, find all links and brute force on login pages if any 

Brutus is a tool that provides basically two functionality 

1. Crawling target domain - It crawls given domain and collects links it finds
 a. Tells you about all links it could find       
 b. Tells you if there is any link that contains login form

 2. Login Brute force:       If a login link is passed to it with the supply of dectionaries required 
                             If starts performing a bruteforce attack on the link 
                             It can be passed with sql injection strings to try with on the login forms
                             
                             
Author: Pyxloytous (pyxloytous@gmil.com)
version: 0.1  

./brutus -h  - to see required parameters to run it
