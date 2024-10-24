#!/bin/bash

#/home/jfoutz/bluehound/bluehound_sc/BlueHound/

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m' 
NOCOLOR='\033[0m'
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

#the find command creates a list of files/directories within the given path. if the path
#is just a file it still runs.
find $1 |
while IFS= read -r p; do
    FILE_TYPE=$(file -b $p)
	if [[ "$FILE_TYPE" == *"Python"* ]] || [[ "$p" == *".py"* ]];
	then
	    echo -e ${BOLD}$p${NORMAL}
        
        grep -q -E --color=always "apikey|api_key|secret|token|password|auth|key|pass|user" $p \
        && echo -e "${YELLOW}Searching for API Keys and Secrets [+]${NOCOLOR}" \
        && grep -n -E --color=always "apikey|api_key|secret|token|password|auth|key|pass|user" $p \

        grep -q -E --color=always "(user|username|pass|password)\s*\=\s*\".*\"" $p \
        && echo -e "${YELLOW}Searching for Hardcoded Creds [+]${NOCOLOR}" \
        && grep -n -E --color=always "(user|username|pass|password)\s*\=\s*\".*\"" $p \

        grep -q -E --color=always "www|http" $p \
        && echo -e "${YELLOW}Finding Hardcoded URLs or Endpoints [+]${NOCOLOR}" \
        && grep -n -E --color=always "www|http" $p \

        grep -q -E --color=always "crypt|rc4|arcfour|md5|sha1|sha-1|TripleDES" $p \
        && echo -e "${YELLOW}Bad Cryptography Practices [+]${NOCOLOR}" \
        && grep -n -E --color=always "crypt|rc4|arcfour|md5|sha1|sha-1|TripleDES" $p \

        grep -q -E --color=always "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $p \
        && echo -e "${YELLOW}Finding Hardcoded IP Addresses [+]${NOCOLOR}" \
        && grep -n -E --color=always "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $p \

        grep -q -E --color=always "port\s*\=\s*\d+" $p \
        && echo -e "${YELLOW}Finding Hardcoded Ports [+]${NOCOLOR}" \
        && grep -n -E --color=always "port\s*\=\s*\d+" $p \

        grep -q -E --color=always "SQL|query\(" $p \
        && echo -e "${YELLOW}Potential SQL Injection [+]${NOCOLOR}" \
        && grep -n -E --color=always "SQL|query\(" $p \

        grep -q -E --color=always "(MySQLdb\.connect|MySQLDatabase|psycopg2\.connect|sqlalchemy\.create_engine|MongoClient|connect)\(" $p \
        && echo -e "${YELLOW}Database Connection Objects. Look for Hardcoded Creds [+]${NOCOLOR}" \
        && grep -n -E --color=always "(MySQLdb\.connect|MySQLDatabase|psycopg2\.connect|sqlalchemy\.create_engine|MongoClient|connect)\(" $p \
        
        grep -q -E --color=always "urllib3\.disable_warnings" $p \
        && echo -e "${YELLOW}Certificate Checking Disabled [+]${NOCOLOR}" \
        && grep -n -E --color=always "urllib3\.disable_warnings" $p \

        grep -q -E --color=always "ssl_version" $p \
        && echo -e "${YELLOW}SSL Communications Allowed [+]${NOCOLOR}" \
        && grep -n -E --color=always "ssl_version" $p \

        grep -q -E --color=always "exec\(|eval\(|subprocess|popen" $p \
        && echo -e "${YELLOW}Application Shells out or Dynamically Executes Code [+]${NOCOLOR}" \
        && grep -n -E --color=always "exec\(|eval\(|subprocess|popen" $p \

        grep -q -E --color=always "cPickle\.loads|pickle\.loads|_pickle\.loads|jsonpickle\.decode" $p \
        && echo -e "${YELLOW}Insecure Deserialization [+]${NOCOLOR}" \
        && grep -n -E --color=always "cPickle\.loads|pickle\.loads|_pickle\.loads|jsonpickle\.decode" $p \
        
        grep -q -E --color=always "logger\.info\(|app\.logger\.info\(|logging\.info\(|request_logger\.warn\(|logtest\.debug\(|import logging" $p \
        && echo -e "${YELLOW}Log Injection. Check for Input Sanitization [+]${NOCOLOR}" \
        && grep -n -E --color=always "logger\.info\(|app\.logger\.info\(|logging\.info\(|request_logger\.warn\(|logtest\.debug\(|import logging" $p \

        grep -q -E --color=always "xpath\(" $p \
        && echo -e "${YELLOW}Potential XPATH Injection. Check for Input Sanitization [+]${NOCOLOR}" \
        && grep -n -E --color=always "xpath\(" $p \

        grep -q -E --color=always "exec " $p \
        && echo -e "${YELLOW}Use of exec statement. exec() is OKAY [+]${NOCOLOR}" \
        && grep -n -E --color=always "exec " $p \

        grep -q -E --color=always "\`" $p \
        && echo -e "${YELLOW}Backticks should not be used. Replace with repr() [+]${NOCOLOR}" \
        && grep -n -E --color=always "\`" $p \

        grep -q -E --color=always "\*" $p && grep -q -E --color=always "import" $p \
        && echo -e "${YELLOW}Wildcard imports should not be used [+]${NOCOLOR}" \
        && grep -n -E --color=always "\*" $p && grep -q -E --color=always "import" $p \

        grep -q -E --color=always "not" $p && grep -q -E --color=always "==|<|>|<=|>=" $p \
        && echo -e "${YELLOW}Boolean check is inverted [+]${NOCOLOR}" \
        && grep -q -E --color=always "not" $p && grep -n -E --color=always "==|<|>|<=|>=" $p \

        echo "==================================================="
    fi
done

