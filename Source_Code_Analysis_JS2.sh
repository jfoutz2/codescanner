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
#Loops through the list of files/directories, filters out directories.
while IFS= read -r p; do
    #determines the file type and sets it to a variable
    FILE_TYPE=$(file -b $p)
    #Runs checks if the file is Javascript. Maybe change this incase the filetype shows up differently
    if [[ "$FILE_TYPE" == *"JavaScript"* ]] || [[ "$p" == *".js"* ]];
	then
	    echo -e ${BOLD}$p${NORMAL}
        grep -q -E --color=always "apikey|api_key|secret|token|password|auth|key|pass|user" $p \
        && echo -e "${YELLOW}Searching for API Keys and Secrets [+]${NOCOLOR}" \
        && grep -n -E --color=always "apikey|api_key|secret|token|password|auth|key|pass|user" $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "eval|document\.write|innerHTML|setTimeout|setInterval|Function|trustAsHtml|dangerouslySetInnerHTML" $p \
        && echo -e "${YELLOW}Detecting Dangerous Function Calls [+]${NOCOLOR}" \
        && grep -n -E --color=always "eval|document\.write|innerHTML|setTimeout|setInterval|Function|trustAsHtml|dangerouslySetInnerHTML" $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "location\.href|location\.replace|location\.assign|window\.open" $p \
        && echo -e "${YELLOW}Checking for URL Manipulation [+]${NOCOLOR}" \
        && grep -n -E --color=always "location\.href|location\.replace|location\.assign|window\.open" $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "XMLHttpRequest|fetch|Access-Control-Allow-Origin|withCredentials” /path/to/js/files" $p \
        && echo -e "${YELLOW}Searching for Cross-Origin Requests [+]${NOCOLOR}" \
        && grep -n -E --color=always "XMLHttpRequest|fetch|Access-Control-Allow-Origin|withCredentials” /path/to/js/files" $p \
        #&& echo "---------------------------------------------------"
        
        grep -q --color=always postMessage $p \
        && echo -e "${YELLOW}Analyzing postMessage Usage [+]${NOCOLOR}" \
        && grep -n --color=always postMessage $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "www|http" $p \
        && echo -e "${YELLOW}Finding Hardcoded URLs or Endpoints [+]${NOCOLOR}" \
        && grep -n -E --color=always "www|http" $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "console\.log|debugger|alert|console\.dir" $p \
        && echo -e "${YELLOW}Locating Debugging Information [+]${NOCOLOR}" \
        && grep -n -E --color=always "console\.log|debugger|alert|console\.dir" $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "document\.getElementById|document\.getElementsByClassName|document\.querySelector|document\.forms" $p \
        && echo -e "${YELLOW}Investigating User Input Handling [+]${NOCOLOR}" \
        && grep -n -E --color=always "document\.getElementById|document\.getElementsByClassName|document\.querySelector|document\.forms" $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "crypt|rc4|arcfour|md5|sha1|sha-1|TripleDES|Math\.random\(" $p \
        && echo -e "${YELLOW}Bad Cryptography Practices [+]${NOCOLOR}" \
        && grep -n -E --color=always "crypt|rc4|arcfour|md5|sha1|sha-1|TripleDES|Math\.random\(" $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $p \
        && echo -e "${YELLOW}Finding Hardcoded IP Addresses [+]${NOCOLOR}" \
        && grep -n -E --color=always "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "SQL|query\(" $p \
        && echo -e "${YELLOW}Potential SQL Injection [+]${NOCOLOR}" \
        && grep -n -E --color=always "SQL|query\(" $p \
        #&&echo "---------------------------------------------------"

        grep -q -E --color=always "eval\(" $p \
        && echo -e "${YELLOW}Remote Code Execution if User Input is sent [+]${NOCOLOR}" \
        && grep -n -E --color=always "eval\(" $p \
        #&& echo "---------------------------------------------------"

        grep -q -E --color=always "NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized|insecure|strictSSL|clientPemCrtSignedBySelfSignedRootCaBuffer" $p \
        && echo -e "${YELLOW}Certificate Checking Disabled [+]${NOCOLOR}" \
        && grep -n -E --color=always "NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized|insecure|strictSSL|clientPemCrtSignedBySelfSignedRootCaBuffer" $p
        
        #echo "***************************************************"
        echo "===================================================="
    fi
done

