#!/bin/bash

# Add base paths and tool directories
TOOLS_DIR="$HOME/tools"
WORDLISTS_DIR="$HOME/wordlists"

# Add error handling for required tools
check_requirements() {
    local tools=("subfinder" "assetfinder" "findomain" "amass" "httpx" "nuclei" "naabu")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "Error: $tool is not installed"
            exit 1
        fi
    done
}

# Add logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "${dirdomain}/scan.log"
}

# Add progress tracking
progress() {
    echo -ne "\r[+] $1: $2%"
}

# Add cleanup function
cleanup() {
    echo "Cleaning up..."
    kill $(jobs -p) 2>/dev/null
    exit
}

trap cleanup SIGINT SIGTERM

# Add file checking function
check_file() {
    if [ ! -f "$1" ]; then
        echo "Error: File $1 not found"
        return 1
    fi
    if [ ! -s "$1" ]; then
        echo "Warning: File $1 is empty"
        return 1
    fi
    return 0
}

# Input validation
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Validate domain format
if ! echo "$1" | grep -P "^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$" > /dev/null; then
    echo "Error: Invalid domain format"
    exit 1
fi

# Colors Output
NORMAL="\e[0m"			
RED="\033[0;31m" 		
GREEN="\033[0;32m"		   
BOLD="\033[01;01m"    	
WHITE="\033[1;37m"		
YELLOW="\033[1;33m"	
LRED="\033[1;31m"		
LGREEN="\033[1;32m"		
LBLUE="\033[1;34m"			
LCYAN="\033[1;36m"		
SORANGE="\033[0;33m"		      		
DGRAY="\033[1;30m"		
DSPACE="  "
CTAB="\t"
DTAB="\t\t"
TSPACE="   "
TTAB="\t\t\t"
QSPACE="    "
QTAB="\t\t\t\t"
BLINK="\e[5m"
TICK="\u2714"
CROSS="\u274c"

# Define the target domain
target=$1
dirdomain=$(printf $target | awk -F[.] '{print $1}')

# Create required directories
create_directories() {
    local dirs=(
        "${dirdomain}/subdomains/.tmp"
        "${dirdomain}/osint"
        "${dirdomain}/info"
        "${dirdomain}/wordlists"
        "${dirdomain}/fuzzing"
        "${dirdomain}/parameters"
        "${dirdomain}/vulnerability"
        "${dirdomain}/screenshots"
        "${dirdomain}/patterns"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done
}

# Call directory creation
create_directories

# Check requirements
check_requirements

# Rest of your existing variable definitions...

# Add these new tool paths and outputs
cmseek_output="${dirdomain}/vulnerability/cmseek.txt"
dirsearch_output="${dirdomain}/fuzzing/dirsearch.txt"
gospider_output="${dirdomain}/parameters/gospider.txt"
meg_output="${dirdomain}/parameters/meg.txt"
unfurl_output="${dirdomain}/parameters/unfurl.txt"
gau_plus_output="${dirdomain}/parameters/gauplus.txt"
chaos_output="${dirdomain}/subdomains/chaos.txt"
dnsx_output="${dirdomain}/subdomains/dnsx.txt"
shodan_output="${dirdomain}/info/shodan.txt"
censys_output="${dirdomain}/info/censys.txt"
subfinder2_output="${dirdomain}/subdomains/subfinder2.txt"
puredns_output="${dirdomain}/subdomains/puredns.txt"
shuffledns_output="${dirdomain}/subdomains/shuffledns.txt"
alterx_output="${dirdomain}/subdomains/alterx.txt"
httpx_probe_output="${dirdomain}/info/httpx_probe.txt"
naabu_output="${dirdomain}/info/naabu_ports.txt"
nuclei_critical="${dirdomain}/vulnerability/nuclei_critical.txt"
nuclei_high="${dirdomain}/vulnerability/nuclei_high.txt"
nuclei_medium="${dirdomain}/vulnerability/nuclei_medium.txt"
katana_output="${dirdomain}/parameters/katana.txt"
gxss_output="${dirdomain}/vulnerability/gxss.txt"
sqlmap_output="${dirdomain}/vulnerability/sqlmap.txt"
whatweb_output="${dirdomain}/info/whatweb.txt"
wafw00f_output="${dirdomain}/info/wafw00f.txt"
eyewitness_output="${dirdomain}/screenshots/eyewitness"
gittools_output="${dirdomain}/osint/gittools"
jsscanner_output="${dirdomain}/vulnerability/jsscanner.txt"
corscanner_output="${dirdomain}/vulnerability/corscanner.txt"
ssrf_scanner="${dirdomain}/vulnerability/ssrf.txt"
prototype_scanner="${dirdomain}/vulnerability/prototype.txt"
webtech_output="${dirdomain}/info/webtech.txt"
arjun_output="${dirdomain}/parameters/arjun.txt"
ffuf_output="${dirdomain}/fuzzing/ffuf.txt"
jaeles_output="${dirdomain}/vulnerability/jaeles.txt"
crlfuzz_output="${dirdomain}/vulnerability/crlfuzz.txt"
xsstrike_output="${dirdomain}/vulnerability/xsstrike.txt"
dalfox_output="${dirdomain}/vulnerability/dalfox.txt"
subjs_output="${dirdomain}/info/subjs.txt"
linkfinder_output="${dirdomain}/info/linkfinder.txt"
secretfinder_output="${dirdomain}/info/secretfinder.txt"
getjs_output="${dirdomain}/info/getjs.txt"
subzy_output="${dirdomain}/vulnerability/subzy.txt"
notify_output="${dirdomain}/info/notify.txt"
axiom_output="${dirdomain}/info/axiom.txt"
amass_passive="${dirdomain}/subdomains/amass_passive.txt"
amass_active="${dirdomain}/subdomains/amass_active.txt"
tlsx_output="${dirdomain}/info/tlsx.txt"
asnmap_output="${dirdomain}/info/asnmap.txt"
clouddetect_output="${dirdomain}/info/clouddetect.txt"
ipcdn_output="${dirdomain}/info/ipcdn.txt"
csprecon_output="${dirdomain}/vulnerability/csprecon.txt"
paramspider_output="${dirdomain}/parameters/paramspider.txt"
gitdorker_output="${dirdomain}/osint/gitdorker.txt"
gitls_output="${dirdomain}/osint/gitls.txt"
dnsvalidator_output="${dirdomain}/info/dnsvalidator.txt"
dnsreaper_output="${dirdomain}/info/dnsreaper.txt"
hakrawler_output="${dirdomain}/parameters/hakrawler.txt"
waybackurls_output="${dirdomain}/parameters/waybackurls.txt"
gf_xss="${dirdomain}/vulnerability/gf_xss.txt"
gf_ssrf="${dirdomain}/vulnerability/gf_ssrf.txt"
gf_redirect="${dirdomain}/vulnerability/gf_redirect.txt"
gf_idor="${dirdomain}/vulnerability/gf_idor.txt"
gf_lfi="${dirdomain}/vulnerability/gf_lfi.txt"
gf_rce="${dirdomain}/vulnerability/gf_rce.txt"
kxss_output="${dirdomain}/vulnerability/kxss.txt"
airixss_output="${dirdomain}/vulnerability/airixss.txt"
cariddi_output="${dirdomain}/vulnerability/cariddi.txt"
nuclei_fuzz="${dirdomain}/vulnerability/nuclei_fuzz.txt"
sqlmap_dump="${dirdomain}/vulnerability/sqlmap_dump"
osmedeus_output="${dirdomain}/vulnerability/osmedeus"
reconftw_output="${dirdomain}/vulnerability/reconftw"
subfinder_config="${dirdomain}/config/subfinder-config.yaml"
amass_config="${dirdomain}/config/amass-config.ini"
httpx_tech="${dirdomain}/info/httpx_tech.txt"
nmap_vuln="${dirdomain}/vulnerability/nmap_vuln.txt"
masscan_output="${dirdomain}/info/masscan.txt"
rustscan_output="${dirdomain}/info/rustscan.txt"
wpscan_output="${dirdomain}/vulnerability/wpscan.txt"
joomscan_output="${dirdomain}/vulnerability/joomscan.txt"
droopescan_output="${dirdomain}/vulnerability/droopescan.txt"
nikto_output="${dirdomain}/vulnerability/nikto.txt"
wapiti_output="${dirdomain}/vulnerability/wapiti.txt"
zap_output="${dirdomain}/vulnerability/zap.txt"
xray_output="${dirdomain}/vulnerability/xray.txt"
feroxbuster_output="${dirdomain}/fuzzing/feroxbuster.txt"
gobuster_output="${dirdomain}/fuzzing/gobuster.txt"
dirb_output="${dirdomain}/fuzzing/dirb.txt"
arachni_output="${dirdomain}/vulnerability/arachni"
skipfish_output="${dirdomain}/vulnerability/skipfish"
w3af_output="${dirdomain}/vulnerability/w3af"
vega_output="${dirdomain}/vulnerability/vega"
acunetix_output="${dirdomain}/vulnerability/acunetix"
burp_output="${dirdomain}/vulnerability/burp"
netsparker_output="${dirdomain}/vulnerability/netsparker"
qualys_output="${dirdomain}/vulnerability/qualys"
snyk_output="${dirdomain}/vulnerability/snyk"
semgrep_output="${dirdomain}/vulnerability/semgrep"
trufflehog_output="${dirdomain}/vulnerability/trufflehog"
subfinder_passive="${dirdomain}/subdomains/subfinder_passive.txt"
subfinder_recursive="${dirdomain}/subdomains/subfinder_recursive.txt"
github_subdomains="${dirdomain}/subdomains/github_subdomains.txt"
gitlab_subdomains="${dirdomain}/subdomains/gitlab_subdomains.txt"
cero="${dirdomain}/subdomains/cero.txt"
analyticsrelationships="${dirdomain}/subdomains/analyticsrelationships.txt"
dnsprobe_output="${dirdomain}/info/dnsprobe.txt"
mapcidr_output="${dirdomain}/info/mapcidr.txt"
cdncheck_output="${dirdomain}/info/cdncheck.txt"
interactsh_output="${dirdomain}/vulnerability/interactsh.txt"
notify_discord="${dirdomain}/notifications/discord.txt"
notify_slack="${dirdomain}/notifications/slack.txt"
notify_telegram="${dirdomain}/notifications/telegram.txt"

# Modified check_and_download function with error handling
check_and_download() {
    local file_path="$1"
    local download_url="$2"
    local file_name="${file_path##*/}"

    if [ -f "$file_path" ]; then
        log "File $file_name already exists"
        return 0
    fi

    if ! curl -# -o "$file_path" "$download_url"; then
        log "Error downloading $file_name"
        return 1
    fi

    log "Successfully downloaded $file_name"
    printf "Downloaded $file_name\n"
}

# Modified scan_subdomains function with progress tracking and error handling
scan_subdomains() {
    log "Starting subdomain enumeration"
    total=100
    current=0
    
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Starting subdomain enumeration for ${YELLOW}$target${NORMAL}\n"
    
    # Subfinder
    progress "Subfinder" $current
    if subfinder -silent -d $target -all -o ${dirdomain}/subdomains/subfinder.txt 2>/dev/null; then
        current=$((current + 20))
        progress "Subdomain Enumeration" $current
        log "Subfinder completed successfully"
    else
        log "Error running subfinder"
    fi

    # Add Chaos scanner
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}chaos${NORMAL}]"
    chaos -d $target -silent | anew -q ${dirdomain}/subdomains/chaos.txt
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}chaos${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/chaos.txt 2> /dev/null | wc -l)"

    # Add DNSx enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] DNS Enumeration  -  ${NORMAL}[${LRED}${BLINK}dnsx${NORMAL}]"
    cat ${dirdomain}/subdomains/subdomains.txt | dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -resp -json -o $dnsx_output

    # Add puredns for subdomain enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}puredns${NORMAL}]"
    puredns bruteforce $wordlists/subdomain_megalist.txt $target -r $wordlists/resolvers.txt -w $puredns_output &> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}puredns${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/puredns.txt 2> /dev/null | wc -l)"

    # Add shuffledns for subdomain enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}shuffledns${NORMAL}]"
    shuffledns -d $target -w $wordlists/subdomain_megalist.txt -r $wordlists/resolvers.txt -o $shuffledns_output &> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}shuffledns${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/shuffledns.txt 2> /dev/null | wc -l)"

    # Add alterx for subdomain enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}alterx${NORMAL}]"
    cat ${dirdomain}/subdomains/subdomains.txt | alterx -silent > $alterx_output
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}alterx${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/alterx.txt 2> /dev/null | wc -l)"

    # Add httpx probing
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Probing with httpx  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/subdomains/subdomains.txt | httpx -silent -td -probe -title -location -fhr >> $httpx_probe_output

    # Add Subzy for subdomain takeover
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Checking Subdomain Takeover  -  ${NORMAL}[${LRED}${BLINK}Subzy${NORMAL}]"
    subzy run --targets ${dirdomain}/subdomains/subdomains.txt --hide_fails --verify_ssl -timeout 30 | anew -q $subzy_output

    # Add Amass passive and active scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Amass Passive  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    amass enum -passive -d $target -o $amass_passive &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Amass Active  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    amass enum -active -d $target -o $amass_active &>/dev/null

    # Add TLS/SSL scanning with tlsx
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] TLS/SSL Scanning  -  ${NORMAL}[${LRED}${BLINK}tlsx${NORMAL}]"
    tlsx -l ${dirdomain}/subdomains/subdomains.txt -o $tlsx_output &>/dev/null

    # Add Osmedeus scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Osmedeus Scan  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    osmedeus scan -t $target -w general -o $osmedeus_output &>/dev/null
    # Add passive subfinder scan
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Passive Subfinder  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    subfinder -d $target -silent -sources passive -o $subfinder_passive &>/dev/null

    # Add recursive subfinder scan
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Recursive Subfinder  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    subfinder -d $target -silent -recursive -o $subfinder_recursive &>/dev/null

    # Add GitHub subdomain enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] GitHub Subdomain Enumeration  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    github-subdomains -d $target -t $GITHUB_TOKEN -o $github_subdomains &>/dev/null

    # Add GitLab subdomain enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] GitLab Subdomain Enumeration  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    gitlab-subdomains -d $target -t $GITLAB_TOKEN -o $gitlab_subdomains &>/dev/null

    # Add Cero subdomain enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Cero  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cero $target -o $cero &>/dev/null

    # Add Analytics Relationships
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Checking Analytics Relationships  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    analyticsrelationships -d $target -o $analyticsrelationships &>/dev/null

    log "Completed subdomain enumeration"
}

# Modified get_endpoints function with progress tracking and error handling
get_endpoints() {
    log "Starting endpoint enumeration"
    
    if ! check_file "${dirdomain}/subdomains/livesubdomain.txt"; then
        echo "No live subdomains found. Running subdomain scan first..."
        scan_subdomains
    fi
    
    # Add GoSpider crawler
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Crawling with GoSpider  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    gospider -S ${dirdomain}/subdomains/livesubdomain.txt -o $gospider_output -t 50 -c 10 -d 3 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|svg)"

    # Add meg for path probing
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Path Probing with meg  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    meg -d 1000 -c 50 /api ${dirdomain}/subdomains/livesubdomain.txt $meg_output

    # Add unfurl for parameter extraction
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Extracting Parameters  -  ${NORMAL}[${LRED}${BLINK}unfurl${NORMAL}]"
    cat ${dirdomain}/parameters/endpoints.txt | unfurl -u format %s://%d%p | anew -q $unfurl_output

    # Add katana crawler
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Crawling with Katana  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    katana -list ${dirdomain}/subdomains/livesubdomain.txt -jc -kf all -c 50 -d 3 -o $katana_output &>/dev/null

    # Add gau plus for URL discovery
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] URL Discovery with GAU  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/subdomains/livesubdomain.txt | gauplus --random-agent -b eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,pdf,svg,txt -o $gau_plus_output &>/dev/null

    # Add Arjun parameter discovery
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Parameter Discovery with Arjun  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    for url in $(cat ${dirdomain}/subdomains/livesubdomain.txt); do
        arjun -u $url -oT $arjun_output
    done

    # Add ffuf directory fuzzing
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Directory Fuzzing with ffuf  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    for url in $(cat ${dirdomain}/subdomains/livesubdomain.txt); do
        ffuf -u "${url}/FUZZ" -w $fuzz_file -mc 200,204,301,302,307,401,403 -o $ffuf_output
    done

    # Add JavaScript analysis tools
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Extracting JavaScript Files  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/subdomains/livesubdomain.txt | subjs | tee -a $subjs_output
    cat ${dirdomain}/subdomains/livesubdomain.txt | getJS --complete | tee -a $getjs_output
    
    # Add LinkFinder for endpoint discovery in JS
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Analyzing JavaScript with LinkFinder  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    for js in $(cat $subjs_output); do
        python3 $TOOLS_DIR/LinkFinder/linkfinder.py -i $js -o cli | tee -a $linkfinder_output
    done

    # Add SecretFinder for sensitive data in JS
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Searching Secrets in JavaScript  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    for js in $(cat $subjs_output); do
        python3 $TOOLS_DIR/SecretFinder/SecretFinder.py -i $js -o cli | tee -a $secretfinder_output
    done

    # Add ParamSpider
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Parameter Discovery with ParamSpider  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    python3 $TOOLS_DIR/ParamSpider/paramspider.py -d $target -o $paramspider_output &>/dev/null

    # Add GitDorker
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] GitHub Dork Scanning  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    python3 $TOOLS_DIR/GitDorker/GitDorker.py -t $GITHUB_TOKEN -d $target -o $gitdorker_output &>/dev/null

    # Add gitls
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Git Repo Scanning  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    gitls -d $target -o $gitls_output &>/dev/null

    # Add hakrawler crawler
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Crawling with hakrawler  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/subdomains/livesubdomain.txt | hakrawler -depth 3 -plain | anew -q $hakrawler_output

    # Add waybackurls
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Fetching Wayback URLs  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/subdomains/livesubdomain.txt | waybackurls | anew -q $waybackurls_output
}

# Modified check_vulnerabilities function with improved error handling
check_vulnerabilities() {
    log "Starting vulnerability checks"
    
    if ! check_file "${dirdomain}/subdomains/livesubdomain.txt"; then
        echo "No live subdomains found. Cannot proceed with vulnerability checks."
        return 1
    fi
    
    # Add CMSeeK scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Scanning CMS  -  ${NORMAL}[${LRED}${BLINK}CMSeeK${NORMAL}]"
    for url in $(cat ${dirdomain}/subdomains/livesubdomain.txt); do
        python3 $TOOLS_DIR/CMSeeK/cmseek.py -u $url --batch -r >> $cmseek_output
    done

    # Add dirsearch for directory fuzzing
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Directory Fuzzing  -  ${NORMAL}[${LRED}${BLINK}dirsearch${NORMAL}]"
    for url in $(cat ${dirdomain}/subdomains/livesubdomain.txt); do
        dirsearch -u $url -w $fuzz_file -o $dirsearch_output -t 50 -e php,asp,aspx,jsp,html,zip,jar
    done

    # Add nuclei scanning by severity
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Nuclei Critical Scans  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    nuclei -l ${dirdomain}/subdomains/livesubdomain.txt -t nuclei-templates -severity critical -o $nuclei_critical &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Nuclei High Scans  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    nuclei -l ${dirdomain}/subdomains/livesubdomain.txt -t nuclei-templates -severity high -o $nuclei_high &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Nuclei Medium Scans  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    nuclei -l ${dirdomain}/subdomains/livesubdomain.txt -t nuclei-templates -severity medium -o $nuclei_medium &>/dev/null

    # Add gxss scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] XSS Scanning with gxss  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/parameters/endpoints.txt | gxss -c 100 -p Xss | grep "=" | qsreplace '"><svg onload=confirm(1)>' | while read url; do
        curl -s -L "$url" | grep -qs "<svg onload=confirm(1)>" && echo "$url" >> $gxss_output
    done

    # Add SQLMap scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] SQL Injection Scanning  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    for url in $(cat ${dirdomain}/parameters/endpoints.txt | grep "="); do
        sqlmap -u "$url" --batch --random-agent --level 1 --risk 1 >> $sqlmap_output
    done

    # Add naabu port scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Port Scanning with Naabu  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    naabu -list ${dirdomain}/subdomains/livesubdomain.txt -p $ports -c 50 -o $naabu_output &>/dev/null

    # Add WhatWeb scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Technology Detection with WhatWeb  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    whatweb -i ${dirdomain}/subdomains/livesubdomain.txt --quiet --no-errors > $whatweb_output

    # Add WAF detection
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] WAF Detection with wafw00f  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    wafw00f -i ${dirdomain}/subdomains/livesubdomain.txt -o $wafw00f_output

    # Add EyeWitness for visual recon
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Visual Recon with EyeWitness  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    eyewitness --web --threads 10 --file ${dirdomain}/subdomains/livesubdomain.txt --d $eyewitness_output

    # Add Webtech scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Technology Stack Detection  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    webtech -l ${dirdomain}/subdomains/livesubdomain.txt > $webtech_output

    # Add JS Scanner
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] JavaScript Analysis  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    for js in $(cat ${dirdomain}/info/js.txt); do
        python3 $TOOLS_DIR/JSScanner/scanner.py --url $js --enable-all >> $jsscanner_output
    done

    # Add CORS Scanner
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] CORS Misconfiguration Check  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    python3 $TOOLS_DIR/CORSScanner/cors_scan.py -i ${dirdomain}/subdomains/livesubdomain.txt -t 50 >> $corscanner_output

    # Add SSRF Scanner
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] SSRF Testing  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/parameters/endpoints.txt | grep "=" | qsreplace "http://169.254.169.254/latest/meta-data/" | while read url; do
        curl -s -L "$url" | grep -q "ami-id" && echo "$url" >> $ssrf_scanner
    done

    # Add Prototype Pollution Scanner
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Prototype Pollution Testing  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    for url in $(cat ${dirdomain}/parameters/endpoints.txt); do
        ppfuzz -u "$url" -t 30 >> $prototype_scanner
    done

    # Add Jaeles scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Scanning with Jaeles  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    jaeles scan -s /root/.jaeles/base-signatures -U ${dirdomain}/subdomains/livesubdomain.txt -o $jaeles_output

    # Add CRLF injection scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Checking CRLF Injection  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    crlfuzz -l ${dirdomain}/subdomains/livesubdomain.txt -o $crlfuzz_output

    # Add XSStrike scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Advanced XSS Scanning  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    for url in $(cat ${dirdomain}/parameters/endpoints.txt | grep "="); do
        python3 $TOOLS_DIR/XSStrike/xsstrike.py -u "$url" --file $xsstrike_output
    done

    # Add Dalfox XSS scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] XSS Scanning with Dalfox  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/parameters/endpoints.txt | dalfox pipe --skip-bav --skip-mining-dom --skip-mining-dict -o $dalfox_output

    # Add CSP Scanner
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] CSP Misconfiguration Check  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    python3 $TOOLS_DIR/CSPRecon/csprecon.py -i ${dirdomain}/subdomains/livesubdomain.txt -o $csprecon_output &>/dev/null

    # Add DNS Validator
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] DNS Validation  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    dnsvalidator -tL ${dirdomain}/subdomains/subdomains.txt -o $dnsvalidator_output &>/dev/null

    # Add DNS Reaper
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] DNS Security Check  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    dnsreaper -d $target -o $dnsreaper_output &>/dev/null

    # Add GF pattern scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running GF Pattern Scans  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/parameters/endpoints.txt | gf xss | anew -q $gf_xss
    cat ${dirdomain}/parameters/endpoints.txt | gf ssrf | anew -q $gf_ssrf
    cat ${dirdomain}/parameters/endpoints.txt | gf redirect | anew -q $gf_redirect
    cat ${dirdomain}/parameters/endpoints.txt | gf idor | anew -q $gf_idor
    cat ${dirdomain}/parameters/endpoints.txt | gf lfi | anew -q $gf_lfi
    cat ${dirdomain}/parameters/endpoints.txt | gf rce | anew -q $gf_rce

    # Add kxss scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] XSS Scanning with kxss  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat $gf_xss | kxss | anew -q $kxss_output

    # Add Airixss scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] XSS Scanning with Airixss  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat $gf_xss | airixss -payload "alert(1)" | anew -q $airixss_output

    # Add Cariddi scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] JavaScript Analysis with Cariddi  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/subdomains/livesubdomain.txt | cariddi -intensive | anew -q $cariddi_output

    # Add Nuclei Fuzzing
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Fuzzing with Nuclei  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    nuclei -l ${dirdomain}/subdomains/livesubdomain.txt -t nuclei-templates/fuzzing -o $nuclei_fuzz

    # Enhanced SQLMap scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Advanced SQL Injection Scanning  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    mkdir -p $sqlmap_dump
    for url in $(cat ${dirdomain}/parameters/endpoints.txt | grep "="); do
        sqlmap -u "$url" --batch --random-agent --level 5 --risk 3 --threads 10 \
        --dump-all --flush-session \
        --tamper=space2comment,between,randomcase \
        --output-dir=$sqlmap_dump
    done

    # Add Nmap vulnerability scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Nmap Vuln Scan  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    nmap -sV -Pn --script vuln -iL ${dirdomain}/info/ips.txt -oA $nmap_vuln &>/dev/null

    # Add CMS scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] WordPress Scanning  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    wpscan --url $target --api-token YOUR_TOKEN --random-user-agent --enumerate vp,vt,cb,dbe --output $wpscan_output &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Joomla Scanning  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    joomscan --url $target --ec --random-agent --output $joomscan_output &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Drupal Scanning  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    droopescan scan drupal -u $target -t 10 -o $droopescan_output &>/dev/null

    # Add Web Application scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Nikto Scan  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    nikto -h $target -output $nikto_output &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Wapiti Scan  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    wapiti -u $target -f txt -o $wapiti_output &>/dev/null

    # Add OWASP ZAP scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running ZAP Scan  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' -o $zap_output $target &>/dev/null

    # Add Xray scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Xray Scan  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    xray webscan --url $target --html-output $xray_output &>/dev/null

    # Add directory fuzzing tools
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Feroxbuster  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    feroxbuster --url $target --silent --depth 2 --wordlist $fuzz_file -o $feroxbuster_output &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Gobuster  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    gobuster dir -u $target -w $fuzz_file -q -o $gobuster_output &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Dirb  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    dirb $target $fuzz_file -o $dirb_output -S &>/dev/null

    # Add commercial web scanners (if available)
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Arachni  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    arachni $target --output-directory=$arachni_output &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Skipfish  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    skipfish -o $skipfish_output $target &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running W3AF  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    w3af_console -s $w3af_output $target &>/dev/null

    # Add secret scanning tools
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Trufflehog  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    trufflehog filesystem ${dirdomain} --json > $trufflehog_output &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Semgrep  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    semgrep scan --config=auto ${dirdomain} -o $semgrep_output &>/dev/null

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Snyk  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    snyk test ${dirdomain} --json > $snyk_output &>/dev/null

    # Add Interactsh for OAST testing
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Running Interactsh  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    interactsh-client -v -o $interactsh_output &>/dev/null
}

# Modified generate_report function with markdown output
generate_report() {
    log "Generating report"
    
    {
        echo "# Security Scan Report for $target"
        echo "## Scan Time: $(date)"
        echo "## Summary"
        
        # Add checks for file existence
        for file in "${dirdomain}"/vulnerability/*.txt; do
            if [ -f "$file" ]; then
                count=$(wc -l < "$file")
                name=$(basename "$file" .txt)
                echo "- $name: $count findings"
            fi
        done
        
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} CMS Issues:${NORMAL}${BOLD}${GREEN} $(cat $cmseek_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Directory Fuzzing:${NORMAL}${BOLD}${GREEN} $(cat $dirsearch_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} DNS Records:${NORMAL}${BOLD}${GREEN} $(cat $dnsx_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} WAF Detection:${NORMAL}${BOLD}${GREEN} $(cat $wafw00f_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Tech Stack:${NORMAL}${BOLD}${GREEN} $(cat $webtech_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Parameters Found:${NORMAL}${BOLD}${GREEN} $(cat $arjun_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} JS Vulnerabilities:${NORMAL}${BOLD}${GREEN} $(cat $jsscanner_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} CORS Issues:${NORMAL}${BOLD}${GREEN} $(cat $corscanner_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} SSRF Points:${NORMAL}${BOLD}${GREEN} $(cat $ssrf_scanner 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Prototype Issues:${NORMAL}${BOLD}${GREEN} $(cat $prototype_scanner 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Subdomain Takeover:${NORMAL}${BOLD}${GREEN} $(cat $subzy_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} FFUF Findings:${NORMAL}${BOLD}${GREEN} $(cat $ffuf_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Jaeles Issues:${NORMAL}${BOLD}${GREEN} $(cat $jaeles_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} CRLF Issues:${NORMAL}${BOLD}${GREEN} $(cat $crlfuzz_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} XSStrike Findings:${NORMAL}${BOLD}${GREEN} $(cat $xsstrike_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Dalfox XSS:${NORMAL}${BOLD}${GREEN} $(cat $dalfox_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} JS Endpoints:${NORMAL}${BOLD}${GREEN} $(cat $linkfinder_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} JS Secrets:${NORMAL}${BOLD}${GREEN} $(cat $secretfinder_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Amass Findings:${NORMAL}${BOLD}${GREEN} $(cat $amass_passive $amass_active 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} TLS Issues:${NORMAL}${BOLD}${GREEN} $(cat $tlsx_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} ASN Info:${NORMAL}${BOLD}${GREEN} $(cat $asnmap_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Cloud Infrastructure:${NORMAL}${BOLD}${GREEN} $(cat $clouddetect_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} CDN IPs:${NORMAL}${BOLD}${GREEN} $(cat $ipcdn_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} CSP Issues:${NORMAL}${BOLD}${GREEN} $(cat $csprecon_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} DNS Issues:${NORMAL}${BOLD}${GREEN} $(cat $dnsreaper_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Hakrawler Endpoints:${NORMAL}${BOLD}${GREEN} $(cat $hakrawler_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Wayback URLs:${NORMAL}${BOLD}${GREEN} $(cat $waybackurls_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} GF XSS:${NORMAL}${BOLD}${GREEN} $(cat $gf_xss 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} GF SSRF:${NORMAL}${BOLD}${GREEN} $(cat $gf_ssrf 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} GF Redirect:${NORMAL}${BOLD}${GREEN} $(cat $gf_redirect 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} GF IDOR:${NORMAL}${BOLD}${GREEN} $(cat $gf_idor 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} GF LFI:${NORMAL}${BOLD}${GREEN} $(cat $gf_lfi 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} GF RCE:${NORMAL}${BOLD}${GREEN} $(cat $gf_rce 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} KXSS Findings:${NORMAL}${BOLD}${GREEN} $(cat $kxss_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Airixss Findings:${NORMAL}${BOLD}${GREEN} $(cat $airixss_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Cariddi Issues:${NORMAL}${BOLD}${GREEN} $(cat $cariddi_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Nuclei Fuzzing:${NORMAL}${BOLD}${GREEN} $(cat $nuclei_fuzz 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Osmedeus Findings:${NORMAL}${BOLD}${GREEN} $(find $osmedeus_output -type f -exec cat {} \; 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} ReconFTW Findings:${NORMAL}${BOLD}${GREEN} $(find $reconftw_output -type f -exec cat {} \; 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Nmap Vulnerabilities:${NORMAL}${BOLD}${GREEN} $(cat $nmap_vuln.nmap 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} WordPress Issues:${NORMAL}${BOLD}${GREEN} $(cat $wpscan_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Joomla Issues:${NORMAL}${BOLD}${GREEN} $(cat $joomscan_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Drupal Issues:${NORMAL}${BOLD}${GREEN} $(cat $droopescan_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Nikto Findings:${NORMAL}${BOLD}${GREEN} $(cat $nikto_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Wapiti Issues:${NORMAL}${BOLD}${GREEN} $(cat $wapiti_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} ZAP Findings:${NORMAL}${BOLD}${GREEN} $(cat $zap_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Xray Issues:${NORMAL}${BOLD}${GREEN} $(cat $xray_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Feroxbuster:${NORMAL}${BOLD}${GREEN} $(cat $feroxbuster_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Gobuster:${NORMAL}${BOLD}${GREEN} $(cat $gobuster_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Dirb:${NORMAL}${BOLD}${GREEN} $(cat $dirb_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Arachni:${NORMAL}${BOLD}${GREEN} $(find $arachni_output -type f -exec cat {} \; 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Skipfish:${NORMAL}${BOLD}${GREEN} $(find $skipfish_output -type f -exec cat {} \; 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} W3AF:${NORMAL}${BOLD}${GREEN} $(find $w3af_output -type f -exec cat {} \; 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Trufflehog:${NORMAL}${BOLD}${GREEN} $(cat $trufflehog_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Semgrep:${NORMAL}${BOLD}${GREEN} $(cat $semgrep_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Snyk:${NORMAL}${BOLD}${GREEN} $(cat $snyk_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Passive Subfinder:${NORMAL}${BOLD}${GREEN} $(cat $subfinder_passive 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Recursive Subfinder:${NORMAL}${BOLD}${GREEN} $(cat $subfinder_recursive 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} GitHub Subdomains:${NORMAL}${BOLD}${GREEN} $(cat $github_subdomains 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} GitLab Subdomains:${NORMAL}${BOLD}${GREEN} $(cat $gitlab_subdomains 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Cero Findings:${NORMAL}${BOLD}${GREEN} $(cat $cero 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Analytics Relations:${NORMAL}${BOLD}${GREEN} $(cat $analyticsrelationships 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} DNSProbe Records:${NORMAL}${BOLD}${GREEN} $(cat $dnsprobe_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} MapCIDR Results:${NORMAL}${BOLD}${GREEN} $(cat $mapcidr_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} CDN IPs:${NORMAL}${BOLD}${GREEN} $(cat $cdncheck_output 2> /dev/null | wc -l)${NORMAL}\n"
        echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Interactsh Findings:${NORMAL}${BOLD}${GREEN} $(cat $interactsh_output 2> /dev/null | wc -l)${NORMAL}\n"
    } > "${dirdomain}/report.md"
    
    log "Report generated successfully"
}

# Modified main menu with error handling
while true; do
    echo -ne "${GREEN}Please choose an option:${NORMAL}\n"
    echo -ne "${GREEN}#################################\n"
    echo -ne "${GREEN}1. Scan for subdomains${NORMAL}\n"
    echo -ne "${GREEN}2. Get all endpoints${NORMAL}\n"
    echo -ne "${GREEN}3. Get Info of subdomains${NORMAL}\n"
    echo -ne "${GREEN}4. Get IPs of subdomains${NORMAL}\n"
    echo -ne "${GREEN}5. Check for vulnerabilities${NORMAL}\n"
    echo -ne "${GREEN}6. Generate a full report${NORMAL}\n"
    echo -ne "${GREEN}7. Full Recon${NORMAL}\n"
    echo -ne "${GREEN}8. Exit${NORMAL}\n"
    echo -ne "${GREEN}#################################\n"
    
    read -p "Enter your choice (1-8): " choice
    
    case $choice in
        1) scan_subdomains ;;
        2) get_endpoints ;;
        3) get_info ;;
        4) get_ips ;;
        5) check_vulnerabilities ;;
        6) generate_report ;;
        7) full_recon ;;
        8) cleanup ;;
        *) echo "Invalid option. Please try again." ;;
    esac
done
