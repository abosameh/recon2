#!/bin/bash

#Colors Output
NORMAL="\e[0m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"

# Define the target domain
target=$1
dirdomain=$(printf $target | awk -F[.] '{print $1}')
subdomains_live="${dirdomain}/subdomains/livesubdomain.txt"
CMSresult="${dirdomain}/info/CMSresult.txt"
Serverresult="${dirdomain}/info/Serverresult.txt"
websites_file="$subdomains_live" 
if [ ! -f "$subdomains_live" ]; then
    echo "Websites file not found: $subdomains_live"
    exit 1
fi

# Initialize result files
> "$CMSresult"
> "$Serverresult"

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

    server_info=$(curl -I "$website" 2>&1 | grep -i 'server:')
    if [ -z "$server_info" ]; then
        server_info="Unknown"
    fi

    echo -ne "[+]${GREEN}$website${YELLOW}   CMS: $cms   $server_info\n"
    echo -ne "$website   CMS: $cms   Server: $server_info\n" >> "$Serverresult"
done < "$subdomains_live"
