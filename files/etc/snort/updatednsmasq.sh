#!/bin/bash
# Update DNSMASQ to block known malicious URLs
echo "Downloading Updated DNSMASQ rules"
wget -O /etc/snort/rules/bad-domains.txt https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt
wget -O /etc/snort/rules/bad-hostnames.txt https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt

echo "Restarting DNSMASQ..."
/etc/init.d/dnsmasq restart
echo "DNSMASQ has been Restarted...  Please wait 20 seconds for it to initialize!"
sleep 20
