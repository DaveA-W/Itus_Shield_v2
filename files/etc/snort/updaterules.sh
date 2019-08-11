#!/bin/sh

# Prepare /tmp/snort/ and counts.log
if [ ! -d "/tmp/snort" ] ; then	mkdir /tmp/snort ; else	rm -rf /tmp/snort/* ; fi
cd /tmp/snort
echo " "
echo "# Rules  Downloaded set, via etc/snort/updaterules"                   > counts.log
echo "-------- -----------------------------------------"                  >> counts.log

# Start downloads - comment out any sections if they begin to fail
echo "Downloading snort rule sets to /tmp/snort ..."
echo " "

# NOTE: Snort Community Rules ~1.7MB location uses a 302 redirect to Amazon S3 bucket
curl -k -1 -m 120 -o community-rules.tar.gz -L https://www.snort.org/downloads/community/community-rules.tar.gz
tar x -z -f community-rules.tar.gz
cat community-rules/*.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'community-rules'" }' >> counts.log

# Emerging Threats https://rules.emergingthreats.net/open/snort-edge/rules/

# BotCC
# Detect hosts communicating with a known and active Bot or Malware command and control server.
curl -k -1 -m 40 -o emerging-botcc.portgrouped.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-botcc.portgrouped.rules
cat emerging-botcc.portgrouped.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-botcc.portgrouped.rules'" }' >> counts.log

curl -k -1 -m 40 -o botcc.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-botcc.rules
cat botcc.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-botcc.rules'" }' >> counts.log

# CIArmy
# Subset of CINS Active Threat Intelligence rules, where an IP's 'Rogue Packet' score is poor or it has tripped a number of trusted alerts around the world.
curl -k -1 -m 40 -o emerging-ciarmy.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-ciarmy.rules
cat emerging-ciarmy.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-ciarmy.rules'" }' >> counts.log

# Compromised
# Hosts compromised by bots, phishing sites, or spewing hostile traffic. These are not your everyday infected and sending a bit of spam hosts, these are significantly infected and hostile hosts.
curl -k -1 -m 40 -o emerging-compromised.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-compromised.rules
cat emerging-compromised.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-compromised.rules'" }' >> counts.log

# Dshield
# Daily list of the top attackers reported to www.dshield.org
curl -k -1 -m 40 -o emerging-dshield.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-dshield.rules
cat emerging-dshield.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-dshield.rules'" }' >> counts.log

# Exploits
# Detect direct exploits including Windows exploits, Veritas, etc.
curl -k -1 -m 40 -o emerging-exploit.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-exploit.rules
cat emerging-exploit.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-exploit.rules'" }' >> counts.log

# Malware
# Spyware and other things you don't want running on your network. URL hooks for known update schemes, User-Agent strings of known malware, and a load of other goodies.
curl -k -1 -m 40 -o emerging-malware.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-malware.rules
cat emerging-malware.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-malware.rules'" }' >> counts.log

# Mobile Malware
curl -k -1 -m 40 -o emerging-mobile_malware.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-mobile_malware.rules
cat emerging-mobile_malware.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1"\t", "'emerging-mobile_malware.rules'" }' >> counts.log

# User Agents
curl -k -1 -m 40 -o emerging-user_agents.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-user_agents.rules
cat emerging-user_agents.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-user_agents.rules'" }' >> counts.log

# Web Clients
curl -k -1 -m 40 -o emerging-web_client.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-web_client.rules
cat emerging-web_client.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-web_client.rules'" }' >> counts.log

# Worms
curl -k -1 -m 40 -o emerging-worm.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-worm.rules
cat emerging-worm.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-worm.rules'" }' >> counts.log

# Current Events
# Most often simple sigs for the Storm binary URL of the day, sigs to catch CLSIDs of newly found vulnerable apps where we don't have detail on the exploit.
# Useful sigs but not for the long term until they have been properly tested.
# (file size is ~1.5MB - increase timeout to 120 seconds)
curl -k -1 -m 120 -o emerging-current_events.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-current_events.rules
cat emerging-current_events.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'emerging-current_events.rules'"}' >> counts.log

# Trojans
# (file size is ~4MB - increase timeout to 120 seconds)
curl -k -1 -m 120 -o emerging-trojan.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-trojan.rules
cat emerging-trojan.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "emerging-trojan.rules" }' >> counts.log

# Spamhaus Drops
# Rules to block networks listed as DROP by www.spamhaus.org
curl -k -1 -m 40 -o emerging-drop.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-drop.rules
cat emerging-drop.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "emerging-drop.rules" }' >> counts.log

# Web Specific Apps			** commented out in fw_upgrade? **
#  curl -k -1 -m 40 -o emerging-web_specific_apps.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-web_specific_apps.rules
#  cat emerging-web_specific_apps.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
#  wc -l < alert.tmp | awk  '{print  $1,"\t", "emerging-web_specific_apps.rules" }' >> counts.log

# Scans
curl -k -1 -m 40 -o emerging-scan.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-scan.rules
cat emerging-scan.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "emerging-scan.rules" }' >> counts.log

# SSL Blacklist
# Bad SSL certificates identified by abuse.ch to be associated with malware or botnet activities in the past 30 days.
curl -k -1 -m 40 -o abuse-sslbl.rules https://sslbl.abuse.ch/blacklist/sslipblacklist.rules
cat abuse-sslbl.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
wc -l < alert.tmp | awk  '{print  $1,"\t", "'sslipblacklist.rules'" }' >> counts.log

# SSL Aggressive
# Bad SSL certificates *ever* identified by abuse.ch to be associated with malware or botnet activities.
# Since IP addresses can change, may contain false positives.
#  curl -k -1 -m 40 -o abuse-dyre.rules https://sslbl.abuse.ch/blacklist/dyre_sslipblacklist_aggressive.rules
#  cat abuse-dyre.rules | sed '/^\#/d' | sed '/^$/d' > alert.tmp
#  wc -l < alert.tmp | awk  '{print  $1, "'dyre_sslipblacklist_aggressive.rules'" }'  >> counts.log

# DISCONTINUED 2019-07-08 per https://zeustracker.abuse.ch/byebye.php?download=snort
# ZeuS command and control servers
# curl -k -1 -m 40 -o /tmp/snort/zeus.rules https://zeustracker.abuse.ch/blocklist.php?download=snort
# cat /tmp/snort/zeus.rules | sed '/^\#/d' | sed '/^$/d' > /tmp/snort/alert.tmp
# wc -l < /tmp/snort/alert.tmp | awk  '{print  $1,"\t", "'zeus.rules'" }' >> /tmp/snort/counts.log

echo " "
echo "Converting alerts to drops"
cat *.rules > alert.list
sed -i 's/alert /drop /' alert.list
sed '/^\#/d' alert.list >> drop.list
sed '/^$/d' drop.list | sort | uniq > drop.sorted

# Snort only allows one sid number, so we have to delete where rules contain multiple revisions
echo "Removing rules with extra sid revision numbers"
cat drop.sorted | awk -F"sid:" '{print $2}' | awk -F";" '{print $1}' | sort | uniq -d > duplicate.sids
> duplicate.sed
for i in $(cat duplicate.sids)
do
	echo "0,/$i/{/$i/d}" >> duplicate.sed
done
cat drop.sorted | awk -F"sid:" '{print $2 $1}' | sort > drop.tmp
sed -i -f duplicate.sed  drop.tmp
sed -i 's/^/sid:/' drop.tmp
cat drop.tmp | awk -F";)" '{print $2 $1}' | sort > drop.sorted
sed -i 's/$/;\)/' drop.sorted

# Searching and removing these ~100 rules takes a couple of minutes
echo "Removing rules determined by ITUS Networks to cause web site issues ..."
sed -i '/sid:2002802/s/^/#/' drop.sorted
sed -i '/sid:2019237/s/^/#/' drop.sorted
sed -i '/sid:2018194/s/^/#/' drop.sorted
sed -i '/sid:2012251/s/^/#/' drop.sorted
sed -i '/sid:2100527/s/^/#/' drop.sorted
sed -i '/sid:2100649/s/^/#/' drop.sorted
sed -i '/sid:2009080/s/^/#/' drop.sorted
sed -i '/sid:2009205/s/^/#/' drop.sorted
sed -i '/sid:2009206/s/^/#/' drop.sorted
sed -i '/sid:2009207/s/^/#/' drop.sorted
sed -i '/sid:2009208/s/^/#/' drop.sorted
sed -i '/sid:2008975/s/^/#/' drop.sorted
sed -i '/sid:2010515/s/^/#/' drop.sorted
sed -i '/sid:2003099/s/^/#/' drop.sorted
sed -i '/sid:2101201/s/^/#/' drop.sorted
sed -i '/sid:2001689/s/^/#/' drop.sorted
sed -i '/sid:2011695/s/^/#/' drop.sorted
sed -i '/sid:2013359/s/^/#/' drop.sorted
sed -i '/sid:2013358/s/^/#/' drop.sorted
sed -i '/sid:2013357/s/^/#/' drop.sorted
sed -i '/sid:2013355/s/^/#/' drop.sorted
sed -i '/sid:2013354/s/^/#/' drop.sorted
sed -i '/sid:2013353/s/^/#/' drop.sorted
sed -i '/sid:2013360/s/^/#/' drop.sorted
sed -i '/sid:2100648/s/^/#/' drop.sorted
sed -i '/sid:2009080/s/^/#/' drop.sorted
sed -i '/sid:2101390/s/^/#/' drop.sorted
sed -i '/sid:2012086/s/^/#/' drop.sorted
sed -i '/sid:2100650/s/^/#/' drop.sorted
sed -i '/sid:2011803/s/^/#/' drop.sorted
sed -i '/sid:2012510/s/^/#/' drop.sorted
sed -i '/sid:2001219/s/^/#/' drop.sorted
sed -i '/sid:2003068/s/^/#/' drop.sorted
sed -i '/sid:2002995/s/^/#/' drop.sorted
sed -i '/sid:2011347/s/^/#/' drop.sorted
sed -i '/sid:2102925/s/^/#/' drop.sorted
sed -i '/sid:2012263/s/^/#/' drop.sorted
sed -i '/sid:2012848/s/^/#/' drop.sorted
sed -i '/sid:2001046/s/^/#/' drop.sorted
sed -i '/sid:2003055/s/^/#/' drop.sorted
sed -i '/sid:2002993/s/^/#/' drop.sorted
sed -i '/sid:2002992/s/^/#/' drop.sorted
sed -i '/sid:2001353/s/^/#/' drop.sorted
sed -i '/sid:2009205/s/^/#/' drop.sorted
sed -i '/sid:2009206/s/^/#/' drop.sorted
sed -i '/sid:2009207/s/^/#/' drop.sorted
sed -i '/sid:2009208/s/^/#/' drop.sorted
sed -i '/sid:2001046/s/^/#/' drop.sorted
sed -i '/sid:2016950/s/^/#/' drop.sorted
sed -i '/sid:2019509/s/^/#/' drop.sorted
sed -i '/sid:2011507/s/^/#/' drop.sorted
sed -i '/sid:2010514/s/^/#/' drop.sorted
sed -i '/sid:2010516/s/^/#/' drop.sorted
sed -i '/sid:2010518/s/^/#/' drop.sorted
sed -i '/sid:2010520/s/^/#/' drop.sorted
sed -i '/sid:2010522/s/^/#/' drop.sorted
sed -i '/sid:2010525/s/^/#/' drop.sorted
sed -i '/sid:2010527/s/^/#/' drop.sorted
sed -i '/sid:2012056/s/^/#/' drop.sorted
sed -i '/sid:2012075/s/^/#/' drop.sorted
sed -i '/sid:2012119/s/^/#/' drop.sorted
sed -i '/sid:2012205/s/^/#/' drop.sorted
sed -i '/sid:2012272/s/^/#/' drop.sorted
sed -i '/sid:2012398/s/^/#/' drop.sorted
sed -i '/sid:2010931/s/^/#/' drop.sorted
sed -i '/sid:2011764/s/^/#/' drop.sorted
sed -i '/sid:2103088/s/^/#/' drop.sorted
sed -i '/sid:2103192/s/^/#/' drop.sorted
sed -i '/sid:2103134/s/^/#/' drop.sorted
sed -i '/sid:2101852/s/^/#/' drop.sorted
sed -i '/sid:2015526/s/^/#/' drop.sorted
sed -i '/sid:2009151/s/^/#/' drop.sorted
sed -i '/sid:2012997/s/^/#/' drop.sorted
sed -i '/sid:2101201/s/^/#/' drop.sorted
sed -i '/sid:2016672/s/^/#/' drop.sorted
sed -i '/sid:2000538/s/^/#/' drop.sorted
sed -i '/sid:2000540/s/^/#/' drop.sorted
sed -i '/sid:2011367/s/^/#/' drop.sorted
sed -i '/sid:2012251/s/^/#/' drop.sorted
sed -i '/sid:2100528/s/^/#/' drop.sorted
sed -i '/sid:2007994/s/^/#/' drop.sorted
sed -i '/sid:2008066/s/^/#/' drop.sorted
sed -i '/sid:2012180/s/^/#/' drop.sorted
sed -i '/sid:2102925/s/^/#/' drop.sorted
sed -i '/sid:2100628/s/^/#/' drop.sorted
sed -i '/sid:2010697/s/^/#/' drop.sorted
sed -i '/sid:2013479/s/^/#/' drop.sorted
sed -i '/sid:2001046/s/^/#/' drop.sorted
sed -i '/sid:2011803/s/^/#/' drop.sorted
sed -i '/sid:2009768/s/^/#/' drop.sorted
sed -i '/sid:2019490/s/^/#/' drop.sorted
sed -i '/sid:2011347/s/^/#/' drop.sorted
sed -i '/sid:2011037/s/^/#/' drop.sorted
sed -i '/sid:2103133/s/^/#/' drop.sorted
sed -i '/sid:2103132/s/^/#/' drop.sorted
sed -i '/sid:2017005/s/^/#/' drop.sorted
sed -i '/sid:2006445/s/^/#/' drop.sorted
sed -i '/sid:2003927/s/^/#/' drop.sorted
sed -i '/sid:2010908/s/^/#/' drop.sorted
sed -i '/sid:2014020/s/^/#/' drop.sorted
sed -i '/sid:2017479/s/^/#/' drop.sorted

echo "Removing blank lines"
awk 'NF' drop.sorted > snort.rules
echo " "

# Log total snort.rules and output
echo "Displaying counts.log"
echo "-------- -----------------------------------------"       >> counts.log
wc -l < snort.rules | awk  '{print  $1,"\t", "'snort.rules'" }' >> counts.log
echo \ >> counts.log
echo " "
cat counts.log

# Cleanup temp files
rm -f alert.* duplicate.* drop.*

echo "Replacing /etc/snort/rules/snort.rules"
mv /etc/snort/rules/snort.rules /etc/snort/rules/snort.rules.bak
mv snort.rules /etc/snort/rules/snort.rules
sleep 1

echo "Restarting SNORT service"
/etc/init.d/snort restart
sleep 1
echo " "
cd /etc/snort
exit 0
