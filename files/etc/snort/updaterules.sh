#!/bin/sh

download ()
{
	# try  
	{
		ruleset=$1
		url=$2
		timeout=$3
		followRedirect=$4
		
		if [ -z "$timeout" ] ; then timeout=40 ; fi
		
		echo " "
		echo "Downloading $ruleset ..."
		echo "$url"

		if [ -n "$followRedirect" ]
		then
			curl -k -1 -m $timeout -o $ruleset -L $url		
		else
			curl -k -1 -m $timeout -o $ruleset $url
		fi
	} || {		
		echo "Unable to download rules '$1' from $2"
		echo "ERROR	$1" >> counts.log
		return 1
	}
}

ingest ()
{	
	# try  
	{
		ruleset=$1
		if [ -n "$2" ] ; then filenames=$2 ; else filenames=$ruleset; fi

		# Extract rules to alert.tmp     
		cat $filenames | sed '/^\#/d' | sed '/^$/d' > alert.tmp &&

		# Output original count to counts.log (assumes it exists)
		wc -l < alert.tmp | awk  '{print  $1,"\t", "'$ruleset'" }' >> counts.log  &&

		return 0
	} || {
		echo "Unable to ingest rules '$1'"
		echo "ERROR	$1" >> counts.log
		return 1
	}
}

downloadAndIngest ()
{
	ruleset=$1
	url=$2
	timeout=$3
	followRedirect=$4
	if [ -n "$url" ]
	then
		if [[ "$url" == *.tar.gz ]]
		then
			download "$ruleset.tar.gz" "$url" $timeout $followRedirect  &&
			tar x -z -f "$ruleset.tar.gz"  &&
			ingest "$ruleset" "$ruleset/*.rules" && 
			return 0
		else
			download "$ruleset" "$url" $timeout $followRedirect  &&
			ingest   "$ruleset"  && 
			return 0
		fi
	fi
	return 1
}


# Prepare /tmp/snort/
if [ ! -d "/tmp/snort" ] ; then	mkdir /tmp/snort ; else	rm -rf /tmp/snort/* ; fi
cd /tmp/snort
echo " "
echo "/tmp/snort is the working director for rule download and ingestion"

# Prepare counts.log
echo "# Rules  Downloaded set, via etc/snort/updaterules"                   > counts.log
echo "-------- -----------------------------------------"                  >> counts.log

# NOTE: Snort Community Rules ~1.7MB location uses a 302 redirect to Amazon S3 bucket
downloadAndIngest community-rules                  https://www.snort.org/downloads/community/community-rules.tar.gz  120  true

# Emerging Threats lists can be found at https://rules.emergingthreats.net/open/snort-edge/rules/

# BotCC: Detect hosts communicating with a known and active Bot or Malware command and control server.
downloadAndIngest emerging-botcc.rules             https://rules.emergingthreats.net/open/snort-edge/rules/emerging-botcc.rules
downloadAndIngest emerging-botcc.portgrouped.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-botcc.portgrouped.rules

# CIArmy: Subset of CINS Active Threat Intelligence rules, where an IP's 'Rogue Packet' score is poor or it has tripped a number of trusted alerts around the world.
downloadAndIngest emerging-ciarmy.rules            https://rules.emergingthreats.net/open/snort-edge/rules/emerging-ciarmy.rules

# Compromised: Hosts compromised by bots, phishing sites, or spewing hostile traffic. These are not your everyday infected and sending a bit of spam hosts, these are significantly infected and hostile hosts.
downloadAndIngest emerging-compromised.rules       https://rules.emergingthreats.net/open/snort-edge/rules/emerging-compromised.rules

# Dshield: Daily list of the top attackers reported to www.dshield.org
downloadAndIngest emerging-dshield.rules           https://rules.emergingthreats.net/open/snort-edge/rules/emerging-dshield.rules

# Exploits: Detect direct exploits including Windows exploits, Veritas, etc.
downloadAndIngest emerging-exploit.rules           https://rules.emergingthreats.net/open/snort-edge/rules/emerging-exploit.rules

# Malware: Spyware and other things you don't want running on your network. URL hooks for known update schemes, User-Agent strings of known malware, and a load of other goodies.
downloadAndIngest emerging-malware.rules           https://rules.emergingthreats.net/open/snort-edge/rules/emerging-malware.rules

# Mobile Malware
downloadAndIngest emerging-mobile_malware.rules    https://rules.emergingthreats.net/open/snort-edge/rules/emerging-mobile_malware.rules

# User Agents
downloadAndIngest emerging-user_agents.rules       https://rules.emergingthreats.net/open/snort-edge/rules/emerging-user_agents.rules

# Web Clients
downloadAndIngest emerging-web_client.rules        https://rules.emergingthreats.net/open/snort-edge/rules/emerging-web_client.rules

# Worms
downloadAndIngest emerging-worm.rules              https://rules.emergingthreats.net/open/snort-edge/rules/emerging-worm.rules

# Current Events 
# Most often simple sigs for the Storm binary URL of the day, sigs to catch CLSIDs of newly found vulnerable apps where we don't have detail on the exploit.
# Useful sigs but not for the long term until they have been properly tested.
# (file size is ~1.5MB - increase timeout to 120 seconds)
downloadAndIngest emerging-current_events.rules    https://rules.emergingthreats.net/open/snort-edge/rules/emerging-current_events.rules  120

# Trojans (file size is ~4MB - increase timeout to 120 seconds)
downloadAndIngest emerging-trojan.rules            https://rules.emergingthreats.net/open/snort-edge/rules/emerging-trojan.rules  120

# Spamhaus Drops: Rules to block networks listed as DROP by www.spamhaus.org
downloadAndIngest emerging-drop.rules              https://rules.emergingthreats.net/open/snort-edge/rules/emerging-drop.rules

# Web Specific Apps			** commented out in fw_upgrade? **
# downloadAndIngest emerging-web_specific_apps.rules https://rules.emergingthreats.net/open/snort-edge/rules/emerging-web_specific_apps.rules

# Scans
downloadAndIngest emerging-scan.rules              https://rules.emergingthreats.net/open/snort-edge/rules/emerging-scan.rules

# SSL Blacklist: Bad SSL certificates identified by abuse.ch to be associated with malware or botnet activities in the past 30 days.
downloadAndIngest abuse-sslbl.rules                https://sslbl.abuse.ch/blacklist/sslipblacklist.rules

# SSL Aggressive: Bad SSL certificates *ever* identified by abuse.ch to be associated with malware or botnet activities.
# Since IP addresses can change, may contain false positives - comment out by default
# downloadAndIngest abuse-dyre.rules               https://sslbl.abuse.ch/blacklist/dyre_sslipblacklist_aggressive.rules

# ZeuS: Command and control servers ** DISCONTINUED 2019-07-08 per https://zeustracker.abuse.ch/byebye.php?download=snort **
# downloadAndIngest /tmp/snort/zeus.rules          https://zeustracker.abuse.ch/blocklist.php?download=snort

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

# Removing rules determined by ITUS Networks to cause web site issues
if [ -f "/etc/snort/rules/exclude.rules" ]; then
	# Searching and removing ~100 rules takes a couple of minutes
	# (note: as of August 2019 though, none seem to be present in default sets above)
	echo "Removing rules determined by ITUS Networks to cause web site issues ..."
	for i in $(cat /etc/snort/rules/exclude.rules)
	do
		if [ "$i" -eq "$i" ] 2>/dev/null
		then
			# it's an integer sid
			sed -i "/sid:$i/s/^/#/" drop.sorted		
		fi
	done
fi

echo "Removing blank lines"
awk 'NF' drop.sorted > snort.rules
sed -i 's/\r//g' snort.rules # carriage return characters
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
# service snort restart
/etc/init.d/snort restart
sleep 1
echo " "
cd /etc/snort
exit 0
