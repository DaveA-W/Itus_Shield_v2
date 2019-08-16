#!/bin/sh

# Wrapper to handle downloads
download () {
	# try  
	{
		ruleset=$1
		url=$2
		followRedirect=$3
		timeout=$4
		
		if [ -z "$timeout" ] ; then timeout=120 ; fi
		
		echo " "
		echo "Downloading $ruleset"
		echo "  $url"

		if [ "$followRedirect" == "true" ]
		then
			curl -k -1 -m $timeout -o $ruleset -L $url		
		else
			curl -k -1 -m $timeout -o $ruleset $url
		fi
	} || {		
		echo "Unable to download rules '$1' from $2"
		echo "*error*	 $1" >> counts.log
		return 1
	}
}

# Ingests files conforming to a specified filespec, appending lines from each to alert.list
ingest () {	
	# try  
	{
		for filename in $(ls $1)
		do
			# Extract rules to alert.tmp
			cat $filename | sed '/^\#/d' | sed '/^$/d' > alert.tmp &&
			# Append to alert.list
			cat alert.tmp >> alert.list	&&
			# Output count to counts.log
			wc -l < alert.tmp | awk  '{print  $1,"\t", "'$filename'" }' >> counts.log
		done
		return 0		
	} || {
		echo "Unable to ingest rules '$1'"
		echo "*error*	 $1" >> counts.log
		return 1
	}
}

# Downloads and ingests rules from an url
# (gzips will be unpacked, resultant $filenames spec should be provided as the last argument)
downloadAndIngest() {
	ruleset=$1
	url=$2
	followRedirect=$3
	filenames=$4
	if [ -n "$url" ]
	then
		if [ -z "$filenames" ] ; then
			filenames=$ruleset
		fi
		download "$ruleset" "$url" $followRedirect &&
		(
			file "$ruleset" | grep -q gzip  &&
			mv "$ruleset" "$ruleset.tar.gz" &&
			tar -zxf "$ruleset.tar.gz"
		) &&
		ingest "$filenames" && 
		return 0
	fi
	return 1
}

# Prepare /tmp/snort/ and cumulative output files
echo " "
echo "Preparing working directory for rule download and ingestion"
echo "/tmp/snort"
if [ ! -d "/tmp/snort" ] ; then	mkdir /tmp/snort ; else	rm -rf /tmp/snort/* ; fi
cd /tmp/snort
touch alert.list
touch ip.list

# Prepare counts.log
echo "# Rules  Set processed by etc/snort/updaterules.sh"  > counts.log
echo "-------- -----------------------------------------" >> counts.log

# NOTE: Snort Community Rules ~1.7MB (`true` below flags that 302 redirects should be followed -> actual file is in an Amazon S3 bucket)
downloadAndIngest community-rules    https://www.snort.org/downloads/community/community-rules.tar.gz  true  community-rules/*.rules

# SSL Blacklist: Bad SSL certificates identified by abuse.ch to be associated with malware or botnet activities in the past 30 days.
downloadAndIngest abuse-sslbl.rules  https://sslbl.abuse.ch/blacklist/sslipblacklist.rules

# SSL Aggressive: Bad SSL certificates *ever* identified by abuse.ch to be associated with malware or botnet activities.
# Since IP addresses can change, may contain false positives - comment out by default
# downloadAndIngest abuse-dyre.rules https://sslbl.abuse.ch/blacklist/dyre_sslipblacklist_aggressive.rules

# ZeuS servers: DISCONTINUED 2019-07 https://zeustracker.abuse.ch/byebye.php?download=snort
# downloadAndIngest zeus.rules       https://zeustracker.abuse.ch/blocklist.php?download=snort

# Emerging Threats zip ~2.3MB        https://doc.emergingthreats.net/bin/view/Main/EmergingFAQ
download emerging-threats.tar.gz     https://rules.emergingthreats.net/open/snort-edge/emerging.rules.tar.gz  &&
(
	# Extract emerging-threats.tar.gz, assumed it will unzip to folder "rules"
	echo " "

	# Look for pre-defined subset of rules to extract
	if [ -f "/etc/snort/updaterules.emerging-threats.txt" ]; then
		echo "Extracting subset listed in /etc/snort/updaterules.emerging-threats.txt"
		# Expect errors due to commented lines, so send error output to null
		tar -zxvf "emerging-threats.tar.gz" -T "/etc/snort/updaterules.emerging-threats.txt" 2>/dev/null
		# Also extract IP blacklist and sid-msg.map for later use
		tar -zxvf "emerging-threats.tar.gz" "rules/compromised-ips.txt" "rules/sid-msg.map"

	else # unzip the lot
		echo "Extracting:"
		tar -zxvf "emerging-threats.tar.gz"
	fi

	# Now ingest *.rules
	ingest "rules/*.rules"
)

echo " "
echo "Changing rules that only alert to drop instead"
sed -i 's/alert /drop /' alert.list
# wc -l alert.list
sed '/^\#/d' alert.list >> drop.list
# wc -l drop.list
sed '/^$/d' drop.list | sort | uniq > drop.sorted
# wc -l drop.sorted

# Snort only allows one sid number, so we have to delete where rules contain multiple revisions
echo "Removing rules with extra sid revision numbers"
cat drop.sorted | awk -F"sid:" '{print $2}' | awk -F";" '{print $1}' | sort | uniq -d > duplicate.sids
touch duplicate.sed
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
# Searching and removing ~100 rules takes a couple of minutes
# (note: as of August 2019 though, none seem to be present in default sets above)
if [ -f "/etc/snort/updaterules.exclude.sids.txt" ]; then
	echo "-------- -----------------------------------------" >> counts.log
	wc -l < drop.sorted  | awk '{print  $1,"\t", "'unique.rules'" }' >> counts.log
	original=$(wc -l drop.sorted | awk '{print $1}')
	total=$(wc -l /etc/snort/updaterules.exclude.sids.txt | awk '{print $1}')
	pattern=0
	for sid in $(cat /etc/snort/updaterules.exclude.sids.txt)
	do
		if [ "$sid" -eq "$sid" ] 2>/dev/null
		then # it's an integer sid
			printf "\rRemoving rules that can cause web site issues: checking sid %3d of %s" "$((++pattern))" "$total";
			sed -i "/sid:$sid/s/^/#/" drop.sorted
		fi
	done
	echo " "
	final=$(wc -l drop.sorted | awk '{print $1}')
	if [ "$final" -eq "$original" ] 2>/dev/null
	then
		echo "No rules removed - consider clearing old sids from /etc/snort/updaterules.exclude.sids.txt"
	else
		removed=$((final-original))
		echo "$removed rules removed"
	fi
fi

echo "Removing blank lines"
sed -i 's/\r//g' drop.sorted # carriage return characters
awk 'NF' drop.sorted > snort.rules

# Cleanup working files
echo "Cleaning up working files"
rm -f ip.list alert.* duplicate.* drop.*

# Update IP blacklists ---------------------------------
echo " "
echo "Updating IP blacklists"
echo "-------- -----------------------------------------" >> counts.log

# rules/compromised-ips.txt comes from emerging-threats.tar.gz downloaded above
if [ -f "rules/compromised-ips.txt" ]; then
	cat rules/compromised-ips.txt >> ip.list
	wc -l < rules/compromised-ips.txt  | awk '{print  $1,"\t", "'rules/compromised-ips.txt'" }' >> counts.log
fi

# Snort Community blacklist url found via https://blog.snort.org/2015/09/ip-blacklist-feed-has-moved-locations.html
# Note other potentially useful urls within https://github.com/shirkdog/pulledpork/blob/master/etc/pulledpork.conf
download talos-ip-blacklist.txt https://talosintelligence.com/documents/ip-blacklist true  # follow url 302 redirects
if [ -f "talos-ip-blacklist.txt" ]; then
	cat talos-ip-blacklist.txt >> ip.list
	wc -l < talos-ip-blacklist.txt  | awk '{print  $1,"\t", "'talos-ip-blacklist.txt'" }' >> counts.log
fi

# Output unique IPs from our downloaded blacklist(s) to L2.blacklist
awk '!seen[$0]++' ip.list > L2.blacklist

# Update counts.log with final results
echo "-------- -----------------------------------------"       >> counts.log
wc -l < snort.rules  | awk '{print  $1,"\t", "'snort.rules'" }' >> counts.log
wc -l < L2.blacklist | awk '{print  $1,"\t", "'L2.blacklist'"}' >> counts.log
echo \ >> counts.log
echo " "
echo "Displaying counts.log"
echo " "
cat counts.log

# Replace snort files and restart ----------------------
if [ -s "snort.rules" ]; then
	echo "Replacing /etc/snort/rules/snort.rules"
	mv /etc/snort/rules/snort.rules /etc/snort/rules/snort.rules.bak
	mv snort.rules /etc/snort/rules/snort.rules
else
	echo "No snort rules downloaded"
fi
if [ -s "L2.blacklist" ]; then
	echo "Replacing /etc/snort/rules/iplists/L2.blacklist"
	mv /etc/snort/rules/iplists/L2.blacklist /etc/snort/rules/iplists/L2.blacklist.bak
	mv L2.blacklist /etc/snort/rules/iplists/L2.blacklist
else
	echo "No IP blacklists downloaded"
fi

echo "Restarting SNORT service"
# service snort restart
/etc/init.d/snort restart
sleep 1
echo " "
cd /etc/snort
exit 0
