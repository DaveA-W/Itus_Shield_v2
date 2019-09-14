#!/bin/sh

# Wrapper to handle downloads
download () {
	# try  
	{
		local outputfile=$1
		local url=$2
		local followRedirect=$3
		local timeout=$4
		
		if [ -z "$timeout" ] ; then timeout=120 ; fi
		
		echo " "
		echo "Download:    $url"

		if [ "$followRedirect" == "true" ]
		then
			curl -k -1 -m $timeout -o $outputfile -L $url		
		else
			curl -k -1 -m $timeout -o $outputfile $url
		fi
	} || {		
		echo "Unable to download $2"
		echo "*error*	 $1" >> host_counter.log
		return 1
	}
}

# Ingests files conforming to a specified filespec, appending lines from each to badhosts
ingest () {	
	# try  
	{

		local url=$1
		local lines=$(wc -l badhosts.tmp | awk '{print $1}')

		# Strip leading spaces; comments; replace 0.0.0.0 and 127.0.0.1 with 0
		sed -i -r 's/^\s*//;s/#.*$//;s/0\.0\.0\.0\s+/0 /;s/127\.0\.0\.1\s+/0 /' badhosts.tmp

		# Remove carriage return characters and blank lines
		tr -d '\r' < badhosts.tmp | awk 'NF' > badhosts
		local count=$(wc -l badhosts | awk '{print $1}')
		echo "$lines lines, $count hosts"
      
		# Pipe through lines that look like
		#     0 fully.qualified.domain.name
		#    :: fully.qualified.domain.name
		#   ::1 fully.qualified.domain.name
		sed -r -n '/^(0|(::)|(::1))\s.*$/p' badhosts >> badhosts.all   &&
		# Assume lines that look like below are IPv4, resolve them to 0
		#       fully.qualified.domain.name
		sed -r -n '/^[^ \t]+[ \t]*$/p' badhosts | sed -e 's/^/0 /' >> badhosts.all   &&

		# Output downloaded badhosts.tmp line count to host_counter.log
		printf "%7d\t%s\n" $count "$url" >> host_counter.log &&
		return 0
	} || {
		echo "Unable to ingest hosts '$1'"
		echo "*error*	 $1" >> host_counter.log
		return 1
	}
}

# Prepare /tmp/hosts/ and cumulative output files
echo " "
echo "Preparing working directory for host list download and ingestion"
echo "/tmp/hosts"
if [ ! -d "/tmp/hosts" ] ; then	mkdir /tmp/hosts ; else	rm -rf /tmp/hosts/* ; fi
cd /tmp/hosts
touch badhosts.all

# Look for pre-defined list of urls to download
if [ -f "/etc/snort/hosts/badhostlisturls.txt" ]; then
   echo "Using bad host list urls defined in /etc/snort/hosts/badhostlisturls.txt"
   cp /etc/snort/hosts/badhostlisturls.txt .
else # download a base set
   echo "Downloading bad host list urls from https://v.firebog.net/hosts/lists.php?type=tick"
   download badhostlisturls.txt https://v.firebog.net/hosts/lists.php?type=tick
fi

if [ -s "badhostlisturls.txt" ]; then
   # Prepare host_counter.log
   echo "# Hosts  Url processed by etc/snort/hosts/updatehosts.sh"  > host_counter.log
   echo "-------- -----------------------------------------------" >> host_counter.log

   # Loop through each url, download and ingest
   for url in $(sed -r -n "/^http\S+$/p" badhostlisturls.txt)
   do
      download badhosts.tmp $url &&
      ingest $url
   done
   
   echo " "
   count=$(wc -l badhosts.all | awk '{print $1}')
   echo "Sorting $count bad hosts and removing duplicates"
   cat badhosts.all | sort | uniq > badhosts.tmp
   # Remove carriage return characters and blank lines
   tr -d '\r' < badhosts.tmp | awk 'NF' > badhosts
else
	echo "No bad host lists defined or downloaded"
fi

# Cleanup working files
echo "Cleaning up working files"
rm -f *.tmp badhosts.all

# Update host_counter.log with final results
echo "-------- -----------------------------------------------" >> host_counter.log
printf "%7d\t%s\n" $count "aggregated" >> host_counter.log
count=$(wc -l badhosts | awk '{print $1}')
printf "%7d\t%s\n" $count "unique bad hosts" >> host_counter.log
echo \ >> host_counter.log
echo " "
echo "Displaying host_counter.log"
echo " "
cat host_counter.log

# Look for pre-defined hosts template
if [ -f "/etc/snort/hosts/hosts" ]; then
   echo "Using host template defined at /etc/snort/hosts/hosts"
   cp /etc/snort/hosts/hosts .
else # download a base set
   echo "Creating a new hosts file"
   cat << EOF > hosts
# This template file at /etc/snort/hosts/hosts is used to update system
# /etc/hosts with known mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should be
# placed in the first column followed by the corresponding host name.
# The IP address and host name should be separated one or more spaces.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# /etc/snort/hosts/updatehosts.sh downloads lists of bad domains using
# urls in /etc/snort/hosts/badhostlisturls.txt
# It then replaces the main /etc/hosts with this template,
# appending lines to resolve all bad domains to 127.0.0.1
#
# For example:
#      102.54.94.97     rhino.acme.com    # known server IP
#      127.0.0.1        malware.site      # prevent outbound traffic

# Common loopback names
127.0.0.1 localhost

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF
fi
echo \ >> hosts

if [ -s "badhosts" ]; then
	echo "Appending badhosts"   
   cat badhosts >> hosts
fi

echo "Replacing /etc/hosts"
if [ -s "/etc/hosts" ]; then
   mv -f /etc/hosts /etc/hosts.bak
fi
mv -f hosts /etc/hosts
cp -f host_counter.log /var/log/host_counter.log

echo "Restarting network"
/etc/init.d/network restart

