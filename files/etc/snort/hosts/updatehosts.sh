#!/bin/bash
#
# Script designed to automate the updating of blocklists for DNS

# Create the temp directory
TEMP_DIR="/var/blacklist"

if [ ! -d /var/${TEMP_DIR} ]
then
   mkdir -p ${TEMP_DIR}
fi

cd ${TEMP_DIR}

# Create a new host file
cat << EOF > hosts
# This host file is automatically generated
# Please see /etc/snort/updateblacklist.sh for more information
127.0.0.1 localhost

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

# YouTube ads
# TODO: Make sure these actually do anything - Untested at the moment
127.0.0.1 r1---sn-vgqsen7z.googlevideo.com
127.0.0.1 r1.sn-vgqsen7z.googlevideo.com
127.0.0.1 r17---sn-vgqsenes.googlevideo.com
127.0.0.1 r2---sn-vgqs7n7k.googlevideo.com
127.0.0.1 r20---sn-vgqs7ne7.googlevideo.com
127.0.0.1 r20.sn-vgqs7ne7.googlevideo.com
127.0.0.1 r4---sn-vgqs7nez.googlevideo.com
127.0.0.1 r4.sn-vgqs7nez.googlevideo.com
127.0.0.1 www.youtube-nocookie.com
EOF

########
# Grab the lists into one place

wget -O badhosts.list https://v.firebog.net/hosts/lists.php?type=tick
IFS=$'\n' read -d '' -r badhosts < badhosts.list
NUM_LINES=$(wc -l badhosts.list)
DL_LINES=${badhosts[@]}
for url in ${badhosts[@]}; do
   wget -O badurls $url
   cat badurls >> hosts
done

# Copy the new hosts files over
echo "Copying new host list"
mv ${TEMP_DIR}/hosts /etc/hosts
/etc/init.d/network restart