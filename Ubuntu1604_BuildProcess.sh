#!/bin/bash
# Ubuntu 16.04 LTS Post-install setup script for pentesting goodness

# Root Check
user=$(whoami)
if [ "$user" != "root" ]; then
    echo "Please run as root"
    exit 1
fi

# Add extra keys and repos for additional packages

apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys BBEBDCB318AD50EC6865090613B00F1FD2C19886 && \
gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 && \
add-apt-repository -y ppa:webupd8team/sublime-text-2 && add-apt-repository -y ppa:atareao/telegram && \
add-apt-repository ppa:openjdk-r/ppa && \
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add - && \
echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list && \
echo "deb http://repository.spotify.com stable non-free" >> /etc/apt/sources.list && \

# Create folder structure

mkdir /test && \
mkdir /opt/00-testing-tools && \
mkdir /opt/00-testing-tools/{01-recon-osint,02-scanning,03-enumeration,04-exploitation,05-network-tools,06-password-tools,07-wireless-tools,08-config-reviews} && \
chown -R jb /opt/00-testing-tools/ && chgrp -R jb /opt/00-testing-tools/ && \
chown -R jb /test && chgrp -R jb /test && \

# Install packages

apt-get update && apt-get install -y aha autoconf bison build-essential cmake \
conky cpanminus cryptsetup dia firebird-dev \
flex freeipmi git google-chrome-stable hping3 \
ipmitool keepassx ldap-utils libc6-dev-i386 \
libffi-dev libgtk2.0-dev libidn11-dev \
libimage-exiftool-perl libkrb5-dev liblzma-dev \
mono-reference-assemblies-2.0 mono-devel libmysqlclient-dev \
libncurses5-dev libnss3-dev libopenmpi-dev \
libpcap-dev libpcre3-dev libpq-dev libsqlite3-dev \
libssh-dev libssl-dev libstoken-dev libsvn-dev \
libxml2-dev libxslt1-dev netcat-traditional \
network-manager-openconnect onesixtyone \
openconnect openjdk-7-jre openmpi-bin openvpn \
p7zip-full postgresql postgresql-server-dev-9.5 \
proxychains python-dev python-pip rpcbind \
ruby ruby-dev samba screen screenfetch \
shutter snmp spotify-client sqlite3 stoken \
sublime-text subnetcalc subversion telegram \
tshark virtualenvwrapper vlan vlc wine \
wireshark yasm yersinia zlib1g-dev && \

# Install python modules

pip install --upgrade pip && \
pip install watchdog selenium cherrypy && \

# Install ruby gems

gem install bundler snmp && \

# Install Metasploit

curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall && \

# Install Git & svn packages

git clone https://github.com/laramies/theHarvester.git /opt/00-testing-tools/01-recon-osint/theharvester && \
git clone https://bitbucket.org/LaNMaSteR53/recon-ng.git /opt/00-testing-tools/01-recon-osint/recon-ng && \
git clone https://github.com/michenriksen/gitrob.git /opt/00-testing-tools/01-recon-osint/gitrob && \
git clone https://github.com/ChrisTruncer/EyeWitness.git /opt/00-testing-tools/01-recon-osint/eyewitness && \
git clone https://github.com/leebaird/discover.git /opt/00-testing-tools/01-recon-osint/discover && \
git clone https://github.com/smicallef/spiderfoot.git /opt/00-testing-tools/01-recon-osint/spiderfoot && \
git clone https://github.com/Eisler/URLCrazy.git /opt/00-testing-tools/01-recon-osint/urlcrazy && \
git clone https://github.com/TheRook/subbrute.git /opt/00-testing-tools/01-recon-osint/subbrute && \
git clone https://github.com/aboul3la/Sublist3r.git /opt/00-testing-tools/01-recon-osint/sublist3r && \
git clone https://github.com/Techno-Hwizrdry/checkpwnedemails.git /opt/00-testing-tools/01-recon-osint/checkpwnedemails && \
git clone https://github.com/robertdavidgraham/masscan /opt/00-testing-tools/02-scanning/masscan && \
git clone https://github.com/sullo/nikto.git /opt/00-testing-tools/02-scanning/nikto && \
svn co https://svn.nmap.org/nmap /opt/00-testing-tools/02-scanning/nmap && \
git clone https://github.com/royhills/arp-scan.git /opt/00-testing-tools/02-scanning/arp-scan && \
git clone https://github.com/davidpepper/fierce-domain-scanner.git /opt/00-testing-tools/03-enumeration/fierce && \
git clone https://github.com/nccgroup/vlan-hopping---frogger.git /opt/00-testing-tools/03-enumeration/frogger && \
git clone https://github.com/urbanadventurer/WhatWeb.git /opt/00-testing-tools/03-enumeration/whatweb && \
git clone https://github.com/wpscanteam/wpscan.git /opt/00-testing-tools/03-enumeration/wpscan && \
git clone https://github.com/royhills/ike-scan.git /opt/00-testing-tools/03-enumeration/ike-scan && \
git clone https://github.com/drwetter/testssl.sh /opt/00-testing-tools/03-enumeration/testssl && \
git clone https://github.com/nabla-c0d3/sslyze.git /opt/00-testing-tools/03-enumeration/sslyze && \
git clone https://github.com/cldrn/davtest.git /opt/00-testing-tools/03-enumeration/davtest && \
git clone https://github.com/breenmachine/httpscreenshot.git /opt/00-testing-tools/03-enumeration/httpscreenshot && \
git clone https://github.com/Dionach/CMSmap /opt/00-testing-tools/03-enumeration/cmsmap && \
git clone https://github.com/SpiderLabs/Responder.git /opt/00-testing-tools/04-exploitation/responder && \
git clone https://github.com/sqlmapproject/sqlmap.git /opt/00-testing-tools/04-exploitation/sqlmap && \
git clone https://github.com/evilsocket/bettercap /opt/00-testing-tools/04-exploitation/bettercap && \
git clone https://github.com/Veil-Framework/Veil.git /opt/00-testing-tools/04-exploitation/Veil && \
git clone https://github.com/nccgroup/chuckle.git /opt/00-testing-tools/04-exploitation/chuckle && \
git clone https://github.com/pentestgeek/smbexec.git /opt/00-testing-tools/04-exploitation/smbexec && \
git clone https://github.com/beefproject/beef.git /opt/00-testing-tools/04-exploitation/beef && \
git clone https://github.com/MooseDojo/praedasploit /opt/00-testing-tools/04-exploitation/praedasploit && \
git clone https://github.com/PowerShellMafia/PowerSploit.git /opt/00-testing-tools/04-exploitation/powersploit && \
git clone https://github.com/samratashok/nishang.git /opt/00-testing-tools/04-exploitation/nishang && \
git clone https://github.com/byt3bl33d3r/CrackMapExec.git /opt/00-testing-tools/04-exploitation/crackmapexec && \
git clone https://github.com/CoreSecurity/impacket.git /opt/00-testing-tools/05-network-tools/impacket && \
git clone https://github.com/secdev/scapy.git /opt/00-testing-tools/05-network-tools/scapy && \
git clone https://github.com/apenwarr/sshuttle.git /opt/00-testing-tools/05-network-tools/sshuttle && \
git clone https://github.com/gentilkiwi/mimikatz.git /opt/00-testing-tools/06-password-tools/mimikatz && \
git clone https://github.com/vanhauser-thc/thc-hydra.git /opt/00-testing-tools/06-password-tools/hydra && \
git clone https://www.github.com/praetorian-inc/gladius /opt/00-testing-tools/06-password-tools/gladius && \
git clone https://github.com/magnumripper/JohnTheRipper.git -b bleeding-jumbo /opt/00-testing-tools/06-password-tools/john && \

cd /opt/00-testing-tools/01-recon-osint && \
wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/goofile/goofilev1.5.zip && \
unzip goofilev1.5.zip && rm goofilev1.5.zip && mv goofilev1.5 goofile && \
cd gitrob && gem install gitrob && \

cd /opt/00-testing-tools/02-scanning/masscan && make && \
cd /opt/00-testing-tools/02-scanning/nmap && ./configure --without-zenmap && make && make install && \
cd /opt/00-testing-tools/02-scanning/arp-scan && autoreconf --install && ./configure && make && make install && \

cd /opt/00-testing-tools/03-enumeration/sslyze && pip install -r requirements.txt --target ./lib && \
cd /opt/00-testing-tools/03-enumeration/ && \
wget https://labs.portcullis.co.uk/download/enum4linux-0.8.9.tar.gz && wget https://labs.portcullis.co.uk/download/polenum-0.2.tar.bz2 && \
mkdir snmpcheck && cd snmpcheck && wget http://www.nothink.org/codes/snmpcheck/snmpcheck-1.9.rb && \
mkdir nbtscan && cd nbtscan && wget http://www.unixwiz.net/tools/nbtscan-source-1.0.35.tgz && \
tar -xvzf nbtscan-source-1.0.35.tgz && make && \
wget http://www.hackingciscoexposed.com/tools/ntp-fingerprint.tar.gz && \
tar -xvzf ntp-fingerprint.tar.gz && mv ntp-fingerprint ntpfingerprint && \
mv ntpfingerprint/ntp-fingerprint.pl ntpfingerprint/ntpfingerprint.pl && rm -r ntp-fingerprint.tar.gz && \
cd /opt/00-testing-tools/03-enumeration && tar -xvzf enum4linux-0.8.9.tar.gz && tar -xvf polenum-0.2.tar.bz2 && \
mv enum4linux-0.8.9 enum4linux && mv polenum-0.2 polenum && rm -r enum4linux-0.8.9.tar.gz polenum-0.2.tar.bz2 && \
chmod +x fierce/fierce.pl && chmod +x frogger/frogger.sh && \
cd wpscan && bundle install && \
cd /opt/00-testing-tools/03-enumeration/ike-scan && autoreconf --install && \
./configure --with-openssl && make && sudo make install && \
sudo cpanm Getopt::Long && sudo cpanm HTTP::DAV && \
cd /opt/00-testing-tools/03-enumeration/httpscreenshot && sudo ./install-dependencies.sh && \

mkdir /opt/00-testing-tools/04-exploitation/metasploit-framework && \
cd /opt/00-testing-tools/04-exploitation && mv responder/Responder.py responder/responder.py && chmod +x responder/responder.py && \
cd /opt/00-testing-tools/04-exploitation/bettercap && gem build bettercap.gemspec && sudo gem install bettercap*.gem && \

cd /opt/00-testing-tools/05-network-tools/impacket && chmod +x setup.py && \
sudo python setup.py install && cd impacket && chmod +x *.py && \
cd /opt/00-testing-tools/05-network-tools/sshuttle && sudo python ./setup.py install && cd ../ && \
mkdir /opt/00-testing-tools/05-network-tools/networkminer && cd /opt/00-testing-tools/05-network-tools/networkminer && \
wget www.netresec.com/?download=NetworkMiner -O nm.zip && unzip nm.zip && \
cd NetworkMiner_2-0/ && cp *.* ../ && cp -R */ ../ && \
rm -rf nm.zip NetworkMiner_2-0/ && chmod +x NetworkMiner.exe && chmod -R go+w AssembledFiles/ && chmod -R go+w Captures/ && \
touch launchme.txt && echo "mono NetworkMiner.exe" > launchme.txt && \

cd /opt/00-testing-tools/06-password-tools/ && wget https://hashcat.net/files/hashcat-2.00.7z && \
p7zip -d hashcat-2.00.7z && mv hashcat-2.00 hashcat && \
cd /opt/00-testing-tools/06-password-tools/hydra && ./configure && make && sudo make install && cd ../ && \
cd gladius && git clone https://www.github.com/praetorian-inc/Hob0Rules && cp Hob0Rules/* . && rm -rf Hob0Rules/ && \
cd /opt/00-testing-tools/06-password-tools/ && wget https://digi.ninja/files/cewl_5.1.tar.bz2 && tar -xf cewl_5.1.tar.bz2 && rm -rf cewl_5.1.tar.bz2 && \
cd cewl/ && bundle install && \
cd /opt/00-testing-tools/06-password-tools/ && wget http://www.ampliasecurity.com/research/wce_v1_41beta_universal.zip && \
mkdir wce && unzip wce_v1_41beta_universal.zip -d wce/ && rm wce_v1_41beta_universal.zip && \
svn checkout http://rexgen.googlecode.com/svn/trunk/ rexgen && cd rexgen/src && mkdir build && cd build && \
cmake .. && make && sudo make install && cd /opt/00-testing-tools/06-password-tools/ && \
cd /opt/00-testing-tools/06-password-tools/john/src && ./configure --enable-mpi && \
make -s clean && make -sj4 && \

ln -s /usr/bin/wireshark /opt/00-testing-tools/05-network-tools/wireshark && \
ln -s /usr/bin/yersinia /opt/00-testing-tools/05-network-tools/yersinia && \
ln -s /usr/bin/tshark /opt/00-testing-tools/05-network-tools/tshark && \
ln -s /usr/bin/onesixtyone /opt/00-testing-tools/03-enumeration/onesixtyone && \
ln -s /usr/bin/subnetcalc /opt/00-testing-tools/05-network-tools/subnetcalc && \
ln -s /usr/bin/proxychains /opt/00-testing-tools/05-network-tools/proxychains && \
ln -s /usr/sbin/openvpn /opt/00-testing-tools/05-network-tools/openvpn && \
ln -s /usr/sbin/hping3 /opt/00-testing-tools/05-network-tools/hping3 && \
ln -s /usr/bin/ipmitool /opt/00-testing-tools/03-enumeration/ipmitool && \
ln -s /opt/metasploit-framework/ /opt/00-testing-tools/04-exploitation/metasploit-framework/ && \
ln -s /opt/00-testing-tools/01-recon-osint/dnsrecon/dnsrecon.py /usr/bin/dnsrecon && \
ln -s /opt/00-testing-tools/01-recon-osint/goofile/goofile.py /usr/bin/goofile && \
ln -s /opt/00-testing-tools/01-recon-osint/theharvester/theHarvester.py /usr/bin/theHarvester && \
ln -s /opt/00-testing-tools/02-scanning/masscan/bin/masscan /usr/bin/masscan && \
ln -s /opt/00-testing-tools/02-scanning/arp-scan/arp-scan /usr/bin/arp-scan && \
ln -s /opt/00-testing-tools/02-scanning/nikto/program/nikto.pl /usr/bin/nikto && \
ln -s /opt/00-testing-tools/03-enumeration/enum4linux/enum4linux.pl /usr/bin/enum4linux && \
ln -s /opt/00-testing-tools/03-enumeration/polenum/polenum.py /usr/bin/polenum && \
ln -s /opt/00-testing-tools/03-enumeration/fierce/fierce.pl /usr/bin/fierce && \
ln -s /opt/00-testing-tools/03-enumeration/frogger/frogger.sh /usr/bin/frogger && \
ln -s /opt/00-testing-tools/03-enumeration/whatweb/whatweb /usr/bin/whatweb && \
ln -s /opt/00-testing-tools/03-enumeration/snmpcheck/snmpcheck-1.9.rb /usr/bin/snmpcheck
ln -s /opt/00-testing-tools/03-enumeration/ike-scan/ike-scan /usr/bin/ike-scan && \
ln -s /opt/00-testing-tools/03-enumeration/testssl/testssl.sh /usr/bin/testssl.sh && \
ln -s /opt/00-testing-tools/03-enumeration/sslyze/sslyze.py /usr/bin/sslyze && \
ln -s /opt/00-testing-tools/03-enumeration/nbtscan/nbtscan /usr/bin/nbtscan && \
ln -s /opt/00-testing-tools/03-enumeration/ntpfingerprint/ntpfingerprint.pl /usr/bin/ntpfingerprint && \
ln -s /opt/00-testing-tools/04-exploitation/responder/responder.py /usr/bin/responder
ln -s /opt/00-testing-tools/04-exploitation/sqlmap/sqlmap.py /usr/bin/sqlmap
ln -s /opt/00-testing-tools/04-exploitation/exploitdb/searchsploit /usr/bin/searchsploit
ln -s /opt/00-testing-tools/04-exploitation/Veil/Veil-Evasion/Veil-Evasion.py /usr/bin/veil-evasion
ln -s /opt/00-testing-tools/06-password-tools/hashcat/hashcat-cli64.bin /usr/bin/hashcat && \

updatedb

# frogger - check works with new-style interface naming
# hard-set csv path for searchsploit in exploitdb folder
# cleanup script for responder, eyewitness, discover scripts, etc
# copy in irmtools & relevant stuff from armoury
# consider changing john install process to provide GPU support
# wordlists??
# wireless tools
# add scripts to relevant directories
# install crunch from sourceforge
# check symlinks all work from cli
# remember to launch msfconsole as normal user to setup local db!
# OCLhashcat setup for vid card??
# change gladius.py to point to all correct file paths for hashcat, etc
# configure gitrob to create db, add api key, etc
# Run setup scripts for eyewitness, discover scripts, smbexec, Veil-Framework, smb-exec, crackmapexec
# configure API keys for recon-ng
# import token to stoken
