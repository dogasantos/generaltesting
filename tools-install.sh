apt-get update 
apt-get install -y nmap python python3-pip vim build-essential pkg-config gcc wget curl make libpcap-dev zlib1g-dev libjpeg-dev rsync nodejs npm jq awscli
cd /usr/local/
wget -q https://golang.org/dl/go1.17.2.src.tar.gz
tar zxf go1.14.4.linux-amd64.tar.gz
mkdir -p ~/.config/go
cat > ~/.config/go/env <_EOF_
GOROOT=/usr/local/go
GOBIN=$HOME/go/bin
GOPATH=$HOME/go
_EOF_

pip uninstall -y python-nmap
cd /tmp
git clone https://github.com/dogasantos/python-nmap
cd python-nmap
python setup.py install
cd /tmp
rm -rf python-nmap

cd /usr/share
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
make install

cd /usr/share
git clone https://github.com/robertdavidgraham/masscan masscan
cd masscan
make
make install

# fix old nodejs package provided by apt:
npm cache clean -f
npm install -g n
n stable
# fix missing chromium browser:
npm install -g puppeteer --unsafe-perm=true --allow-root

npm i -g wappalyzer --unsafe-perm=true --allow-root
ln -s /usr/local/lib/node_modules/wappalyzer/cli.js /usr/bin/wappalyzer

cd /usr/share/
git clone https://github.com/dogasantos/masstomap.git masstomap
echo '#!/bin/bash' > /usr/bin/masstomap
echo "python /usr/share/masstomap/masstomap.py \$@" >> /usr/bin/masstomap
cd masstomap
pip install -r requirements.txt
chmod 755 /usr/share/masstomap/masstomap.py
chmod 755 /usr/bin/masstomap

cd /usr/share/
git clone git@github.com:dogasantos/automator.git
cd automator
bash install.sh

cd /usr/share
git clone https://github.com/GerbenJavado/LinkFinder.git linkfinder
pip install jsbeautifier argparse
echo '#!/bin/bash' >/usr/bin/linkfinder
echo "python /usr/share/linkfinder/mod_linkfinder.py \$@" >> /usr/bin/linkfinder
chmod 755 /usr/bin/linkfinder


cd /usr/share/
git clone https://github.com/sa7mon/S3Scanner.git s3scanner
cd s3scanner
pip install -r requirements.txt
echo '#!/bin/bash' >/usr/bin/s3scanner
echo "python /usr/share/s3scanner/s3scanner.py \$@" >> /usr/bin/s3scanner
chmod 755 /usr/bin/s3scanner

cd /usr/share
git clone https://github.com/dogasantos/webmapper.git
cd webmapper
pip install -r requirements
echo '#!/bin/bash' > /usr/bin/webmapper
echo "python3 $workdir/webmapper.py \$@" >> /usr/bin/webmapper
chmod 755 /usr/bin/webmapper



go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/projectdiscovery/proxify/cmd/proxify@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/dogasantos/prefixcheck/cmd/prefixcheck@latest
go install -v github.com/netevert/delator@latest
go install -v github.com/dogasantos/tls-scan-hostgrabber@latest
go install -v github.com/dogasantos/aggro@latest
go install -v github.com/dogasantos/dhv@latest
go install -v github.com/dogasantos/hof@latest
go install -v github.com/dogasantos/hakrawler@latest
go install -v github.com/unstppbl/gowap@latest
go install -v github.com/cgboal/sonarsearch/cmd/crobat@latest

