#!/bin/bash
echo "
 __  __             ______ _  ____
|  ||  | ___ __  __|__   /(_)|  _ \
|      |/  _\\ \/ /  /  / | || |_) |
|  _   |  __/ >  <  /  /__| ||  __/
|__||__|\___|/_/\_\/______|_||_|    v1.1

"

help(){
  echo "
Usage: ./HexZip.sh [options] -d domain.com
Options:
    -h            Display this help message.
    -k            Run Knockpy on the domain.
    -n            Run Nmap on all subdomains found.
    -a            Run Arjun on all subdomains found.
    -p            Run Photon crawler on all subdomains found.
    -b            Run Custom Bruteforcer to find subdoamins.

  Target:
    -d            Specify the domain to scan.
  
Example:
    ./Hexzip.sh -d hackerone.com
"
}
POSITIONAL=()

if [[ "$*" != *"-d"* ]]
then
	help
  exit
fi

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -h|--help)
    help
    exit
    ;;
    -d|--domain)
    d="$2"
    shift
    shift
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

echo "Starting SubEnum $d"

echo "Creating directory"
set -e
if [ ! -d $PWD/HexZip ]; then
    mkdir HexZip
fi
if [ ! -d $PWD/HexZip/$d ]; then
    mkdir HexZip/$d
fi
source tokens.txt

echo "starting our subdomain enumeration force..."


if [[ "$*" = *"-k"* ]]
then
	echo "Starting KnockPy"
	mkdir HexZip/$d/knock
	cd HexZip/$d/knock; python ../../../knock/knockpy/knockpy.py "$d" -j; cd ../../..
fi

echo "Starting Sublist3r..."
python3 Sublist3r/sublist3r.py -d "$d" -o HexZip/$d/fromsublister.txt

echo "Amass turn..."
amass enum --passive -d $d -o HexZip/$d/fromamass.txt

echo "Starting subfinder..."
./subfinder -d $d -o HexZip/$d/fromsubfinder.txt -v --exclude-sources dnsdumpster

echo "Starting assetfinder..."
./assetfinder --subs-only $d > HexZip/$d/fromassetfinder.txt

echo "Starting aquatone-discover"
aquatone-discover -d $d --disable-collectors dictionary -t 300
rm -rf amass_output
cat ~/aquatone/$d/hosts.txt | cut -f 1 -d ',' | sort -u >> HexZip/$d/fromaquadiscover.txt
rm -rf ~/aquatone/$d/

echo "Starting github-subdomains..."
python3 github-subdomains.py -t $github_token_value -d $d | sort -u >> HexZip/$d/fromgithub.txt

echo "Starting findomain"
export findomain_fb_token="$findomain_fb_token"
export findomain_spyse_token="$findomain_spyse_token"
export findomain_virustotal_token="$findomain_virustotal_token"

./findomain -t $d -r -u HexZip/$d/fromfindomain.txt

nl=$'\n'
echo "Starting bufferover"
curl "http://dns.bufferover.run/dns?q=$d" --silent | jq '.FDNS_A | .[]' -r 2>/dev/null | cut -f 2 -d',' | sort -u >> HexZip/$d/frombufferover-dns.txt
echo "$nl"
echo "Bufferover DNS"
echo "$nl"
cat HexZip/$d/frombufferover-dns.txt
curl "http://dns.bufferover.run/dns?q=$d" --silent | jq '.RDNS | .[]' -r 2>/dev/null | cut -f 2 -d',' | sort -u >> HexZip/$d/frombufferover-dns-rdns.txt
echo "$nl"
echo "Bufferover DNS-RDNS"
echo "$nl"
cat HexZip/$d/frombufferover-dns-rdns.txt
curl "http://tls.bufferover.run/dns?q=$d" --silent | jq '. | .Results | .[]'  -r 2>/dev/null | cut -f 3 -d ',' | sort -u >> HexZip/$d/frombufferover-tls.txt
echo "$nl"
echo "Bufferover TLS"
echo "$nl"
cat HexZip/$d/frombufferover-tls.txt

if [[ "$*" = *"-b"* ]]
then
  echo "Starting our custom bruteforcer"
  for sub in $(cat subdomains.txt); do echo $sub.$d >> /tmp/sub-$d.txt; done
  ./massdns/bin/massdns -r massdns/lists/resolvers.txt -s 1000 -q -t A -o S -w /tmp/subresolved-$d.txt /tmp/sub-$d.txt
  rm /tmp/sub-$d.txt
  awk -F ". " "{print \$d}" /tmp/subresolved-$d.txt | sort -u >> HexZip/$d/fromcustbruter.txt
  rm /tmp/subresolved-$d.txt
fi
cat HexZip/$d/*.txt | grep $d | grep -v '*' | sort -u  >> HexZip/$d/alltogether.txt

echo "Deleting other(older) results"
rm -rf HexZip/$d/from*

echo "Resolving - Part 1"
./massdns/bin/massdns -r massdns/lists/resolvers.txt -s 1000 -q -t A -o S -w /tmp/massresolved1.txt HexZip/$d/alltogether.txt
awk -F ". " "{print \$1}" /tmp/massresolved1.txt | sort -u >> HexZip/$d/resolved1.txt
rm /tmp/massresolved1.txt
rm HexZip/$d/alltogether.txt

echo "Removing wildcards"
python3 wildcrem.py HexZip/$d/resolved1.txt >> HexZip/$d/resolved1-nowilds.txt
rm HexZip/$d/resolved1.txt

echo "Starting AltDNS..."
altdns -i HexZip/$d/resolved1-nowilds.txt -o HexZip/$d/fromaltdns.txt -t 300

echo "Resolving - Part 2 - Altdns results"
./massdns/bin/massdns -r massdns/lists/resolvers.txt -s 1000 -q -o S -w /tmp/massresolved1.txt HexZip/$d/fromaltdns.txt
awk -F ". " "{print \$1}" /tmp/massresolved1.txt | sort -u >> HexZip/$d/altdns-resolved.txt
rm /tmp/massresolved1.txt
rm HexZip/$d/fromaltdns.txt

echo "Removing wildcards - Part 2"
python3 wildcrem.py HexZip/$d/altdns-resolved.txt >> HexZip/$d/altdns-resolved-nowilds.txt
rm HexZip/$d/altdns-resolved.txt

cat HexZip/$d/*.txt | sort -u >> HexZip/$d/alltillnow.txt
rm HexZip/$d/altdns-resolved-nowilds.txt
rm HexZip/$d/resolved1-nowilds.txt

echo "Starting DNSGEN..."
dnsgen HexZip/$d/alltillnow.txt >> HexZip/$d/fromdnsgen.txt

echo "Resolving - Part 3 - DNSGEN results"
./massdns/bin/massdns -r massdns/lists/resolvers.txt -s 1000 -q -t A -o S -w /tmp/massresolved1.txt HexZip/$d/fromdnsgen.txt
awk -F ". " "{print \$1}" /tmp/massresolved1.txt | sort -u >> HexZip/$d/dnsgen-resolved.txt
rm /tmp/massresolved1.txt
#rm /tmp/forbrut.txt
rm HexZip/$d/fromdnsgen.txt

echo "Removing wildcards - Part 3"
python3 wildcrem.py HexZip/$d/dnsgen-resolved.txt >> HexZip/$d/dnsgen-resolved-nowilds.txt
rm HexZip/$d/dnsgen-resolved.txt

cat HexZip/$d/alltillnow.txt | sort -u >> HexZip/$d/$d.txt
rm HexZip/$d/dnsgen-resolved-nowilds.txt
rm HexZip/$d/alltillnow.txt

echo "Appending http/s to hosts"
for i in $(cat HexZip/$d/$d.txt); do echo "http://$i" && echo "https://$i"; done >> HexZip/$d/with-protocol-domains.txt
cat HexZip/$d/$d.txt | ~/go/bin/httprobe | tee -a HexZip/$d/alive.txt

echo "Taking screenshots..."
cat HexZip/$d/with-protocol-domains.txt | ./aquatone -ports xlarge -out HexZip/$d/aquascreenshots

if [[ "$*" = *"-a"* ]]
then
	cat HexZip/$d/$d.txt | ~/go/bin/httprobe | tee -a HexZip/$d/alive.txt
	python3 Arjun/arjun.py --urls HexZip/$d/alive.txt --get -o HexZip/$d/arjun_out.txt -f Arjun/db/params.txt
fi

 
echo "Total hosts found: $(wc -l HexZip/$d/$d.txt)"

if [[ "$*" = *"-n"* ]]
then
	echo "Starting Nmap"
  if [ ! -d $PWD/HexZip/$d/nmap ]; then
  	mkdir HexZip/$d/nmap
  fi
	for i in $(cat HexZip/$d/$d.txt); do nmap -sC -sV $i -o HexZip/$d/nmap/$i.txt; done
fi

if [[ "$*" = *"-p"* ]]
then
	echo "Starting Photon Crawler"
  if [ ! -d $PWD/HexZip/$d/photon ]; then
  	mkdir HexZip/$d/photon
  fi
	for i in $(cat HexZip/$d/$d.txt); do python3 Photon/photon.py -u $i -o HexZip/$d/photon/$i -l 2 -t 50; done
fi

echo "Checking for Subdomain Takeover"
python3 subdomain-takeover/takeover.py -d $d -f HexZip/$d/$d.txt -t 20 | tee HexZip/$d/subdomain_takeover.txt

echo "Starting DirSearch"
if [ ! -d $PWD/HexZip/$d/dirsearch ]; then
	mkdir HexZip/$d/dirsearch
fi
for i in $(cat HexZip/$d/$d.txt); do python3 dirsearch/dirsearch.py -e php,asp,aspx,jsp,html,zip,jar -w dirsearch/db/dicc.txt -t 80 -u $i --plain-text-report="HexZip/$d/dirsearch/$i.txt"; done

echo "Notifying you on slack"
curl -X POST -H 'Content-type: application/json' --data '{"text":"HexZip finished scanning: '$d'"}' $slack_url

echo "Finished successfully."