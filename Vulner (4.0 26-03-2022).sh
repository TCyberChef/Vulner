#!/bin/bash
##
##   script that maps network devices for ports, services, and vulnerabilities.
##
## 			fully automated 
##

	



### 
### Sudo Verification 
### 
### 
### 

	if [[ "$EUID" = 0 ]]; then
		    echo "Root Access Granted"
		    sleep 2
		function install()
		{
			apt update && apt install tshark nmap masscan 
		}
		sleep 1
		echo 
		echo "Making sure you're up-to-date with all the tools needed"
		echo 
	    install
	 clear
		
		
		
		else
		echo " [*] Please run the script as sudo. [*] "
		        echo "Usage: sudo ./vulner {Network Range} "
		        echo
		        echo "Your Input: $0 $1 "
		        echo
		        echo "Vulner:  2.6V (CyberChef) " ; sudo -k ; exit  # make sure to ask for password on next sudo
		    
	fi
	
	
##  checking the user's input for typo in their input.

        userinput1=$1
        IPrange=$userinput1
        IPclean=$(echo "$IPrange" |cut -d'/' -f1)
        ip=${1:-1.2.3.4}
            if expr "$ip" : '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\/[0-9][0-9]*$' >/dev/null; 
                    then
                    for i in 1 2 3 4  ;
                        do
                            ipNOsubnet=$(echo "$ip" |cut -d'/' -f1)
                            if [ "$(echo "$ipNOsubnet" | cut -d. -f$i )" -gt 255 ]; 
                                then
                                    echo "Your Input: $ip"
                                    echo
                                    echo "fail ($ip)"
                                    echo "One of the values is greater then 255 therefor invalid"
                                    echo "IP address must be between 0.0.0.0 and 255.255.255.255"
                                    exit 1
                            fi
                    done
            fi
            
            
            ipSUBNET=$(echo "$ip" | awk -F "/" '{print $2}')
                if [[ -z "$ipSUBNET" ]];
                then
                    echo "Your Input: $ip"
                    echo
                    echo "Netmask not present or invalid"
                    echo
                    echo "Must Input a subnet mask for the IP address to set the Network Range"
                    echo
                    echo "Try Again"
                    echo
                    echo "Please Enter A Valid Network Range Expl: 10.0.0.0/24 , 172.16.0.0/12 etc."
                    echo
                    echo "Usage: sudo ./vulner {Network Range} "
                    echo
                    echo "Vulner:  2.6V (CyberChef) "
                    exit 1
                elif [[ "$ipSUBNET" -ge 32 ]];
                then
                    echo "Your Input: $ip"
                    echo
                    echo "Netmask not present or invalid"
                    echo
                    echo "Must Input a subnet mask for the IP address to set the Network Range"
                    echo
                    echo "Try Again"
                    echo
                    echo "Please Enter A Valid Network Range Expl: 10.0.0.0/24 , 172.16.0.0/12 etc."
                    echo
                    echo "Usage: sudo ./vulner {Network Range} "
                    echo
                    echo "Vulner:  2.6V (CyberChef) "    
                    exit 1
                fi
ip=$1
           ### 
###
###   Bash script for calculating network and broadcast addresses from ip and netmask or CIDR Notation 
### Link https://gist.github.com/cskeeters/278cb27367fbaa21b3f2957a39087abf
#       @cskeeters
#       cskeeters/broadcast_calc.sh
#       Created 5 years ago
#       Chad Skeeters "cskeeters" | San Antonio, TX, USA 
###

## 
## User's input of network range is broken down to 

##  Subnetmask,netID,BroadCast address
## 
            tonum() {
                if [[ $1 =~ ([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+) ]]; then
                    addr=$(( (${BASH_REMATCH[1]} << 24) + (${BASH_REMATCH[2]} << 16) + (${BASH_REMATCH[3]} << 8) + ${BASH_REMATCH[4]} ))
                    eval "$2=\$addr"
                fi
            }
            toaddr() {
                b1=$(( ($1 & 0xFF000000) >> 24))
                b2=$(( ($1 & 0xFF0000) >> 16))
                b3=$(( ($1 & 0xFF00) >> 8))
                b4=$(( $1 & 0xFF ))
                eval "$2=\$b1.\$b2.\$b3.\$b4"
            }

            if [[ $1 =~ ^([0-9\.]+)/([0-9]+)$ ]]; then
                # CIDR notation
                IPADDR=${BASH_REMATCH[1]}
                NETMASKLEN=${BASH_REMATCH[2]}
                zeros=$((32-NETMASKLEN))
                NETMASKNUM=0
                for (( i=0; i<$zeros; i++ )); do
                    NETMASKNUM=$(( (NETMASKNUM << 1) ^ 1 ))
                done
                NETMASKNUM=$((NETMASKNUM ^ 0xFFFFFFFF))
                toaddr $NETMASKNUM NETMASK
            else
                IPADDR=${1:-192.168.1.1}
                NETMASK=${2:-255.255.255.0}
            fi

            tonum $IPADDR IPADDRNUM
            tonum $NETMASK NETMASKNUM

            #printf "IPADDRNUM: %x\n" $IPADDRNUM
            #printf "NETMASKNUM: %x\n" $NETMASKNUM

            # The logic to calculate network and broadcast
            INVNETMASKNUM=$(( 0xFFFFFFFF ^ NETMASKNUM ))
            NETWORKNUM=$(( IPADDRNUM & NETMASKNUM ))
            BROADCASTNUM=$(( INVNETMASKNUM | NETWORKNUM ))

            IPADDRBIN=$(   python -c "print(bin(${IPADDRNUM}   )[2:].zfill(32))")
            NETMASKBIN=$(  python -c "print(bin(${NETMASKNUM}  )[2:].zfill(32))")
            NETWORKBIN=$(  python -c "print(bin(${NETWORKNUM}  )[2:].zfill(32))")
            BROADCASTBIN=$(python -c "print(bin(${BROADCASTNUM})[2:].zfill(32))")

            toaddr $NETWORKNUM NETWORK
            toaddr $BROADCASTNUM BROADCAST
            ##https://gist.github.com/cskeeters/278cb27367fbaa21b3f2957a39087abf
            ##
            ##
            ##
userinput1=$1
IPrange=$userinput1
IPclean=$(echo "$IPrange" |cut -d'/' -f1)
###
###
###
###

## The user enters the network range, and a new directory is created.
###
### "Splash screen" 
## general info, log , and disclaimer 
###
TIMESTAMP=$(date +%k:%M:%S%n%A-%D)
echo
echo "                                      Vulner."
echo
echo "                [*]   MAKE SURE YOU RUN Vulner AS sudo     [*]"
echo "              [*]            sudo ./vulner {networkrange}                      [*]"
echo 
echo        "                   This tool should be used with caution"
echo
echo "             Please note that the network traffic the tool generates **MAYBE ILLEGAL**"
echo "                                  USE WITH CAUTION!"
echo
echo
echo
echo "[*] Mapping the range $IPrange"
echo "[+] Directory created: $IPclean"
echo 
echo
    
    mkdir -p "$IPclean"
    
    ##LOGGING CIDR  
{
printf "%-25s %s\n" "IPADDR=$IPADDR"       $IPADDRBIN
printf "%-25s %s\n" "NETMASK=$NETMASK"     $NETMASKBIN
printf "%-25s %s\n" "NETWORK=$NETWORK"     $NETWORKBIN
printf "%-25s %s\n" "BROADCAST=$BROADCAST" $BROADCASTBIN
} > "$IPclean"/"$IPclean"_CIDR_details
        
    ## logging number of ip's in the network
        NUMBEROFHOSTSINRANGE=$(nmap "$IPrange" -sL -n -oN Potential)
        NUMBEROFHOSTSINRANGE1=$(cat Potential |grep 'for' -c)
        echo
        echo "[&] Additional information about the given Network range"
        cat "$IPclean"/"$IPclean"_CIDR_details
        echo
        echo "$NUMBEROFHOSTSINRANGE1 <- Potential Hosts In Network Range"
        rm Potential
        echo
        
##

### Scanning for uphosts in the network range
 
###  logging the IP's that responded to the ping

#####  
        (
        TIMESTAMP=$(date +%k:%M:%S%n%A-%D)
            cd "$IPclean" || exit
            echo
            echo
            echo "Logging Scan timestamp:$TIMESTAMP"
            echo "scan started at :" >> timelog
            echo "$TIMESTAMP" >> timelog
            echo
		        masscan "$IPrange" --ping --rate=1200 --wait=5 -oL PingScan
		        LINES=$(cat PingScan | grep open -c)
			echo
			echo "$LINES <- Online Hosts In Network Range"
			echo
			echo "[*] Starting Scan on $LINES Hosts [*]"
			echo
			IPaddresses=$(cat PingScan | grep  open | awk '{print $4}' | sort -u )
			echo "[*] Host's IPs found:"
			echo "$IPaddresses"" "
			echo
        )




###
### Scanning the IPs found in previous function 
###
### 
### special addon by me , tshark is running in the background , giving the user  
### 	a pcap file for the scan duration 
### 
function scan()
    {
		    IPrange=$userinput1
		    IPclean=$(echo "$IPrange" |cut -d'/' -f1)
			## Staring terminal shark.
			## basiclly opens wireshark in the background to give the user pcap file at the end of the script.
			mkdir -p $IPclean/SCAN
			echo
			tshark -i 1 -w $IPclean/SCAN/Scan.pcap -q & echo " [*] Tshark Starting [*] " ; sleep 5 &&echo
			echo
			## 
			## For loop for checking Online end devices Inside the given network range.
			##
    
        (
			cd "$IPclean" || exit
			IPaddresses=$(cat PingScan | grep open | awk '{print $4}' | sort -u )
            echo "$IPaddresses">>IP_Hosts
			echo
			echo " [*] Starting Nmap TCP SCAN. [*] "
			echo
			nmap -iL IP_Hosts -T4 -top-ports 10000 -oN NmapTCP -n
			cat NmapTCP | grep / |cut -d/ -f1 | sort -u > TCPports
			echo
			echo " [*] Starting Masscan UDP SCAN. [*] "
			echo
			MasscanUDP=$(masscan -iL IP_Hosts -pU:0-50000 --rate=5000 --wait=5 -oL MasscanUDP)
			cat MasscanUDP | grep udp |awk '{print $3}' | sort -u > UDPports
			##
			
			TCPports=$(sed 's/.*/&/;$!s/$/,/' TCPports | tr -d '\n')
			UDPports=$(sed 's/.*/&/;$!s/$/,/' UDPports | tr -d '\n')
			
			## Decending list converter. and inspretion
			## https://stackoverflow.com/a/41940103 ^^^
			##
			echo
			echo -ne " Open Ports Found. " ; sleep 1 ; printf " Starting Nmap VersionScanner For Open Ports Found, Sit Tight"
			echo 
			echo " [*] --------------------------------------- [*] "
			echo
			echo "  NOTICE:Nmap Version Scan is an aggressive scan which can take time to perform well. "
			echo
			_NmapVersionScan=$(nmap -iL IP_Hosts -pT:"$TCPports" -sT -sV -T4 -oN ServiceVersion.NSE -oX ServiceVersion.xml )
			echo
			echo " 		Fetching OS info"
			echo " [*] --------------------------------------- [*] "
			echo
			_nmapOSSCAN=$(nmap -iL IP_Hosts -O -T4 -oN OperatingSystem.NSE )
			echo
        )
}


##
## After we scanned the networkrange and hopfully found somthing intersting
##  The script will automaticly look for vulnerabilities by version of the service
##
## Using [*]NSE[*]

##      [*]SearchSploit[*]

function NSE ()
    {
        
    IPrange=$userinput1
    IPclean=$(echo "$IPrange" |cut -d'/' -f1)
    (
        cd "$IPclean" || exit
            TCPports=$(sed 's/.*/&/;$!s/$/,/' TCPports | tr -d '\n')
            UDPports=$(sed 's/.*/&/;$!s/$/,/' UDPports | tr -d '\n')
                echo 
                echo "      NSE Is Scanning For Vulnerabilities "
                echo " [*] --------------------------------------- [*] "

                NMAPSCRIPTSCAN=$(nmap -sT -sU -sC -T4 -iL IP_Hosts -pT:"$TCPports",U:"$UDPports" -oX NmapVulneFound.xml -oN NmapVulneFound.nmap)
                    echo
                            echo
                            echo "    NSE is Scanning for Authentication information "
							echo " [*] ----------------------------------------------- [*] "
                            echo
                            _NMAPauth=$(nmap -iL IP_Hosts -T4 --script=auth -oN authscript.NSE )
    )
	echo " Killing Tshark process "
	echo 

	tsharkproc=$(pgrep 'tshark')
kill $tsharkproc && echo " [*] Tshark Stopped [*] " ; sleep 5 &&echo
}

function SEARCHSPLOIT ()
    {
    IPrange=$userinput1
    IPclean=$(echo "$IPrange" |cut -d'/' -f1)
    mkdir -p "$IPclean"/SearchSploit
		(
		cd "$IPclean" || exit
		
		SEARCHSPLOITexploitlist=$(searchsploit --nmap ServiceVersion.xml --id > SearchSploit/ExploitsFound )
		FilteringSearchSploit=$(cat SearchSploit/ExploitsFound | grep "|" |cut -d'|' -f2- |sed 's/[a-z]*//g;s/[A-Z]*//g;s/[#$%*@\-|-]//g' > SearchSploit/EDB-ID)
		for EDBID in $(cat SearchSploit/EDB-ID |sort );
		do searchsploit -p "$EDBID";
		done > SearchSploit/Available_Exploits
		EXPLOITSfound=$(cat SearchSploit/Available_Exploits | grep -E "Exploit" -c)
		
		
		if [[ $EXPLOITSfound -gt 0 ]];
		then
		
			echo
			echo "[*] SearchSploit Found $EXPLOITSfound Potential Exploits Available [*]"
			echo "  [*] Full Exploit list can be found Inside SearchSploit Directory [*]"
			echo " [*] --------------------------------------- [*] "
			echo " You may also use SearchSploit manually "
			echo "  Nmap XML VersionScan can be found inside the XML Files Directory Created by Vulner "
			echo
		else
			echo " [*] --------------------------------------- [*] " 
			echo "No Exploits Found By SearchSploit Engine" 
			echo " You may use SearchSploit manually "
			echo "  Nmap XML VersionScan can be found inside the XML Files Directory Created by Vulner "
		fi
		)	
}



###
### Utilising NMAP nse brute script to automate the proccess.
###
###

### special addon by me , tshark is running in the background , giving the user  
### 	a pcap file for the brute duration 

function BRUTE ()
    {
		echo
		echo
		tshark -i 1 -w $IPclean/brute.pcap -q & echo " [*] Tshark Starting [*] " ; sleep 5 &&echo
		##
		echo 
        IPrange=$userinput1
        IPclean=$(echo "$IPrange" |cut -d'/' -f1)
           
           
		(
			cd "$IPclean" || exit
			TCPports=$(sed 's/.*/&/;$!s/$/,/' TCPports | tr -d '\n')
			echo
			echo " Starting NMAP NSE Brute"
			echo "   "
			
			echo " [*] --------------------------------------- [*] " 
			echo
			echo
			echo " Please Note That BruteForce attempts can take some time, Sit Tight.  "
			echo "      Undergoing Script Scan!! !! !! "
			echo
			TCPBRUTEnse=$(nmap --script=brute -iL IP_Hosts -pT:"$TCPports" -oN Brute.NSE -oX Brute.xml )
		)
	    echo " Killing Tshark process "
		echo 
	
		tsharkproc=$(pgrep 'tshark')
		kill $tsharkproc && echo " [*] Tshark Stopped [*] " ; sleep 5 &&echo

    }







###
###
### finally logging the results into a logfile and displaying the info to the user.
###

### and the script cleans after it self, orgnazing the directories by title. 


function LOG ()
    {
		sleep 3
        (
        IPrange=$userinput1
        IPclean=$(echo "$IPrange" |cut -d'/' -f1)
            cd "$IPclean" || exit
					_startofscan=$(head -3 timelog )
				echo "Scan Started at $_startofscan"
				echo
				echo
				echo
				echo
                echo '[*]IP Addresses SCANNED [*]'
                echo '----------------------------'
                cat IP_Hosts | sort | uniq
                echo
                sleep .2
                echo
                echo '[*] Services Found [*]'
                echo '----------------------------'
                cat ServiceVersion.NSE |grep -E 'open|scan report for|EST ' | awk '{print $0}' | uniq | sed 's/at/Time Stamp For Scan : /g;s/open/<- PORT   SERVICE->/g;s/syn-ack ttl 128/VERSION->/g;s/syn-ack ttl 64//g'
                echo
                sleep .2
                echo
                echo
                echo '[*]PC Names.[*]'
                echo '----------------------------'
                PCNAME=$(cat NmapVulneFound.nmap |grep -i computer |awk '{print $4}'|sort -u |sed 's/name://g')
                if [[ -n "$PCNAME" ]]
                then
                echo $PCNAME
                echo
                else
                echo "No PC name found"
                echo
                fi
                echo '[*]Operating system Found.[*]'
                echo '----------------------------'
                OSNAME=$(cat NmapVulneFound.nmap |grep -E 'OS:' |cut -d':' -f2-|uniq )
                    if [[ -n "$OSNAME" ]]
                    then
                        echo "$OSNAME"
                    else
                        echo "No OS Found"
                        echo
                    fi
                echo '[*]Vulnerabilities Nmap Found.[*]'
                echo '----------------------------'
                cat NmapVulneFound.nmap | sed 's/for /\n-->/g'
                    if [ -f "NmapVulneFound.nmap" ];
                    then
                        echo "Full Info Here : Nmap/NmapVulneFound.nmap "
                        echo
                    else
                        echo "Couldnt Find any vulnerabilities."
                        echo
                    fi
                echo " [*] OSs Found in the Network Range[*] "
                echo '----------------------------'
                cat OperatingSystem.NSE | grep -E "OS details:|MAC Address|Nmap scan" |sed 's/Nmap/\n↓Nmap/g'
                echo
                echo '[*]Valid credentials Found [*]'
                echo '----------------------------'
                _grepValid=$(cat Brute.NSE | grep Valid)
                    if [[ -n "$_grepValid" ]]
                    then
                        cat Brute.NSE | grep -E 'Valid|/tcp|Nmap scan '  |sed 's/syn-ack ttl 64//g;s/syn-ack ttl 128//g;s///g' | grep -E -B1 '(Valid|for )'
                        echo
                    else
                        echo "No Valid credentials Found."
                        echo
                    fi
                    _AvaliableExploits=$(cat SearchSploit/Available_Exploits | wc -l )
                    if [[ "$_AvaliableExploits" -gt 10 ]]
                    then
						
						
						echo
                        echo '[*] TOP 3 Backdoor Exploits Available [*]'
                        echo '----------------------------'
                        cat SearchSploit/Available_Exploits | grep Backdoor | head -3

						echo
                        echo '[*] TOP 3 Command Execution Exploits Available [*]'
                        echo '----------------------------'
                        cat SearchSploit/Available_Exploits | grep "Command Execution" |head -3
                
                
						echo
                        echo '[*] TOP 3 Remote Code Execution Exploits Available [*]'
                        echo '----------------------------'
                        cat SearchSploit/Available_Exploits | grep "Remote Code Execution" | head -3
                    else
                        echo "No Exploits Found."
                        echo    
                    fi                    
						
						echo
						echo "scan ended at: $TIMESTAMP "
						echo "scan ended at : $TIMESTAMP " >> timelog
						echo
						echo " Making Seder  hehe"
						echo "  organizing log directories' "
						echo "  Converting XML Files to HTML Readable format "
						echo " [*] --------------------------------------- [*] " 
						echo
						echo
						sleep 5
						###
						###
						xsltproc1=$(xsltproc NmapVulneFound.xml -o NmapVulneFound.html)
						xsltproc2=$(xsltproc ServiceVersion.xml -o ServiceVersion.html)
						xsltproc3=$(xsltproc Brute.xml -o Brute.html)						
						###
						###
						###
						mv SearchSploit/EDB-ID SearchSploit/.EDB-ID
						###
						###
						###
						mv IP_Hosts SCAN
						mv MasscanUDP SCAN
						mv NmapTCP SCAN
						mv PingScan SCAN
						mv TCPports SCAN/.TCPports
						mv UDPports SCAN/.UDPports
						mkdir -p NSE
						mv *.NSE NSE
						mv *.nmap NSE
						mv brute.pcap NSE
						mkdir -p HTML_baby_view
						mv *.html HTML_baby_view
						mv *.xml HTML_baby_view
						###
						###
						###
						###
						###
						sleep 2
						echo
						echo 
						echo "DONE!! Thanks :) "
						echo 
						echo
			) >> $IPclean/results.log
			cat $IPclean/results.log
    }
				LINES=$(grep 'open' -c  "$IPclean"/PingScan	)
            if [[ "$LINES" -gt 1 ]]
    then

    scan

    NSE

    SEARCHSPLOIT

    BRUTE
    
    LOG
    
    else
    
    figlet-figlet " No Hosts found " 

    echo
    
    echo "Make sure that you entered a right network range"
    
    echo "Please Enter A Valid Network Range Expl: 10.0.0.0/24 , 172.16.0.0/12 etc." ;
fi
