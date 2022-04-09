# Vulner
The Bash script uses well known tools in the industry , and automates them for the user.
Please use this for your own goodwill.
My in my inspiration for this script is from studying cybersecurity in John Bryce.

### Vulner
The the main purpose for this tool is for anyone who wants to test his network for vulnerabilities.
    The tool uses tools such as Nmap, masscan and Tshark.
        Scanning the network and giving the user information about the devices found on that specific network.
            This tool works on LAN and WAN networks.


### The tools that script will use are:
1.	Nmap + NSE (Nmap Script Engine)
2.	Masscan
3.	Thsark ( allows the user  to look through the pcap file )
4.	SearchSploit

The script requires the user to have the tools installed on his machine.
Built-in function will update and download the tools required to continue with the script.


### The objective
The script will map netwrok devices for ports, services and vulnerabilities 
 
 # Step 1
Getting user input
    The user enters the network range, and a new directory should be created.

# Step 2
Mapping ports and services
    The script scans and maps the network, saving information into the directory.

# Step 3
Mapping vulnerabilities
    The script will look for vulnerabilities using the nmap scripting engine,
        searchsploit, and finding weak passwords used in the network.

# Step 4
Displaying results
    At the end of the scan, show the user the general scanning statistics.


