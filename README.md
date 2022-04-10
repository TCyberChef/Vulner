# Vulner
The Bash script uses well known tools in the industry , and automates them for the user.
Please use this for your own goodwill.
My inspiration for this script came from studying cybersecurity in John Bryce.

The the main purpose for this tool is for anyone who wants to test his network for vulnerabilities.
    The tool uses tools such as Nmap, masscan and Tshark.
        Scanning the network and giving the user information about the devices found on that specific network.
            This tool works on LAN and WAN networks.

##

<h3><p align="center">Disclaimer</p></h3>

<i>Any actions and or activities related to <b>Vulner</b> is solely your responsibility. The misuse of this toolkit can result in <b>criminal charges</b> brought against the persons in question. <b>The contributors will not be held responsible</b> in the event any criminal charges be brought against any individuals misusing this toolkit to break the law.

<b>This toolkit contains materials that can be potentially damaging or dangerous for social media</b>. Refer to the laws in your province/country before accessing, using,or in any other way utilizing this in a wrong way.

<b>This Tool is made for educational purposes only</b>. Do not attempt to violate the law with anything contained here. <b>If this is your intention, then Get the hell out of here</b>!

It only demonstrates "how phishing works". <b>You shall not misuse the information to gain unauthorized access to someones social media</b>. However you may try out this at your own risk.</i>

##

### Installation

- Make sure that you have git installed -
```
$ apt install git
```
- Just, Clone this repository -
```
$ git clone https://github.com/TCyberChef/Vulner
```

- Change to cloned directory and run `zphisher.sh` -
```
$ cd Vulner
$ bash Vulner.sh
```
or
```
$ cd Vulner
$ chmod 777 Vulner.sh
$ ./Vulner.sh
```

- On first launch, It'll install the dependencies and that's it. `Zphisher` is installed.


The script requires the user to have the tools installed on his machine.
Built-in function will update and download the tools required to continue with the script.


### Dependencies

**`Vulner`** requires following programs to run properly - 
- `Nmap + NSE (Nmap Script Engine)`
- `Masscan`
- `Thsark`
- `SearchSploit`

> All the dependencies will be installed automatically when you run `Vulner` for the first time.



### Features
- The script will map netwrok devices for ports, services and vulnerabilities 
- Getting user input
- The user enters the network range, and a new directory should be created.

- Mapping ports and services
- The script scans and maps the network, saving information into the directory.


- Mapping vulnerabilities
- The script will look for vulnerabilities using the nmap scripting engine,
- searchsploit, and finding weak passwords used in the network.

- Displaying results
- At the end of the scan, show the user the general scanning statistics.


