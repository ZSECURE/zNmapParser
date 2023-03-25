# zNmap Parser

zNmap Parser is a Python script that parses the output of the nmap tool and categorizes the open ports on each host. The script can help identify potential attack vectors during a penetration testing engagement.

## Requirements

- Python 3.6+
- `argparse` library (`pip install argparse`)
- `termcolor` library (`pip install termcolor`)
- `nmap` tool (https://nmap.org/)

## Usage

1. Run the nmap tool on the target network to generate a scan report:
`nmap -oN scan_results.txt <target_network>`

2. Run the zNmap Parser script on the scan report:
`python3 zNmap-Parser.py scan_results.txt`
This will parse the nmap output and categorize the open ports on each host.

3. The script will print the results to the console and save them to an output file (if specified).

## Categories

The zNmap Parser script categorizes open ports on each host into the following categories:

- Domain controllers
- Printers
- Web servers
- Windows hosts
- Linux hosts
- Database servers
- VPN servers
- Remote access tools
- Exploitable services
- DNS servers
- FTP servers
- Email servers
- VoIP servers
- File sharing services
- Remote administration tools

## Output

The script prints the results to the console and saves them to an output file (if specified). The output is formatted as follows:
```
<category>:
<host>: <port>, <port>, ...
<host>: <port>, <port>, ...
...

<category>:
<host>: <port>, <port>, ...
<host>: <port>, <port>, ...
...

...
```

- `<category>`: The name of the category (e.g., "Web servers", "Exploitable services", etc.).
- `<host>`: The IP address of the host that has the open ports.
- `<port>`: The port number that is open on the host.

## License

This script is licensed under the MIT License. See the LICENSE file for more information.

## Disclaimer

This script is intended for educational and/or penetration testing purposes only. Use of this script on a network without explicit permission from the network owner is illegal and may result in criminal and/or civil liability. The author of this script is not responsible for any damages or legal issues caused by the use or misuse of this script.
