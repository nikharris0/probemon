# probemon
Modified to allow excluded list of MAC addresses, added daemon mode, and added quotes to the fields for SIEM output.



A simple command line tool for monitoring and logging 802.11 probe frames

I decided to build this simple python script using scapy so that I could record 802.11 probe frames over a long period of time. This was specifically useful in my use case: proving that a person or device was present at a given location at a given time.

## Usage

```
usage: probemon.py [-h] [-i INTERFACE] [-t TIME] [-o OUTPUT] [-b MAX_BYTES]
                   [-c MAX_BACKUPS] [-d DELIMITER] [-f] [-s] [-r] [-D] [-l]
                   [-e EXCLUDE] [-z]

a command line tool for logging 802.11 probe request frames

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        capture interface
  -t TIME, --time TIME  output time format (unix, iso)
  -o OUTPUT, --output OUTPUT
                        logging output location
  -b MAX_BYTES, --max-bytes MAX_BYTES
                        maximum log size in bytes before rotating
  -c MAX_BACKUPS, --max-backups MAX_BACKUPS
                        maximum number of log files to keep
  -d DELIMITER, --delimiter DELIMITER
                        output field delimiter
  -f, --mac-info        include MAC address manufacturer
  -s, --ssid            include probe SSID in output
  -r, --rssi            include rssi in output
  -D, --debug           enable debug output
  -l, --log             enable scrolling live view of the logfile
  -e EXCLUDE, --exclude EXCLUDE
                        list of MAC addresses to exclude from output, one MAC
                        per line
  -z, --daemon          fork process and run in background
