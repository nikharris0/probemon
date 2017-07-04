# probemon
A simple command line tool for monitoring and logging 802.11 probe frames

I decided to build this simple python script using scapy so that I could record 802.11 probe frames over a long period of time. This was specifically useful in my use case: proving that a person or device was present at a given location at a given time.

## Usage

```
usage: probemon.py [-h] -i INTERFACE [-t {iso,unix}] [-o OUTPUT]
                   [-b MAX_BYTES] [-c MAX_BACKUPS] [-d DELIMITER] [-f] [-s]
                   [-r] [-D] [-l]

a command line tool for logging 802.11 probe request frames

optional arguments:
  -h, --help      show this help message and exit

Interface:
  -i INTERFACE    Capturing interface

Log options:
  -t {iso,unix}   Time format (default: iso)
  -o OUTPUT       Log file (default: probemon.log)
  -b MAX_BYTES    Log rotation size in bytes (default: 5242880 (5MB))
  -c MAX_BACKUPS  Number log files to keep (default: 200)
  -d DELIMITER    Field delimiter (default: \t)
  -f              Exclude MAC address vendor from output
  -s              Exclude SSID probe from output
  -r              Exclude rssi from output

Additional options:
  -D              Enable debug output
  -l              Enable scrolling live view of the logfile
```

