# mb68xx-utils
Utilities providing data logging and restart functionality for the Motorola MB6800 / MB6811 series
cable modems


## Usage

`actions.py` provides an entry point for usage within a script. Currently, information is logged
to the console in a very rudimentary format.

```bash
#!/bin/bash
export MODEM_PASSWORD="foobar"
# reboots the modem
python3 actions.py -r
```


## Environment Variables

Configuration is primarily provided via environment variables, as the modules are primarily
intended for non-interactive use.

| Variable       |                                                |
| -------------- | ---------------------------------------------- |
| MODEM_ADDRESS  | IP address or hostname (default 192.168.100.1) |
| MODEM_PASSWORD | Admin password for the modem                   |
