# Splunk Infolbox TIDE Threat Lookup tool
## Infoblox TIDE
Threat intelligence is evidence-based knowledge, including context, mechanisms, indicators, implications and actionable advice, about an existing
or emerging threat or hazard. It can be used to inform decisions regarding the subject’s response to that threat or hazard. Threats can come from
internal as well as external sources, and can come in the form of malicious IP addresses, hostnames, domain names and URLs.

TIDE is available as part of ActiveTrust Suite. Infoblox ActiveTrust Suite uses highly accurate machine-readable threat intelligence data via a
flexible and open Threat Intelligence Data Exchange (TIDE) platform to aggregate, curate, and enable distribution of data across a broad range of
infrastructures.

TIDE enables organizations to ease consumption of threat intelligence from various internal and external sources, and to effectively defend
against and quickly respond to threats.

<p align="center"><img src="https://github.com/Homas/Splunk_AT_Lookup/blob/master/img/TIDE.png"></p>

## spl_at_tide_lookup_cli.py
spl_at_tide_lookup_cli.py is an external lookup tool for Splunk which returns a threat property for ip-addresses, hostnames and domains. 
It uses a local cache in SQLite3. The local cache is updated by spl_at_tide_db_update.sh script which should be periodically executed by cron.   

spl_at_tide_db_update.sh and spl_at_tide_lookup_cli.py

<p align="center"><img src="https://github.com/Homas/Splunk_AT_Lookup/blob/master/img/event_enrichment.png"></p>

# Prerequisites 
* jq
* sqlite3

## Installation on Ubuntu 18
```
sudo add-apt-repository universe
sudo apt-get update
sudo apt-get install jq sqlite3
```

# How to use
## Configuration
### Cache dir
DB and TIDE API key are stored in ```/opt/splunk/cache``` by default. If you want to use a different directory change CPATH variable in spl_at_tide_db_update.sh and spl_at_tide_lookup_cli.py files.
### API key
### Crontab
### External Lookup
<p align="center"><img src="https://github.com/Homas/Splunk_AT_Lookup/blob/master/img/spl_external_lookup.png"></p>


## Usage examples

