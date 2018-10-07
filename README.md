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
```spl_at_tide_lookup_cli.py``` is an external lookup tool for Splunk which returns an active threat property (or properties) for ip-addresses, hostnames/domains, URLs.
You may use the lookup tool to enrich any event/log message which contains an IP-address, domain/hostname or URL. 
```spl_at_tide_lookup_cli.py``` uses a local cache of all active indicators. The local cache is updated by ```spl_at_tide_db_update.sh``` script which should be periodically executed by Cron.   
<p align="center"><img src="https://github.com/Homas/Splunk_AT_Lookup/blob/master/img/event_enrichment.png"></p>
On the screenshot you can see sshd server authentication errors logs which are attributed with threat properties by a source IP address.

# Prerequisites 
The scripts are using the following utilities:
* jq
* sqlite3

## Prerequisites installation on Ubuntu 18.04
```
sudo add-apt-repository universe
sudo apt-get update
sudo apt-get install jq sqlite3
```

# How to use
## Configuration
To use the external lookup tool you need:
1. Create a database directory (by default ```/opt/splunk/cache```)
2. Set Infolbox TIDE API KEY in ```$CPATH/at_api_key.txt```
3. Copy scripts to ```$SPLUNK_HOME/etc/searchscripts``` or ```$SPLUNK_HOME/etc/apps/<app_name>/bin``` and make them executable.
4. Create a crontab task to automatically update the database
5. Create an external lookup 

### DB dir
DB and TIDE API key are stored in ```/opt/splunk/cache``` by default. If you want to use a different directory change CPATH variable in both scripts.
### API key
```$CPATH/at_api_key.txt``` file should contain only Infoblox TIDE API key. No new line, spaces or any other extra charachters are allowed.
### Crontab
The cache database is big enough and it is recommended to update it once a day.
Below you can find a sample crontab schedule for a script which is located in ```/opt/etc/searchscripts/```. 
```
0 * * * *  /opt/etc/searchscripts/spl_at_tide_db_update.sh
```
You may also use Splunk scheduler to execute the script.
### External Lookup
You need to set up an external look up with the following parameters:
- ```Command``` set to ```spl_at_tide_lookup_cli.py ip host url```
- ```Supported fields``` set to ```ip,host,url,property```
<p align="center"><img src="https://github.com/Homas/Splunk_AT_Lookup/blob/master/img/spl_external_lookup.png"></p>

### Splunk documentation
The Splunk external lookup configuration described in details by [this](https://docs.splunk.com/Documentation/Splunk/7.2.0/Knowledge/DefineanexternallookupinSplunkWeb) link.
## Examples
### IP Lookup
Lookup a threat property for an IP address in the *address* field.
```
... | lookup spl_at_lookup ip as address OUTPUT property as "Threat Property"
```
### Domain Lookup
Lookup a threat property for a domain/host in the *domain* field.
```
... | lookup spl_at_lookup host as domain OUTPUT property as "Threat Property"
```
### URL Lookup
Lookup a threat property for a URL in the *URL* field.
```
... | lookup spl_at_lookup url as URL OUTPUT property as "Threat Property"
```
# Debug
## Debug in CLI
To debug the lookup tool in CLI:
1. Login to the Splunk server
2. Execute the following command as a Splunk user (specify a path to spl_at_tide_lookup_cli.py which is relevant on you server)
```
$ echo -e "ip,host,url,property\n,www.eicar.co,,"|/opt/splunk/bin/splunk cmd python /opt/etc/searchscripts/spl_at_tide_lookup_cli.py
```
3. Check the response
```
ip,host,url,property
"",eicar.co,"",MaliciousNameserver_Generic
```
## Debug in Splunk Search
To debug the lookup tool in Search:
1. Execute the following search 
```
index=* | head 1 | eval domain="eicar.co" | lookup spl_at_lookup host as domain OUTPUT property as "Threat Property" | table domain, "Threat Property"
```
2. Check that the resulting table looks like

| domain  | Threat Property |
| ------- | ---------------------------- |
| eicar.co | MaliciousNameserver_Generic |
