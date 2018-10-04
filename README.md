# Splunk Infolbox TIDE External Lookup tool
spl_at_tide_lookup_cli.py is an external lookup tool for Splunk which returns a threat property for ip-addresses, hostnames and domains
It uses a local cache in SQLite3. Local cache is updated daily by spl_at_tide_db_update.sh script which should be 

spl_at_tide_db_update.sh and spl_at_tide_lookup_cli.py

#Prerequisites 
jq
sqlite3

##Installation on Ubuntu 18
sudo add-apt-repository universe
sudo apt-get update
sudo apt-get install jq sqlite3

#How to use
## Configuration
By default DB and TIDE API key are stored in /opt/splunk/cache. If you want to use a different directory change CPATH variable in spl_at_tide_db_update.sh and spl_at_tide_lookup_cli.py files
###Cache dir
###API key
###Crontab
###External Lookup

##Usage examples

