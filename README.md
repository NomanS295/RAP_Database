# RAP_Database
Enhanced Version with Database Integration, Whitelisting, and Alert System
This project scans Wi-Fi networks to detect Rogue Access Points and Evil Twin attacks.
It saves all scan results and alerts to an SQLite database (wifi_scanner.db) and JSON files (scan_results.json and alert.json).
A whitelist system is also included to flag known safe networks.

# Step 1: Install Dependencies and clone the project 
```
sudo apt update
sudo apt install python3 python3-pip sqlite3
pip3 install scapy

git clone https://github.com/alexbascevan/RAP_Scanner.git
cd RAP_Scanner
```
# Step 2: Make the database and tables

In this project we worked in SQLite3 since it doesnt require a server and is lightweight. 
Created an SQlite database named wifi_scanner.db with two tables (scan results and alerts) 
```
sqlite3 wifi_scanner.db
```

```
CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    essid TEXT,
    bssid TEXT,
    channel INTEGER,
    avg_power REAL,
    auth TEXT,
    enc TEXT,
    scanned_at TEXT,
    whitelist_id TEXT
)


-- Create Alerts Table
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    essid TEXT,
    bssid TEXT,
    channel INTEGER,
    avg_power REAL,
    auth TEXT,
    enc TEXT,
    alert_type TEXT,
    detected_at TEXT,
    whitelist_id TEXT
);



```


# Step 3 Create the whitelist.txt 
cd back into the rap scanner and type in 


```
nano whitelist.txt
```
# Step 4: Add entries like: ESSID,BSSID

add some enteries into the whitelist for the networks you trust 
for example:
BELL683,54:64:d9:f6:32:f8



