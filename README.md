README.md

Introduction

Welcome to Project Chief 117. This set of scripts can be used with Zeek to detect Covenant C2 traffic. 

Installation/Usage

Two different use cases are available. To use the script against a sample packet capture, the following command should be given in the command line: zeek -r [name of script] [name of file]

These scripts can be installed by adding to the load section of Zeek, which is in the local.zeek config file. The location of this file, in our testing machine, is /opt/zeek/share/zeek/site/local.zeek


Scripts Included in this Repository


zeek-delta

This script provides the ability to calculate the time difference (delta) between a connection from a host to responding ip and its last connection. It also averages out the time deltas over a given epoch time. The delta.log gives fields for the timestamped epoch (ts), originating host ip address (orig_h), responding host ip address (resp_h), time delta average(avg), min time delta (min), max time delta (max), and number of connections (num).
You can redefine epoch time to fit your organization’s needs.

zkg.meta

[package]
version = 0.1
tags = notice, average, delta 
script_dir = scripts
description = This script provides the ability to calculate the time difference (delta) between a connection from a host to responding ip and its last connection.
depends =
	zeek >=2.5.5


Beaconing Detection

This script uses the SumStats framework to look for signs of beaconing between the Covenant server and the victim computer. Provided, the SumStats look at the number of packets sent between the attacker and victim, along with the response length from the attacker. This script also uses Regex to find default endpoints that Covenant uses to connect to a victim machine. 
