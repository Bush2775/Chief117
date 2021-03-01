<h1>Introduction</h1>

Welcome to Project Chief 117. This set of scripts can be used with Zeek to detect Covenant C2 traffic. While there are tools and repositories that can detect C2 traffic from Zeek logs, Zeek can not detect Covenant traffic natively. Our package will allow Zeek to natively detect Covenant traffic, beaconing behavior, and other signs of the framework. With this ability now being native to Zeek, users and developers won’t have to find or develop other tools for that functionality.
Zeek has a massive footprint out in the open source community. It has over 110 community-contributed packages, 20 plus years of federally-funded research and design, and it has over 10 thousand deployments worldwide.


<h2>Installation/Usage</h2>

Two different use cases are available. To use the script against a sample packet capture, the following command should be given in the command line: zeek -r [name of file] [name of script]





These scripts can be installed by adding to the load section of Zeek, which is in the local.zeek config file. The location of this file, in our testing machine, is /opt/zeek/share/zeek/site/local.zeek. The location of this file in your particular instance will depend on your Zeek install. 



<h2>Scripts Included in this Repository</h2>

<h3>delta.zeek</h3>

This script provides the ability to calculate the time difference (delta) between a connection from a host to responding ip and its last connection. It also averages out the time deltas over a given epoch time. The delta.log gives fields for the timestamped epoch (ts), originating host ip address (orig_h), responding host ip address (resp_h), time delta average(avg), min time delta (min), max time delta (max), and number of connections (num).
You can redefine epoch time to fit your organization’s needs.


<h3>BeaconingObservations.zeek</h3>

This script uses the SumStats framework to look for signs of beaconing between the Covenant server and the victim computer. Provided, the SumStats look at the number of packets sent between the attacker and victim, along with the response length from the attacker. This script also uses Regex to find default endpoints that Covenant uses to connect to a victim machine. Other attributes of beaconing can be added to this file by adding the necessary parts for the SumStats required. 
