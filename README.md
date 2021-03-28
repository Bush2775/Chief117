<h1>Introduction</h1>

Welcome to Project Chief 117, an enhancement for Zeek made by a team of students from Brigham Young University. This set of scripts can be used with Zeek to detect Covenant C2 traffic. While there are tools and repositories that can detect C2 traffic from Zeek logs, Zeek cannot detect Covenant traffic natively. Our package will allow Zeek to natively detect Covenant traffic, beaconing behavior, and other signs of the framework. With this ability now being native to Zeek, users and developers won’t have to find or develop other tools for that functionality.
Zeek has a massive footprint out in the open source community. It has over 110 community-contributed packages, 20 plus years of federally funded research and design, and it has over 10 thousand deployments worldwide.


<h2>Installation/Usage</h2>

Two different use cases are available. To use the script against a sample packet capture, the following command should be given in the command line: 
`zeek -r [name of file] [name of script]`

Included are results of running the scripts against the sample packet capture in the "Examples" zip file. The example packet capture is named "austin.pcap".



These scripts can be installed by adding to the load section of Zeek, which is in the local.zeek config file. The location of this file, in our testing machine, is /opt/zeek/share/zeek/site/local.zeek. The location of this file in your particular instance will depend on your Zeek install. 



<h2>Scripts Included in this Repository</h2>

<h3>delta.zeek</h3>

This script provides the ability to calculate the time difference (delta) between a connection from a host to responding ip and its last connection. It also averages out the time deltas over a given epoch time. The delta.log gives fields for the timestamped epoch (ts), originating host ip address (orig_h), responding host ip address (resp_h), time delta average(avg), min time delta (min), max time delta (max), and number of connections (num).
You can redefine epoch time to fit your organization’s needs.


<h3>Beaconing-Observations.zeek</h3>

This script uses the SumStats framework to look for signs of beaconing between the Covenant server and the victim computer. Provided, the SumStats look at the number of packets sent between the attacker and victim, along with the response length from the attacker. This script also uses Regex to find default endpoints that Covenant uses to connect to a victim machine. Endpoints can be added by adding the appropriate regex to the definition of the endpoints in the file. Other attributes of beaconing can be added to this file by adding the necessary parts for the SumStats required. 


<h2>Future Additions in Development</h2>

While our package includes those scripts vital to detecting Covenant C2 traffic with Zeek, new developments may be added on by individual contributors and organizations in the Zeek community. The following features have been explored in our own testing and may serve as starting points for the next stage of development.

<h3>Email Notices</h3>

An additional feature to be considered for later developments on the Notice framework for these scripts is email notifications for specified activities in Covenant traffic. Referencing the current Zeek documentation, email notices can be configured to alert administrators and other monitoring positions to factors that pass beyond set perimeters and limits in the framework.

<h3>Log File Consolidation</h3>

An additional feature to be considered for later developments within the Logging framework for these scripts is consolidation of log files produced from Covenant traffic detection. For instance, a bash shell script which takes the existing log files as input and extracts certain variables and the events data associated with them may be run as a cron job on a scheduled basis. By consolidating log files, the data compiled in a certain monitored period becomes easier to manage and classify based on the nature of events occurring within that timespan and the administrative discretion.

An example of a simple printout of log data variables (i.e. orig_h) in the command line using the utility `zeek-cut` with the `-d` flag to print the timestamp epoch in human-readable format:

`cat [log_file] | zeek-cut -d ts [log_variable1] [log_variable2]`

In addition, another tool to consider for the design of this feature would be Zeek Analysis Tools (ZAT), found here: https://github.com/SuperCowPowers/zat
