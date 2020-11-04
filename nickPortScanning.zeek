@load base/frameworks/sumstats
@load base/utils/time
@load base/frameworks/notice

module portScan

export 
{

}

event zeek_init()
{
    #Parts of sum stats that we will need to scan the ports
    #
}

#Identify source and destination IP address
#Identify source and destination ports (80)
#Epoch (How many different IP addresses are in that time interval)
#Counter for how many IP addresses 
#Check on the criteria
    #Is the port port 80
    #right timeframe
    #the source IP has scanned, a threshold for how many times it has scanned
#Log the source IP address(if it fits the criteria)



