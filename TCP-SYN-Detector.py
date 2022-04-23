
#Mariam Safieldin and Peter Farah develloped this Detection code

from scapy.all import *
from collections import Counter
from time import localtime, strftime
import logging
import time



#log attacks at what time
class LOG():#logging attack by Mariam
    
     @staticmethod
     def run(ip):

        date = strftime("%a, %d %b %Y %X", localtime())
        logging.info("Status at "+ str(date) + ": a TCP SYN Flood Attack is Detected! with latest IP:"+ip)



def analyzer(pkt):#detection logic by Peter
                  #packet sniffing and passing throw function by Mariam
    
    #By Peter:
    global a#number of packets that are tcp syn
    global start#used for timing
    global th#Threshold number for attack detection
    global SA
    
    if (SA==0):
        if (TCP in pkt and pkt[TCP].flags & 2 ):
            if(pkt[TCP].flags & 16):
                a=a-1
                #decrement a every time we have a tcp syn ack
            else:
                #increment a every time we have a tcp syn
                src = pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')
                a=a+1
            
    elif (SA==1): 
       if (TCP in pkt and pkt[TCP].flags & 2 ):
           src = pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')
           a=a+1
        #every 5s reset number of tcp syn-ack packets loged to 0 by Peter
    
    
    if ((time.time()-start)>=5):
        a=0
        start=time.time()
    #when a=th log that an attacked is regestered and set a to 80% its threshold by Peter
    elif (a>=th):#deppends on the server change the number
        a=int(0.8*th)
        LOG.run(src)

    
#Saving an analysis of the traffic  by Mariam
logging.basicConfig(filename='packets_breakdown.log', format='%(message)s', level=logging.INFO)

#initialising some variables and user input by Peter
global a#number of packets that are tcp syn
global start#for timing
global th
global SA
SA=1
a=0


#choosing which detection mode to do and threshold by Peter
print()
print()
print("Recommended:(do not enter 0)")
th=abs(int( input("Enter threshold for number of SYN/5s. Enter 0 if you prefer to choose a threshold of (SYN-ack)/5s: ")))
if (th == 0):
    print()
    print("Warning: this could be attacked with attacker sending syn and any syn ack packets to balance the syn")
    th=abs(int( input("Enter threshold of (SYN-ack)/5s: "))) 
    SA=0
start=time.time()


#sniffing packets and passing them through the analyzer by Mariam
sniff(prn=analyzer, store=0)