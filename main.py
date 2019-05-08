import requests , json , argparse , sys , socket
from termcolor import colored
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass
def banner():
    print("""
   _   __                   _      _              
  | | / /                  | |    (_)             
  | |/ /   ___  _ __   ___ | |__   _  _ __   ___  
  |    \  / _ \| '_ \ / __|| '_ \ | || '__| / _ \ 
  | |\  \|  __/| | | |\__ \| | | || || |   | (_) |
  \_| \_/ \___||_| |_||___/|_| |_||_||_|    \___/ 
              Create By InfinitumIT                               
           { omae wa mou shindeiru! Nani? }                                       
    """)
def parser_error():
    banner()
    if sys.argv[0]==None:
        print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
        sys.exit()
    else:
        pass
def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(description='Web Information Gathering Tool.')
    parser.add_argument('-m', action="store", help='Modules : header or domain .Usage:[-m header]')
    parser.add_argument('-f', action="store", help='Url list load from path. Do not add https:// tag.')
    parser.add_argument('-o', action="store" , help='Output File path.')
    return parser.parse_args()
# Header Security Checker

def headersecurity(file):
    whitelist = ["X-Frame-Options","Strict-Transport-Security","X-XSS-Protection","X-Content-Type-Options", "Content-Security-Policy"] 
    with open(file) as fp:  
        line = fp.readline()
        while line:
            user_agent = {'User-agent': 'Mozilla/5.0'}
            r = requests.get(line.strip(), headers=user_agent,verify=False)
            print("\nScan Url -> " + line.strip())
            for whiteitem in whitelist:
                if whiteitem in r.headers:
                    print(colored(whiteitem, 'white'), colored(' available', 'green'))
                else:
                    print(colored(whiteitem, 'white'), colored(' not available.', 'red'))
            line = fp.readline()  
# Domain To Ip Address Converter
def domaintoip(file):
    with open(file) as fp:  
            line = fp.readline()
            while line:
                print(colored("Host: " , 'red'), colored(line.strip() , 'white' ) , colored(" IP: ", 'red'), colored(socket.gethostbyname(line.strip()), 'white'))
                line = fp.readline()
def DnsResolver(file):
      with open(file) as fp:  
            line = fp.readline()
            while line:
                reversed_dns = socket.gethostbyaddr(line.strip())
                print(colored("Host: " , 'red'), colored(line.strip() , 'white' ) , colored(" DNS: ", 'red'), colored(reversed_dns[0], 'white'))
                line = fp.readline()
#Main
def main():
    parser_error()
    args = parse_args()
    if (args.m == "header"):    
        headersecurity(args.f)
    elif (args.m == "domain"):
        domaintoip(args.f)
    elif (args.m == "dnsresolve"):
        DnsResolver(args.f)
#Load Main
main()