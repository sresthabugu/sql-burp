import sys
import os
from bs4 import BeautifulSoup
import argparse
import codecs

def banner():
    print("""
 #######################################################################
 #                                                                     #
 #  \______   \    |   \______   \______   \ \__    ___/\_____  \      #
 #   |    |  _/    |   /|       _/|     ___/   |    |    /   |   \     #
 #   |    |   \    |  / |    |   \|    |       |    |   /    |    \    #
 #   |______  /______/  |____|_  /|____|       |____|   \_______  /    #
 #          \/                 \/                               \/     #
 #    _________________  .____       _____      _____ __________       #
 #   /   _____/\_____  \ |    |     /     \    /  _  \\\______   \      #
 #   \_____  \  /  / \  \|    |    /  \ /  \  /  /_\  \|     ___/      #
 #   /        \/   \_/.  \    |___/    Y    \/    |    \    |          #
 #  /_______  /\_____\ \_/_______ \____|__  /\____|__  /____|          #
 #          \/        \__>       \/       \/         \/                #
 #                                                                     #
 #    Created By: Milad Khoshdel    E-Mail: miladkhoshdel@gmail.com    #
 #                                                                     #
 #######################################################################
    """)

def usage():
    print("""
  Usage: ./burp-to-sqlmap.py [options]
  Options: -f, --file               <BurpSuite State File>
  Options: -o, --outputdirectory    <Output Directory>
  Options: -s, --sqlmappath         <SQLMap Path>
  Options: -p, --proxy              <Use Proxy>
  Options: -r, --risk               <SqlMap Risk>
  Options: -l, --level              <SqlMap Level>
  Options: -t, --tamper             <SqlMap Tamper List>
  Example: python burp-to-sqlmap.py -f [BURP-STATE-FILE] -o [OUTPUT-DIRECTORY] -s [SQLMap-Path]
    """)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-o", "--outputdirectory", required=True)
    parser.add_argument("-s", "--sqlmappath", required=True)
    parser.add_argument("-p", "--proxy")
    parser.add_argument("-r", "--risk")
    parser.add_argument("-l", "--level")
    parser.add_argument("-t", "--tamper")
    args = parser.parse_args()

    proxyvalue = f"--proxy {args.proxy} " if args.proxy else ""
    risk_value = f"--risk {args.risk} " if args.risk else ""
    level_value = f"--level {args.level} " if args.level else ""
    tamper_value = f"--tamper={args.tamper} " if args.tamper else ""

    banner()

    if not os.path.exists(args.outputdirectory):
        os.makedirs(args.outputdirectory)

    if sys.platform.startswith("win32"):
        run_windows(args.file, args.outputdirectory, args.sqlmappath, proxyvalue, risk_value, level_value, tamper_value)
    elif sys.platform.startswith("linux"):
        run_linux(args.file, args.outputdirectory, args.sqlmappath, proxyvalue, risk_value, level_value, tamper_value)
    else:
        print("[+] Error: Unsupported OS Detected!")
        sys.exit(1)

def run_windows(filename, directory, sqlmappath, proxyvalue, risk_value, level_value, tamper_value):
    export_packets(filename, directory, "windows")
    test_sql_injection(directory, sqlmappath, proxyvalue, risk_value, level_value, tamper_value, "\\")

def run_linux(filename, directory, sqlmappath, proxyvalue, risk_value, level_value, tamper_value):
    export_packets(filename, directory, "linux")
    test_sql_injection(directory, sqlmappath, proxyvalue, risk_value, level_value, tamper_value, "/")

def export_packets(filename, directory, os_type):
    packetnumber = 0
    print(" [+] Exporting Packets ...")

    with open(filename, 'r', encoding="utf-8") as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        for i in soup.find_all("request"):
            packetnumber += 1
            print(f"   [-] Packet {packetnumber} Exported.")
            file_mode = "w" if os_type == "windows" else "w"
            encoding = None if os_type == "windows" else "utf-16le"
            with codecs.open(os.path.join(directory, f"{packetnumber}.txt"), file_mode, encoding) as outfile:
                outfile.write(i.text.strip())
    
    print(f"\n{packetnumber} Packets Exported Successfully.\n")

def test_sql_injection(directory, sqlmappath, proxyvalue, risk_value, level_value, tamper_value, path_sep):
    print(" [+] Testing SQL Injection on packets ... (Based on your network connection, tests can take up to 5 minutes.)")
    vulnerablefiles = []

    for file in os.listdir(directory):
        print(f"   [-] Performing SQL Injection on packet number {file[:-4]}. Please Wait ...")
        cmd = f"python {sqlmappath}{path_sep}sqlmap.py -r {os.path.dirname(os.path.realpath(__file__))}{path_sep}{directory}{path_sep}{file} --batch {proxyvalue}{risk_value}{level_value}{tamper_value} > {os.path.dirname(os.path.realpath(__file__))}{path_sep}{directory}{path_sep}testresult_{file}"
        os.system(cmd)
        
        with open(f"{directory}{path_sep}testresult_{file}", "r") as result_file:
            result = result_file.read()
            if 'is vulnerable' in result or "Payload:" in result:
                print("    - URL is Vulnerable.")
                vulnerablefiles.append(file)
            else:
                print("    - URL is not Vulnerable.")
            print(f"    - Output saved in {directory}{path_sep}testresult_{file}")

    print("\n--------------\nTest Done.\nResult:")
    if not vulnerablefiles:
        print("No vulnerabilities found on your target.")
    else:
        for items in vulnerablefiles:
            print(f"Packet {items[:-4]} is vulnerable to SQL Injection. For more information, please see {items}")
    print("--------------\n")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
        sys.exit(1)

