import tailer
import json
import time
import subprocess
import threading

blocked_ips = {}
block_duration = 45
block_lock = threading.Lock()

def unblock_manager():

    while True:
        with block_lock:  
            for ip, blocked_time in list(blocked_ips.items()):
                if time.time() - blocked_time > block_duration:
                    subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
                    del blocked_ips[ip]
    
                    print(f"Unblocked IP: {ip}")
                    print("--------------------------")
        time.sleep(10)

def main():
    print("Detection Active...")
    
    try:
        
        with open("whitelist.txt") as f:
            whitelist = [line.strip() for line in f]
        
        unblocker_thread = threading.Thread(target=unblock_manager, daemon=True)
        unblocker_thread.start()
        
        for line in tailer.follow(open("/var/log/suricata/eve.json")):
            log_entry = json.loads(line)
            
            if log_entry.get("event_type") == "alert":
                src_ip = log_entry.get('src_ip')
                if src_ip not in blocked_ips and src_ip not in whitelist:
                    
                    print("\n--- New Alert Detected ---")
                    print(f"Source IP: {log_entry.get('src_ip')}")
                    print(f"Signature: {log_entry['alert'].get('signature')}")
                
                    with block_lock:
                        subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-s', src_ip, '-j', 'DROP'])
                        blocked_ips[src_ip]=time.time()
                        print(f"Blocked IP: {src_ip}")
                        print("--------------------------")
                    
    except KeyboardInterrupt: 
        print("\nExiting")
if __name__ == "__main__":
    main()

