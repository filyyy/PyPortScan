"""
PyPortScan
Author: filyyy (https://github.com/filyyy)
Description: Simple multi-threaded TCP port scanner with banner grabbing and dynamic timeouts
License: MIT
"""

import math, socket, sys, argparse, time, errno, string
from threading import Thread, Lock
from dataclasses import dataclass

common_ports =  [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
                143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 993, 995, 1080,
                1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000]

default_parms = {
    "min_timeout": 0.5,
    "max_timeout": 5.0,
    "ignore_above": 3.0,
    "max_threads": 100,
    "no_banner_grab": False,
    "verbose": False,
}

# request strings for ports that require an active query to return a banner
active_requests = {
    21: b"\r\n",
    23: b"\r\n",
    25: b"EHLO test\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"USER test\r\n",
    143: b"a001 CAPABILITY\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    6379: b"PING\r\n",
}

@dataclass
class scan_results:
    result: int
    error: int
    duration: float

open_ports = []
response_times = []
banners = []
lock = Lock()

start = time.time()

def valid_ports(ports_list):
    """
    Validates the list of ports passed through the -p flag and
    returns the validated list
    """
    valids = []
    for port in ports_list:
        if port < 1 or port > 65535:
            print("Ports must be in range [1-65535]!")
            sys.exit(1)
        valids.append(port)
    return valids

def valid_range(ports_range):
    """
    Validates the range of ports passed through the -r flag and
    returns the validated range as a list
    """
    valids = []
    try:
        start, stop = map(int, ports_range.split("-"))
        if start < 1 or stop > 65535:
            print("Ports must be in range [1-65535]!")
            sys.exit(1)
    except ValueError:
        print("Invalid range! (python3 scan_portsner.py [ip] -r [start-stop])")
        sys.exit(1)
    for port in range(start, stop+1):
        valids.append(port)
    return valids

def threads_calc(length, max_threads):
    """
    Calculates the number of threads to use according to the number of ports
    and returns it
    The number of threads is defined with the square root of the number of ports
    to prevent it from rising too quickly
    """
    return int(min(max(1, math.sqrt(length)), max_threads))

def get_timeout(min_timeout, max_timeout):
    """
    Calculates the timeout based on the
    average latency of the last 10 scans
    """
    if not response_times:
        return 1.0
    avg = sum(response_times)/len(response_times)
    return max(min_timeout, min(avg*2.0, max_timeout))

def scan_port(ip, port, timeout):
    """
    Attempts to connect to a port to verify if it is open and retry with the maximum
    timeout if a timeout occurs to prevent false negatives for slow ports
    Returns the result (0 if port is open), any errors and the
    duration of the scan as a dataclass
    """
    start =  time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        res = sock.connect_ex((ip, port))
        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    dur = time.time() - start
    return scan_results(result=res, error=err, duration=dur)

def grab_banner(ip, port, timeout):
    """
    Attempts to capture the banner sent by the service running
    on a port and returns it in a readable format
    Uses the maximum timeout to allow the service enough time
    to respond, reducing the chance of false negatives
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            if port in active_requests:
                sock.sendall(active_requests[port])
            banner = "".join(c for c in sock.recv(1024).decode(errors="ignore") if c in string.printable).strip()
            return banner
    except Exception:
        return None

def scan_range(parms, ports):
    """
    Iterates over a chunk of the ports list, scans each port,
    and attempts to grab its banner if the port is open
    """
    for port in ports:
        is_open = False
        banner = None
        scan_duration = None

        timeout = get_timeout(parms["min_timeout"], parms["max_timeout"])
        # run the scan
        scan = scan_port(parms["ip"], port, timeout)

        if scan.result == 0:
            is_open = True
            scan_duration = scan.duration
            
        # retry the scan with the maximum timeout if the first attempt fails for a timeout
        elif scan.error == errno.ETIMEDOUT:
            retry_scan = scan_port(parms["ip"], port, parms["max_timeout"])
            if retry_scan.result == 0:
                is_open = True
                scan_duration = retry_scan.duration
                
        if is_open:
            print(f"[\033[32m{port}\033[0m]", end=" ", flush=True)
            if not parms["no_banner_grab"]:
                banner = grab_banner(parms["ip"], port, parms["max_timeout"])
            # use Lock to prevent multiple threads to access the lists simultaneously
            with lock:
                open_ports.append(port)
                if banner:
                    banners.append(banner)
                if scan_duration <= parms["ignore_above"]:
                    response_times.append(scan_duration)
                    # sliding window that only keeps the last 10 records
                    response_times[:] = response_times[-10:]

def scan_ports(ip, ports=None, parms=None):
    """
    Divides the list of ports into chunks and feeds them to multiple threads
    to scan them faster
    It gives priority to common ports
    """
    if ports == None:
        ports = common_ports
    if parms == None:
        parms = default_parms.copy()
    else:
        parms = {**default_parms, **parms}

    if parms["verbose"]:
        keys = ["ip", "min_timeout", "max_timeout", "ignore_above", "max_threads"]
        print("\033[91m====| Parameters |=====\033[0m")
        for key in keys:
            print(f"\033[95m{key}\033[0m = {parms[key]}")
        print("")

    print("\033[1;34mOpen ports: \033[0m", end="", flush=True)

    common_in_range = [common for common in common_ports if common in ports]
    ports = [port for port in ports if port not in common_in_range]

    threads = []
    threads_count =  threads_calc(len(ports)+len(common_in_range), parms["max_threads"])

    chunk_size = int((len(ports)+len(common_in_range))/threads_count)

    # priority to common ports in the list
    for ports_chunk in list(common_in_range[i:i+chunk_size] for i in range(0,len(common_in_range),chunk_size)):
        t = Thread(target=scan_range, args=(parms, ports_chunk))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    
    threads.clear()

    # assign each chunk of ports to a thread and start it
    for ports_chunk in list(ports[i:i+chunk_size] for i in range(0,len(ports),chunk_size)):
        t = Thread(target=scan_range, args=(parms, ports_chunk))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

if __name__ == "__main__":

    ports = []

    # parse arguments from CLI
    parser = argparse.ArgumentParser(prog="Port Scanner", description="Simple python TCP port scanner")
    parser.add_argument("ip")
    parser.add_argument("-r", "--range", default=None, type=valid_range, help="Scan ports in the given range")
    parser.add_argument("-p", "--ports", default=None, type=int, nargs="+", help="Scan the given port list")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--max-threads", default=100, type=int, dest="max_threads", help="Max number of threads to use during the scan")
    parser.add_argument("--min-timeout", default=0.5, type=float, dest="min_timeout", help="Minimum timeout for each port")
    parser.add_argument("--max-timeout", default=5.0, type=float, dest="max_timeout", help="Maximum timeout for each port")
    parser.add_argument("--ignore-responses-above", default=3.0, type=float, dest="ignore_above", help="Ignore response times above a certain value when calculating the average response time")
    parser.add_argument("--no-banner-grabbing", dest="no_banner_grab", default=False, action="store_true", help="Disable banner grabbing")

    args = vars(parser.parse_args())

    if args["range"]:
        for port in args["range"]:
            ports.append(port)
    if args["ports"]:
        for port in valid_ports(args["ports"]):
            if port not in ports: # prevents duplicates
                ports.append(port)
            
    ip = args["ip"]

    scan_ports(ip, ports if ports else common_ports, args)

    if banners:
        banners_dict = dict(sorted(zip(open_ports, banners)))
        print("\n")
        for port, banner in banners_dict.items():
            print(f"[\033[1;32m{port}\033[0m] ==> \033[93m{banner}\033[0m\n")

    print(f"\033[94mNumber of open ports:\033[0m {len(open_ports)}")
    print(f"\033[94mScan duration:\033[0m {(time.time()-start):.3f}s")