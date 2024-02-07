import subprocess
import select
import requests
import os
import pycountry
import geohash2
import json
import sys
import ipaddress
from conson import Conson
from datetime import datetime, timedelta


def locate(target):
    """
    Function for sending API request, enriching iptables data with received geodata
     and appending query results to logfile.
    :param target: dictionary containing requested iptables data
    :return: None
    """
    try:

        if target['SRC'] != "0.0.0.0":
            raw = requests.get(f"https://ipinfo.io/{target['SRC']}?token={config()['token']}")\
                .text[1:-1].strip().split("\n")

            dict_raw = {}

            for info in raw:
                info = info.replace('"', "").strip(",").split(":")
                dict_raw[info[0].strip()] = info[1].strip() if len(info[1].strip()) != 0 else ""

            country = str(pycountry.countries.get(alpha_2=dict_raw["country"]))\
                .replace("'", "").split("name=")[1].split(",")[0]
            gh = geohash2.encode(float(dict_raw["loc"].split(",")[0]), float(dict_raw["loc"].split(",")[1]), 7)

            ipt = {}
            for v in config()["to_collect"]:
                ipt[v] = target[f'{v}']

            formatted = {
                "ipt":  ipt,
                "geoip": {
                    "location": {
                        "time_zone": dict_raw["timezone"],
                        "latitude": dict_raw["loc"].split(",")[0],
                        "longitude": dict_raw["loc"].split(",")[1],
                        "geohash": gh

                    },
                    "country": {
                        "names": {
                            "en": country
                        },
                        "iso_code": dict_raw["country"]
                    },
                    "city": {
                        "en": dict_raw["city"]
                    },
                    "organization": {
                        "AS": dict_raw["org"].split(maxsplit=1)[0][2:] if len(dict_raw["org"]) != 0 else "",
                        "name": dict_raw["org"].split(maxsplit=1)[1] if len(dict_raw["org"]) != 0 else ""
                    }
                },
                "ISODATE": datetime.now().isoformat()
            }

            with open(config()['logfile'], "a") as log:
                json.dump(formatted, log, separators=(",", ":"))
                log.write("\n")
    except Exception as err:
        print(line.split()[6:])
        print(err)
        print(target)


def conf_change():
    """
    Function looking for changes in configuration file.
    :return:
    """
    current_mod_time = os.path.getmtime(os.path.join(os.getcwd(), "geoip2grafana_config.json"))
    if current_mod_time > mod_time:
        try:
            test = Conson(cfile="geoip2grafana_config.json")
            test.load()

            time_values = ['minutes', 'hours', 'days', 'weeks']
            if test()["timedelta"].split("=")[0] not in time_values:
                raise Exception("Invalid timedelta. Must be 'minutes', 'hours', 'days' or 'weeks'.")

            if test() == config():
                pass
            elif test() != config():
                for original_key, original_value in config().items():
                    if original_value != test()[original_key]:
                        print(f"INFO: {original_key}: {original_value.strip()} >>> {test()[original_key]}")
                print("\n")
                config.load()

        except Exception as err:
            print("WARNING: config file has been changed, but it's not properly formatted.")
            print(f"ERROR: {err}")
            print("Restoring previous settings...")
            config.save()


def excluded(ip_net_list, address):
    """
    Comparing logged IP with list of excluded IP/networks.
    :param ip_net_list: String -> List of IP addresses and networks from config file.
    :param address: String -> Logged IP address
    :return: Boolean -> True if logged IP matches IP or network from config file, False otherwise.
    """

    xnets = []
    xips = []

    for addr in ip_net_list:
        xnets.append(addr) if "/" in addr else xips.append(addr)

    if address in xips:
        return True
    else:
        for network in xnets:
            net = ipaddress.ip_network(network, strict=False)
            ipaddr = ipaddress.ip_address(address)
            if ipaddr in net:
                return True
    return False


args = ['journalctl', '--lines', '0', '--follow', '--grep', '[iptables]']
f = subprocess.Popen(args, stdout=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)

config = Conson(cfile="geoip2grafana_config.json")
if not os.path.exists(config.file):

    logfile = os.path.join("/var/log/", "geoip2grafana.log")
    temp = os.path.join(r"/tmp/", "geoip2grafana.temp")
    token = "ipinfoToken"

    config.create("logfile", logfile)
    config.create("temp", temp)
    config.create("to_collect", "IN", "SRC", "OUT", "SPT", "PROTO", "DST", "DPT")
    config.create("timedelta", "hours=72")
    config.create("excluded_IP", ["127.0.0.0/8", "0.0.0.0"])
    config.create("token", token)
    config.save()

    print("Please update your info in config file.")
    input("Press enter to exit...")
    sys.exit()
else:
    mod_time = os.path.getmtime(os.path.join(os.getcwd(), "geoip2grafana_config.json"))
    config.load()

ips = Conson(cfilepath=config()["temp"].rsplit("/", 1)[0], cfile=config()["temp"].rsplit("/", 1)[1])
if not os.path.exists(ips.file):
    ips.save()
else:
    ips.load()

if not os.path.exists(config()['logfile']):
    subprocess.run(["touch", f"{config()['logfile']}"])
if not os.path.exists(config()['temp']):
    subprocess.run(["touch", f"{config()['temp']}"])

while True:

    conf_change()

    to_delete = []
    current_conn = {}
    unit, value = config()["timedelta"].split("=")

    for ip, ts in ips().items():
        if (datetime.now() - datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')) > timedelta(**{unit: int(value)}):
            to_delete.append(ip)

    for ip in to_delete:
        ips.dispose(ip)

    if p.poll():
        line = f.stdout.readline().decode()

        if "[iptables]" in line:
            for data in line.split()[6:]:
                kv = data.split("=")
                if len(kv) == 2 and kv[0] in config()["to_collect"]:
                    current_conn[kv[0]] = kv[1]
                elif len(kv) == 1 and kv[0] in config()["to_collect"]:
                    current_conn[kv[0]] = ""

            for item in config()["to_collect"]:
                if item not in list(current_conn):
                    current_conn[item] = ""

            if current_conn["SRC"] not in list(ips()) and not excluded(config()["excluded_IP"], current_conn["SRC"]):
                ips.create(current_conn["SRC"], datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                ips.save()
                locate(current_conn)
