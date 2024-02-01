import subprocess
import select
import requests
import os
import pycountry
import geohash2
import json
from conson import Conson
from datetime import datetime, timedelta


def locate(target):
    try:
        if target['SRC'] != "0.0.0.0":
            raw = requests.get(f"https://ipinfo.io/{target['SRC']}?token={config()['token']}")\
                .text[1:-1].strip().split("\n")

            dict_raw = {}

            for info in raw:
                info = info.replace('"', "").strip(",").split(":")
                dict_raw[info[0].strip()] = info[1].strip()

            country = str(pycountry.countries.get(alpha_2=dict_raw["country"]))\
                .replace("'", "").split("name=")[1].split(",")[0]
            gh = geohash2.encode(float(dict_raw["loc"].split(",")[0]), float(dict_raw["loc"].split(",")[1]), 7)

            formatted = {
                "ipt":  {
                    "SRC": target['SRC'],
                    "SPT": target["SPT"],
                    "PROTO": target["PROTO"],
                    "OUT": target["OUT"],
                    "IN": target["IN"],
                    "DST": target["DST"],
                    "DPT": target["DPT"]
                },
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


args = ['journalctl', '--lines', '0', '--follow', '--grep', '[iptables]']
f = subprocess.Popen(args, stdout=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)
ips = {}

config = Conson()
if not os.path.exists(os.path.join(os.getcwd(), "config.json")):

    logfile = os.path.join("/var/log/", "geoip2grafana.log")
    temp = os.path.join(r"/tmp", "geoip2grafana.temp")
    token = "ipinfoToken"

    config.create("logfile", logfile)
    config.create("temp", temp)
    config.create("token", token)
    config.save()

else:
    config.load()

to_collect = ["IN", "SRC", "OUT", "SPT", "PROTO", "IN", "DST", "DPT"]

if not os.path.exists(config()['logfile']):
    subprocess.run(["touch", f"{config()['logfile']}"])
if not os.path.exists(config()['temp']):
    subprocess.run(["touch", f"{config()['temp']}"])

with open(config()['temp'], "r+") as temp_file:
    try:
        ips = json.load(temp_file)
    except json.JSONDecodeError:
        print("error loading IP list temporary file")
        temp_file.seek(0)
        temp_file.truncate()

    while True:

        to_delete = []
        current_conn = {}

        for ip, ts in ips.items():
            if (datetime.now() - datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')) > timedelta(hours=72):
                to_delete.append(ip)

        for ip in to_delete:
            ips.pop(ip)

        if p.poll():
            line = f.stdout.readline().decode()

            if "[iptables]" in line:
                for data in line.split()[6:]:
                    kv = data.split("=")
                    if len(kv) == 2 and kv[0] in to_collect:
                        current_conn[kv[0]] = kv[1]
                    elif len(kv) == 1 and kv[0] in to_collect:
                        current_conn[kv[0]] = ""

                for item in to_collect:
                    if item not in list(current_conn):
                        current_conn[item] = ""

                if current_conn["SRC"] not in list(ips):
                    ips[current_conn["SRC"]] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    temp_file.seek(0)
                    temp_file.truncate()
                    json.dump(ips, temp_file, indent=4)
                    temp_file.flush()
                    locate(current_conn)
