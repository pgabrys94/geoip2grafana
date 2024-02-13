import subprocess
import select
import requests
import os
import pycountry
import geohash2
import json
import sys
import ipaddress
import socket
from influxdb import InfluxDBClient
from conson import Conson
from datetime import datetime, timedelta


def api_req(src):
    try:
        if config()['token'] == "ipInfoToken":
            raise Exception("API token not changed")
        api_query = requests.get(f"https://ipinfo.io/{src}?token={config()['token']}").text[1:-1].strip().split("\n")
        if "unknown token" in api_query:
            raise Exception("Invalid API token")
        else:
            return api_query
    except Exception as err:
        print(err)
        sys.exit()


def enrich(raw_data, target, db_format=False, from_db=False):
    """
    Function for sending API request, enriching iptables data with received geodata
     and appending query results to logfile.
    :param target: dictionary containing requested iptables data
    :param raw_data: dictionary containing raw geodata
    :param from_db: boolean -> raw data source format flag
    :param db_format: boolean -> adjust enrichment to fit influxdb line protocol
    :return: None
    """
    def enrich_for_log():
        enriched = {
            "ipt": ipt,
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

        return enriched

    def enrich_for_db():
        print("enrich_for_db")
        if from_db:
            print("from DB")
            latest = list(raw_data.get_points())[-1]
            fields = {}
            tags = {}
            for key, val in latest.items():
                if key == "time":
                    continue
                if isinstance(val, str) and val.isdigit():
                    fields[key] = int(val)
                elif isinstance(val, str):
                    fields[key] = val
                else:
                    tags[key] = val

            enriched = [
                {
                    "measurement": hostname,
                    "fields": fields,
                    "tags": tags
                }
            ]

            return enriched

        else:
            print("NOT from db")
            tags = {}
            fields = ipt
            for tag in config()["influxdb_tags"]:
                tags[tag] = ipt[tag]
                fields.pop(tag)
            tags['country'] = country
            tags["API_req_ts"] = datetime.now().isoformat()
            dict_add = {
                "time_zone": dict_raw["timezone"],
                "latitude": dict_raw["loc"].split(",")[0],
                "longitude": dict_raw["loc"].split(",")[1],
                "geohash": gh,
                "iso_code": dict_raw["country"],
                "city": dict_raw["city"],
                "organization": dict_raw["org"].split(maxsplit=1)[1] if len(dict_raw["org"]) != 0 else "",
                "ASN": dict_raw["org"].split(maxsplit=1)[0][2:] if len(dict_raw["org"]) != 0 else ""

            }
            fields.update(dict_add)

            enriched = [
                {
                    "measurement": hostname,
                    "tags": tags,
                    "fields": fields
                }
            ]

            return enriched

    try:
        print("enrich function")
        dict_raw = {}

        if from_db:
            enrich_for_db()
        else:
            print("formatting raw api data")
            for info in raw_data:
                info = info.replace('"', "").strip(",").split(":")
                dict_raw[info[0].strip()] = info[1].strip() if len(info[1].strip()) != 0 else ""
        print("getting country name")
        country = str(pycountry.countries.get(alpha_2=dict_raw["country"]))\
            .replace("'", "").split("name=")[1].split(",")[0]
        print("OK")
        print("geohash convertion")
        gh = geohash2.encode(float(dict_raw["loc"].split(",")[0]), float(dict_raw["loc"].split(",")[1]), 7)
        print("OK")
        ipt = {}
        for v in config()["to_collect"]:
            ipt[v] = target[v]

        return enrich_for_db() if db_format else enrich_for_log()

    except Exception as err:
        breakpoint()
        print(err)
        print(target)


def conf_change():
    """
    Function looking for changes in configuration file.
    :return:
    """
    global mod_time
    current_mod_time = os.path.getmtime(os.path.join(os.getcwd(), "geoip2grafana_config.json"))
    if current_mod_time > mod_time:
        try:
            test = Conson(cfile="geoip2grafana_config.json")
            test.load()

            time_values = ['minutes', 'hours', 'days', 'weeks']
            if test() == config():
                pass
            elif test()["timedelta"].split("=")[0] not in time_values:
                raise Exception("Invalid timedelta. Must be 'minutes', 'hours', 'days' or 'weeks'.")
            elif len(test()["influxdb"]) == 0 or not type(test()["influxdb"]) == list:
                raise Exception("Invalid influxdb parameters.")
            elif test() != config():
                for original_key, original_value in config().items():
                    if original_value != test()[original_key]:
                        print(f"INFO: {original_key}: {original_value.strip()} >>> {test()[original_key]}")
                print("\n")
                mod_time = current_mod_time
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


def retrieve():
    current_conn = {}

    while True:
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

                if not excluded(config()["excluded_IP"], current_conn["SRC"]):
                    return current_conn


def log_way():
    ips = Conson(cfilepath=config()["temp"].rsplit("/", 1)[0], cfile=config()["temp"].rsplit("/", 1)[1])
    if not os.path.exists(ips.file):
        ips.save()
    else:
        ips.load()
        for ip_address, values in ips().items():
            if not isinstance(values, list):
                ips.dispose(ip_address)

    if not os.path.exists(config()['logfile']):
        subprocess.run(["touch", f"{config()['logfile']}"])

    while True:

        conf_change()

        to_delete = []
        unit, value = config()["timedelta"].split("=")

        for ip, ts in ips().items():
            if (datetime.now() - datetime.strptime(ts[0], '%Y-%m-%d %H:%M:%S')) > timedelta(**{unit: int(value)}):
                to_delete.append(ip)

        for ip in to_delete:
            ips.dispose(ip)

        ipt_data = retrieve()
        if ipt_data:
            src = ipt_data['SRC']
            if src not in list(ips()):
                req = api_req(src)
                ips.create(src, [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), req])
                ips.save()
                raw = req
            else:
                raw = ips()[src][1]

            with open(config()['logfile'], "a") as log:
                json.dump(enrich(raw, ipt_data), log, separators=(",", ":"))
                log.write("\n")


def db_way():
    def db_write(fresh=False):
        print("writing to db")
        if fresh:
            print("get fresh info")
            db_client.write_points(enrich(api_req(ipt_data["SRC"]), ipt_data, True, False))
        else:
            print("rewrite")
            db_client.write_points(enrich(db_query, ipt_data, True, True))

    while True:
        try:
            conf_change()

            config()["influxdb"][4] = db[4].replace("<", "", 1)[::-1].replace(">", "", 1)[::-1]

            db_pwd = config.unveil(config()["influxdb"][4])
            db_client = InfluxDBClient(db[1], db[2], db[3], db_pwd, db[5])

            units = {"minutes": "m", "hours": "h", "days": "d", "weeks": "w"}
            unit, value = config()['timedelta'].split('=')
            ret_time = value + units[unit]

            ipt_data = retrieve()

            query = f"""SELECT * FROM "{hostname}" WHERE time > now() - {ret_time} AND "IP" = '{ipt_data["SRC"]}'"""

            if ipt_data:
                db_query = db_client.query(query)
                if len(list(db_query.get_points())) == 0:
                    db_write(True)
                else:
                    rewrite = False
                    for dataset in list(db_query.get_points()):
                        if (datetime.now() - datetime.strptime(dataset["API_ts"], "%Y-%m-%dT%H:%M:%S.%f")
                                < timedelta(**{unit: int(value)})):
                            rewrite = True
                            break
                    if rewrite:
                        db_write()
                    else:
                        db_write(True)

        except Exception as err:
            print("Error connecting to database:")
            print(err)
            sys.exit()


args = ['journalctl', '--lines', '0', '--follow', '--grep', '[iptables]']
f = subprocess.Popen(args, stdout=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)
hostname = socket.gethostname()

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
    config.create("influxdb", [False, "localhost", 8086, "USERNAME", "PASSWORD", "geoip2grafana"])
    config.create("influxdb_tags", ["SRC", "DPT", "PROTO"])
    config.save()

    print("Please update your info in config file.")
    input("Press enter to exit...")
    sys.exit()
else:
    mod_time = os.path.getmtime(os.path.join(os.getcwd(), "geoip2grafana_config.json"))
    config.load()
    pwd = config()["influxdb"][4]
    if pwd != "USERNAME" and pwd != "PASSWORD" and pwd[0] != "<" and pwd[-1] != ">":
        config.veil("influxdb", 4)
        pwd_tagged = config()["influxdb"][4]
        config()["influxdb"].pop(4)
        config()["influxdb"].insert(4, ("<" + pwd_tagged + ">"))
        config.save()

db = config()["influxdb"]
if db[0]:
    db_way()
else:
    log_way()
