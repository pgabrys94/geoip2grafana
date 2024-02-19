# geoip2grafana by Pawel Gabrys, version 2.7
# http://github.com/pawelgabrys/geoip2grafana

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
import time
from influxdb import InfluxDBClient
from conson import Conson
from datetime import datetime, timedelta


def api_req(src):
    """
    Querying IP geolocation API
    :param src: IP address to query
    :return: string -> API answer
    """

    try:
        if config()['token'].lower == "ipinfotoken":
            raise Exception("API token not changed")
        else:
            base_retry_seconds = 5
            while True:
                try:
                    api_query = requests.get(f"https://ipinfo.io/{src}?token={config()['token']}")

                    if str(api_query.status_code) != "200":
                        raise Exception("API query error. Check your token")
                    else:
                        return api_query.text[1:-1].strip().split("\n")

                except requests.ConnectionError as err:
                    print("Connection error: ", err)
                    print(f"Retrying in: {base_retry_seconds} seconds...")
                    time.sleep(base_retry_seconds)
                    base_retry_seconds = base_retry_seconds * 2


    except Exception as err:
        print("In function: api_req()")
        print(err)
        sys.exit()


def enrich(raw_data, target, db_format=False, from_db=False):
    """
    Function for enriching iptables data with received geodata and appending query results to logfile or inserting
    them into a database.
    :param target: dictionary containing requested iptables data
    :param raw_data: dictionary containing raw geodata
    :param from_db: boolean -> raw data source format flag
    :param db_format: boolean -> adjust enrichment to fit influxdb line protocol
    :return: None
    """
    def enrich_for_log():
        """
        Enriching for logfile.
        :return: dictionary
        """
        try:
            enriched = {
                "ipt": ipt,
                "geoip": {
                    "location": {
                        "time_zone": raw_data["time_zone"] if db_format or raw_from_db
                        else dict_raw["timezone"],
                        "latitude": raw_data["latitude"] if db_format or raw_from_db
                        else dict_raw["loc"].split(",")[0],
                        "longitude": raw_data["longitude"] if db_format or raw_from_db
                        else dict_raw["loc"].split(",")[1],
                        "geohash": raw_data["geohash"] if db_format or raw_from_db else gh

                    },
                    "country": {
                        "names": {
                            "en": raw_data["country"] if db_format or raw_from_db
                            else country
                        },
                        "iso_code": raw_data["iso_code"] if db_format or raw_from_db
                        else dict_raw["country"]
                    },
                    "city": {
                        "en": raw_data["city"] if db_format or raw_from_db
                        else dict_raw["city"]
                    },
                    "organization": {
                        "AS": raw_data["ASN"] if db_format or raw_from_db
                        else dict_raw["org"].split(maxsplit=1)[0][2:] if len(dict_raw["org"]) != 0 else "",
                        "name": raw_data["organization"] if db_format or raw_from_db
                        else dict_raw["org"].split(maxsplit=1)[1] if
                        len(dict_raw["org"]) != 0 else ""
                    }
                },
                "ISODATE": raw_data["API_req_ts"] if db_format or raw_from_db
                else datetime.now().isoformat()
            }

            return enriched

        except Exception as e:
            print("In function: enrich_for_log()")
            print("Data enriching error: ", e)
            breakpoint()

    def enrich_for_db():
        """
        Enriching for database insertion.
        :return: list -> compatible with database line protocol format
        """
        try:
            if from_db:
                fields_rw = {}
                tags_rw = {}
                for key, val in raw_data.items():
                    if key in config()["influxdb_tags"]:
                        if key == "hostname":
                            tags_rw["hostname"] = hostname
                        else:
                            tags_rw[key] = val
                    else:
                        fields_rw[key] = val
                fields_rw.pop("time")   # since "time" is not defined in config as tag, it will be put into "fields"

                enriched_rw = [
                    {
                        "measurement": hostname,
                        "fields": fields_rw,
                        "tags": tags_rw
                    }
                ]

                return enriched_rw

            else:
                dict_all = {
                    "country": country,
                    "hostname": hostname,
                    "API_req_ts": datetime.now().isoformat(),
                    "time_zone": dict_raw["timezone"],
                    "latitude": dict_raw["loc"].split(",")[0],
                    "longitude": dict_raw["loc"].split(",")[1],
                    "geohash": gh,
                    "iso_code": dict_raw["country"],
                    "city": dict_raw["city"],
                    "organization": dict_raw["org"].split(maxsplit=1)[1] if len(dict_raw["org"]) != 0 else "",
                    "ASN": dict_raw["org"].split(maxsplit=1)[0][2:] if len(dict_raw["org"]) != 0 else ""

                }
                tags = {}
                fields = ipt
                for tag in config()["influxdb_tags"]:   # check desired tags
                    if tag in config()["to_collect"]:   # check if tag belongs to iptables log data
                        tags[tag] = ipt[tag]
                        fields.pop(tag)
                    else:
                        if tag in list(dict_all):       # if tag does not belong to ip, check geoip api data and others
                            tags[tag] = dict_all[tag]
                            dict_all.pop(tag)
                        else:                           # if tag is unknown, raise error
                            raise Exception("Unknown InfluxDB tag {}".format(tag))

                fields.update(dict_all)

                enriched = [
                    {
                        "measurement": hostname,
                        "tags": tags,
                        "fields": fields
                    }
                ]

                return enriched

        except Exception as e:
            print("In function: enrich_for_db()")
            print(e)

    try:
        dict_raw = {}
        raw_from_db = False

        if from_db and db_format:
            return enrich_for_db()
        else:
            if not isinstance(raw_data, dict):
                for info in raw_data:
                    info = info.replace('"', "").strip(",").split(":")
                    dict_raw[info[0].strip()] = info[1].strip() if len(info[1].strip()) != 0 else ""
                # acquire country name from ISO code
                country = str(pycountry.countries.get(alpha_2=dict_raw["country"]))\
                    .replace("'", "").split("name=")[1].split(",")[0]
                # create geohash from latitude and longitude
                gh = geohash2.encode(float(dict_raw["loc"].split(",")[0]), float(dict_raw["loc"].split(",")[1]), 7)
            else:
                raw_from_db = True

        ipt = {}
        for v in config()["to_collect"]:
            ipt[v] = target[v]

        return enrich_for_db() if db_format else enrich_for_log()

    except Exception as err:
        print("In function: enrich()")
        print(err)


def mod_time(up=False):
    global json_mod_time
    if up:
        json_mod_time = os.path.getmtime(os.path.join(os.getcwd(), "geoip2grafana_config.json"))
        return True
    else:
        return os.path.getmtime(os.path.join(os.getcwd(), "geoip2grafana_config.json"))


def tag_pwd():
    """
    Reformats password hashed string from "hash" to "<hash>".
    Tags are used to validate password format.
    :return:
    """
    config.veil("influxdb", "db_pwd")
    config()["influxdb"]["db_pwd"] = "<" + config()["influxdb"]["db_pwd"] + ">"


def conf_change():
    """
    Function looking for changes in configuration file.
    :return:
    """
    current_mod_time = os.path.getmtime(os.path.join(os.getcwd(), "geoip2grafana_config.json"))
    reported_mod_time = mod_time()
    if current_mod_time > reported_mod_time:
        try:
            test = Conson(cfile="geoip2grafana_config.json")
            test.load()

            time_values = ['minutes', 'hours', 'days', 'weeks']
            if test() == config():
                pass
            elif test()["timedelta"].split("=")[0] not in time_values:
                raise Exception("Invalid timedelta. Must be 'minutes', 'hours', 'days' or 'weeks'.")
            elif len(test()["influxdb"]) == 0 or not isinstance(test()["influxdb"], dict):
                raise Exception("Invalid influxdb parameters.")
            elif test() != config():
                for original_key, original_value in config().items():
                    if isinstance(original_value, dict):
                        for original_subkey, original_subvalue in original_value.items():
                            if original_subvalue != test()[original_key][original_subkey]:
                                print(f"INFO: {original_subkey}: {str(original_subvalue).strip()} >>> "
                                      f"{str(test()[original_key][original_subkey])}")
                                if original_subkey == "db_pwd":
                                    tag_pwd()
                    else:
                        if original_value != test()[original_key]:
                            print(f"INFO: {original_key}: {str(original_value).strip()} >>> {test()[original_key]}")
                print("\n")
                mod_time(True)
                config.load()

        except Exception as err:
            print("In function: conf_change()")
            print("WARNING: config file has been changed, but it was not properly formatted.")
            print(f"ERROR: {err}")
            print("Restoring previous settings...")
            config.save()


def excluded(ip_net_list, address):
    """
    Comparing logged IP with list of excluded IP/networks in addition to iptables logging rules.
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
    """
    Read iptables log entry from journal and pass them for enrichment.
    :return:
    """
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


def db_mgr(operation, content):
    """
    Function for database operations.
    :param operation: string -> "query" or "insert"
    :param content: string -> for "query": source IP address; for "insert": data in line protocol format
    :return: "query" -> ResultSet object; "insert" -> None
    """
    try:

        base_retry_seconds = 5

        while True:
            try:
                db = config()["influxdb"]

                config()["influxdb"]["db_pwd"] = config()["influxdb"]["db_pwd"]\
                    .replace("<", "", 1)[::-1].replace(">", "", 1)[::-1]

                clear_pwd = config.unveil(config()["influxdb"]["db_pwd"])
                db_client = InfluxDBClient(db["db_IP"], db["db_port"], db["db_user"], clear_pwd, db["db_name"])

                if operation == "query":
                    units = {"minutes": "m", "hours": "h", "days": "d", "weeks": "w"}
                    unit, value = config()['timedelta'].split('=')
                    if value.isdigit() and unit in units:
                        ret_time = value + units[unit]
                    else:
                        raise Exception("Timedelta conversion error")

                    formula = f"""SELECT * FROM /.*/ WHERE time > now() - {ret_time} AND "SRC"='{content}' 
                    ORDER BY time DESC LIMIT 1"""

                    return db_client.query(formula)

                elif operation == "insert":
                    db_client.write_points(content)
                    return

            except requests.ConnectionError as err:
                print("Database connection error: ", err)
                print(f"Retrying in: {base_retry_seconds} seconds...")
                time.sleep(base_retry_seconds)
                base_retry_seconds = base_retry_seconds * 2

    except Exception as err:
        print("In function: db_mgr()")
        print("Database connection manager error: ", err)
        sys.exit()


def log_way():
    """
    Use logfile as data container - for use with promtail.
    :return:
    """
    def log_write(data):
        """
        Write provided data to logfile.
        :param data: either data from database or API
        :return:
        """
        try:
            if db_as_temp:
                with open(config()['logfile'], "a") as log:
                    json.dump(enrich(data, ipt_data, False, True), log, separators=(",", ":"))
                    log.write("\n")
            else:
                with open(config()['logfile'], "a") as log:
                    json.dump(enrich(data, ipt_data, False, False), log, separators=(",", ":"))
                    log.write("\n")

        except Exception as e:
            print("In function: log_write()")
            print("Error writing to logfile: ", e)


    try:
        db_as_temp = config()["influxdb"]["active"]
        ips = None

        if not db_as_temp:
            ips = Conson(cfilepath=config()["temp"].rsplit("/", 1)[0], cfile=config()["temp"].rsplit("/", 1)[1])
            if not os.path.exists(ips.file):
                ips.save()
            else:
                ips.load()
                for ip_address, values in ips().items():    # removing old tempfile format data
                    if not isinstance(values, list):
                        ips.dispose(ip_address)

        if not os.path.exists(config()['logfile']):
            subprocess.run(["touch", f"{config()['logfile']}"])

        while True:
            conf_change()
            ipt_data = retrieve()
            to_delete = []
            unit, value = config()["timedelta"].split("=")

            if not db_as_temp:
                for ip, ts in ips().items():
                    if ((datetime.now() - datetime.strptime(ts[0], '"%Y-%m-%dT%H:%M:%S.%f"'))
                            > timedelta(**{unit: int(value)})):
                        to_delete.append(ip)

                for ip in to_delete:
                    ips.dispose(ip)

            if ipt_data:
                src = ipt_data['SRC']
                if db_as_temp:
                    db_query = db_mgr("query", src)
                    if len(list(db_query)) == 0:
                        req = api_req(src)
                        db_mgr("insert", enrich(req, ipt_data, True, False))
                        raw = req
                    else:
                        latest_data = list(db_query.get_points())[0]
                        if (datetime.now() - datetime.strptime(latest_data["API_req_ts"], "%Y-%m-%dT%H:%M:%S.%f"))\
                                > timedelta(**{unit: int(value)}):
                            req = api_req(src)
                            db_mgr("insert", enrich(req, ipt_data, True, False))
                            raw = req
                        else:
                            db_mgr("insert", enrich(latest_data, ipt_data, True, True))
                            raw = latest_data
                else:
                    if src not in list(ips()):
                        req = api_req(src)
                        ips.create(src, [datetime.now().isoformat(), req])
                        ips.save()
                        raw = req
                    else:
                        raw = ips()[src][1]
                log_write(raw)

    except Exception as err:
        print("In function: log_way()")
        print("Database connection manager error: ", err)
        breakpoint()
        sys.exit()


def db_way():
    """
    Use InfluxDB database as data container.
    :return:
    """
    while True:
        try:
            conf_change()

            ipt_data = retrieve()
            if ipt_data:
                db_query = db_mgr("query", ipt_data["SRC"])

                if len(list(db_query)) == 0:
                    # if query result is empty, write to fresh data to DB
                    db_mgr("insert", enrich(api_req(ipt_data["SRC"]), ipt_data, True, False))
                else:
                    latest_data = list(db_query.get_points())[0]
                    unit, value = config()['timedelta'].split('=')
                    if (datetime.now() - datetime.strptime(latest_data["API_req_ts"], "%Y-%m-%dT%H:%M:%S.%f")
                            < timedelta(**{unit: int(value)})):
                        db_mgr("insert", enrich(latest_data, ipt_data, True, True))
                    else:
                        db_mgr("insert", enrich(api_req(ipt_data["SRC"]), ipt_data, True, False))

        except Exception as err:
            print("In function: db_way()")
            print("Data comparer error: ", err)
            sys.exit()


args = ['journalctl', '--lines', '0', '--follow', '--grep', '[iptables]']
f = subprocess.Popen(args, stdout=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)
hostname = socket.gethostname()
json_mod_time = None

config = Conson(cfile="geoip2grafana_config.json")
if not os.path.exists(config.file):

    logfile = os.path.join("/var/log/", "geoip2grafana.log")
    temp = os.path.join(r"/tmp/", "geoip2grafana.temp")
    token = "ipinfoToken"

    config.create("logfile", logfile)
    config.create("temp", temp)
    config.create("use_db_only", False)
    config.create("to_collect", "IN", "SRC", "OUT", "SPT", "PROTO", "DST", "DPT")
    config.create("timedelta", "hours=72")
    config.create("excluded_IP", ["127.0.0.0/8", "0.0.0.0"])
    config.create("token", token)
    config.create("influxdb", {"active": False, "db_IP": "localhost", "db_port": 8086, "db_user": "USERNAME",
                               "db_pwd": "PASSWORD", "db_name": "geoip2grafana"})
    config.create("influxdb_tags", ["hostname", "DPT", "PROTO", "API_req_ts"])
    config.save()

    print("Please update your info in config file.")
    input("Press enter to exit...")
    sys.exit()
else:
    mod_time(True)
    config.load()
    pwd = config()["influxdb"]["db_pwd"]
    if len(pwd) != 0 and pwd != "PASSWORD" and pwd[0] != "<" and pwd[-1] != ">":
        tag_pwd()
        config.save()
        mod_time(True)

    if config()["use_db_only"]:
        db_way()
    else:
        log_way()
