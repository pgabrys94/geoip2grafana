Simple script to enrich iptables journald output with geolocation data acquired from ipinfo.io API to use in Grafana Geomap plugin.

Based on bossm8 idea but does not require docker or syslog-ng: https://medium.com/@bossm8/geoip-dashboards-in-grafana-from-iptables-logs-101a3b256d55

Dependencies:

    pip install pycountry geohash2 conson requests influxdb

Usage:

    nohup python3 geoip2grafana.py &
(or you can create .service file)

VERSION 2.0:

Now you can use InfluxDB database to store your geolocation data. Compatible with version 1.* of database.
You need to set database related parameters in configuration file:

    "influxdb": {
        "active": false,
        "db_IP": "localhost",
        "db_port": 8086,
        "db_user": "USERNAME",
        "db_pwd": "PASSWORD",
        "db_name": "geoip2grafana"
    },

Next, you can set what you want to store as tag. Everything else will be considered as field. You can choose from:

        "country" - full country name,
        "hostname" - hostname creating measurement (table) entry,
        "API_req_ts" - API request timestamp (in ISO format)
        "time_zone" - self explanatory,
        "latitude"  -   self explanatory,
        "longitude" - self explanatory,
        "geohash" - self explanatory,
        "iso_code" - ISO code of source IP country,
        "city" - approximate city location of source IP,
        "organization" - autonomous system owner,
        "ASN" - autonomous system number.

Additionally, you can use any of iptables items, provided you collected them from journal first.

You can set paths to log directory and tempfile directory in geoip2grafana_config.json file. 
You HAVE TO add your own ipinfo.io token to this config.
Also, IP address by default will be queried in API every 72 hours (.temp file stores dictionary of IP:timestamp), 
you can change that value in config using datetime timedelta syntax:

    minutes=float
    hours=float
    days=float
    weeks=float


Requires iptables journald logging:

     iptables -N IP_LOGGING
     iptables -A IP_LOGGING -s 10.0.0.0/8,172.16.0.0/12,192.168.178.0/24,127.0.0.1/32 -j RETURN    # put any private ip pool you do NOT want to log
     iptables -A IP_LOGGING -m recent --rcheck --seconds 43200 --name iptrack --rsource -j RETURN
     iptables -A IP_LOGGING -m recent --set --name iptrack --rsource
     iptables -A IP_LOGGING -j LOG --log-prefix "[iptables] "
     iptables -A INPUT -j IP_LOGGING

Promtail job:

    - job_name: some_job
    static_configs:
    - targets:
        - localhost
      labels:
        job: some_job_label
        __path__: /var/log/geoip2grafana.log
    pipeline_stages:
      - json:
        expressions:
          geoip_country_name: geoip.country.names.en
          geoip_city_name: geoip.city.en
          geoip_geohash: geoip.location.geohash
          geoip_asn: geoip.organization.AS
          geoip_org: geoip.organization.name
    - labels:
        geoip_country_name: geoip_country_name
        geoip_city_name: geoip_city_name
        geoip_geohash: geoip_geohash
        geoip_asn: geoip_asn
        geoip_org: geoip_org
        src_port: ipt.SPT
        dst_port: ipt.DPT
        protocol: ipt.PROTO
    - output:
        source: message

  By default, script will collect from iptables journald log entries following items:

    "IN" - inbound interface
    "SRC" - source IP
    "OUT" - outbound interface
    "SPT" - source port,
    "PROTO" - protocol,
    "DST" - destination IP
    "DPT" - destination port
    
  You can freely add in config file whatever you want to pass to grafana from iptables log. Just remember to put it in promtail job config label.
