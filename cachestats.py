#!env python3
import os
import sys
import re
import requests
import netaddr
from statistics import mean, fmean, mode
from collections import Counter
from prettytable import PrettyTable

# TODO: modify it to run as root, and automatically determine the logfile location based off path in /kinsta/main.conf and refuse to run on staging

""" Regex for parsing kinsta-cache-perf.log """
kcp_log_regex = re.compile(r'^(?P<req_ts>[\w\d\s\/:\+\[\]]+) (?P<req_cache_status>(?:\-|BYPASS|MISS)) (?P<req_cache_zone>[A-Z_]+) (?P<req_ip>[0-9a-f:\.]+) (?P<req_method>GET|POST|PUT|PATCH|DELETE) \"(?P<req_uri>\S+)\" (?P<req_version>HTTP\/[123\.]+) (?P<req_log_cookie>0|\-|cart|wplog|cauth_ppass) (?P<req_upstream_time>[0-9\.]+)$')

""" Catch cases where QS past the first ? contains another ?, as there should only be 1 ? and extra arguments are split by & """
double_qm_invalid_url = re.compile('^[^&\?].*?=.*?\?.*?$')

""" Catch cases where there are multiple & in a query string but only the param name is defined (no =val just &name&name2) """
double_amp_without_equals = re.compile('^.*?\&([^=]+)(?:\&)')

""" Catch cases where there are multi-param which contains a variable without assignment """
multi_param_no_assignment = re.compile('^([\w\d_-]+)[^=]\&')

""" Catch cases where there are param names defined but no value provided at the end of the URL """
final_param_undefined = re.compile('.*\&[^=]+$')

""" Exclude specific exact-match URLs we should ignore from the stats, the point here is to find bypasses the customer / visitors caused """
exclude_urls = ['/wp-cron.php?server_triggered_cronjob', '/?kinsta-monitor', '?server_triggered_cronjob', '?kinsta-monitor' ]

""" Notify us if a URL uses parameters that our cache uses, or bypasses based on """
notify_params = ['nocache']

""" RFI Exceptions """

rfi_exceptions = ['/wp-json/oembed/1.0/embed', '/wp-login.php']

""" JSON endpoint detection """

json_endpoint = re.compile(r'^/wp-json/.*$')

""" If the request took longer than 1 second, then we're interested in displaying requests which took at or longer than that """
long_ttfb_threshold = 1.0

class Grok:

    urls            = Counter()         # url counter
    ips             = Counter()         # ip counter
    ip_aggregates   = Counter()         # ip aggregate buffer
    cookies         = Counter()         # cookie status counter
    methods         = Counter()         # http method counter
    zones           = Counter()         # cache zone counter
    param_names     = Counter()         # param name counter
    long_running    = Counter()         # long-running request url counter
    ts_index_count  = Counter()
    json_queries    = Counter()
    line            = str               # temp buffer for log parsing

    upstream_times      = []            # holds all the upstream response time floats
    upstream_time_reqs  = 0             # total bypass requests

    upstream_time_total = float(0.0)    # holds the total of all response times combined
    upstream_time_avg   = float(0.0)    # average upstream time
    upstream_time_min   = float(0.0)    # minimum upstream time
    upstream_time_max   = float(0.0)    # maximum upstream time
    nz_upstream_time_avg   = float(0.0) # average non-zero upstream time
    nz_upstream_time_min   = float(0.0) # minimum non-zero upstream time
    nz_upstream_time_max   = float(0.0) # maximum non-zero upstream time

    log_buffer = []

    """ Create our Grok class """

    def __init__(self) -> None:
        pass

    """ Process upstream time numbers from self.upstream_times """

    def process_upstream_times(self):

        if self.upstream_times.__len__ == 0:
            print('ERROR: Unable to display stats, because there were no BYPASS requests detected from the current log')
            sys.exit(1)

        nz_upstreams = list(filter(lambda x: x != 0.0, self.upstream_times))

        self.upstream_time_avg = round(mean(self.upstream_times), 4)
        self.upstream_time_min = round(min(self.upstream_times), 4)
        self.upstream_time_max = round(max(self.upstream_times), 4)

        self.nz_upstream_time_avg = round(mean(nz_upstreams), 4)
        self.nz_upstream_time_min = round(min(nz_upstreams), 4)
        self.nz_upstream_time_max = round(max(nz_upstreams), 4)


    """ Given a list of IP addresses, condense the list to IPv4/IPv6 subnets, provided enough IPs exist in a particular subnet mask """
    """ Ideally reduce to CIDR representation where it matches the closest bits required to cover IPs in that subnet mask """

    def process_ip_aggregation(self):

        ips_unique = set()
        ip_network_list = []

        # Duplicate IP removal
        for (k, v) in self.ips.items():
            if k not in ips_unique:
                ips_unique.add(k)

        ip_list = list(ips_unique)

        for ipl in ip_list:
            ip_network_list.append(netaddr.IPNetwork(ipl))

        final_list = netaddr.cidr_merge(ip_network_list)

        for _fl in final_list:
            fl = str(_fl)
           # Don't print/add single IPs either v4 or v6
            if not fl.endswith('/32') and not fl.endswith('/128'):
                self.ip_aggregates[fl] += 1

    """ Import cache log and process lines """

    def import_kcp(self, lf_path):

        # Chunk import 100k lines at a time
        with open(lf_path, 'r', buffering=100000) as f:
            for line in f:
                self.line = line
                self.grok(self)

        # When we're done, send to another function to crunch the numbers
        self.process_upstream_times(self)
        self.process_ip_aggregation(self)

    """ Extract single argument query string param names """

    def dict_qs(self, query_string):

        params = []

        if '=' in query_string:
            params = query_string.split('=')
            self.param_names.update(params[0::2])
            for _param in params:
                if _param in notify_params and query_string not in exclude_urls:
                    self.log_buffer.append(f'System query string parameter present in non system request: `{_param}` in `{query_string}`')
        else:
            self.param_names[query_string] += 1

    """ Extract multiple argument query string param names """

    def dict_multiqs(self, query_string, full_url):

        params = {}

        # Catch cases where query string is misconfigured, or missing query string parameter names and assignment operators and values, but still delimited by ampersand
        if query_string.startswith('?&') or query_string == '' or query_string.startswith('&') or query_string.endswith('&'):
            return

        # Check for double ? condition, skip if URL is invalid
        is_invalid = double_qm_invalid_url.match(query_string)
        if is_invalid is not None:
            self.log_buffer.append(f'Misconfigured QS translation / URI encoding issue with query string: `{query_string}` in `{full_url}`')
            return

        # Check for query string param names that don't have a value assigned, and end with a & without a param name or value, e.g. ?param_name&
        is_mqs_invalid = double_amp_without_equals.match(query_string)
        if is_mqs_invalid is not None:
            self.log_buffer.append(f'Misconfigured prepended query string key without assignment `{query_string}` in `{full_url}`')
            return

        # Check for query string param names where there are multiple valid params but a parameter name defined without a value, and URL not ending in &
        is_mqs_noassign = multi_param_no_assignment.match(query_string)
        if is_mqs_noassign is not None:
            self.log_buffer.append(f'Misconfigured multi-param without assignment `{query_string}` in `{full_url}`')
            return

        # Check for query string where the is a parameter name provided (singular) but there is no value assigned
        is_fpu_empty = final_param_undefined.match(query_string)
        if is_fpu_empty is not None:
            if '?nocache' not in query_string and '&nocache' not in query_string and '?doing_wp_cron' not in query_string and '&doing_wp_cron' not in query_string:
                self.log_buffer.append(f'Missing non-system final parameter value in request url `{query_string}` in `{full_url}`')
            return

        # Catch cases where query string starts with ?http://something=x or ?http://something&
        if query_string.startswith('http'):
            self.log_buffer.append(f'Misconfigured parameter name, URL should be parameter value and not parameter name in query string: `{query_string}` in `{full_url}`')
            return

        if '://' in full_url or '%3a%2f%2f' in full_url.lower():

            for rfi_allowed in rfi_exceptions:

                # Misconfigured query string, :// should be encoded as % instead if it's a query string value
                if '://' in query_string and not full_url.startswith(rfi_allowed):
                    self.log_buffer.append(f'Non-normalized URL inclusion in query arguments: `{query_string}` in `{full_url}`')
                    return

                # If %3a%2f%2f (://) is present anywhere in the query string, trigger a warning that will skip the URL for stats, but trigger a log notice after the report
                if '%3a%2f%2f' in query_string.lower() and not full_url.startswith(rfi_allowed):
                    self.log_buffer.append(f'Possible (normalized, %-encoded) RFI or protocol handler injection in query string: `{query_string}` in `{full_url}`')
                    return

        

        if any([ele for ele in ['%3c', '%3e', '%7c', '%22', '%20'] if(ele in query_string.lower())]):
        # yikes do not uncomment
            # self.log_buffer.append(f'Possible HTML fragments found in query string `{url}` in `{full_url}`')
            return

        if ';' in query_string:
            self.log_buffer.append(f'Alternative query string separator requests found in query string `{query_string}` as part of `{full_url}`')
            return

        # Catch arguments which provide base64-ish data
        # 'page=pie-register&show_dash_widget=1&invitaion_code=PHNjcmlwdD5hbGVydChTdHJpbmcuZnJvbUNoYXJDb2RlKDgxLDg1LDY1LDc2LDg5LDgzLDg4LDgzLDgzLDg0LDY5LDgzLDg0KSk8L3NjcmlwdD4='
        if query_string.endswith('='):
            self.log_buffer.append(f'Assignment character = at end of URL `{query_string}` while accessing `{full_url}`')
            return

        # '/wp-admin/edit.php?s&post_status=all&post_type=audio&action=-1&m=0&cat=0&series=0&audio_show=biblical_studies&filter_action=Filter&paged=1&action2=-1'
        # 's&post_status=all&post_type=audio&action=-1&m=0&cat=0&series=0&audio_show=biblical_studies&filter_action=Filter&paged=1&action2=-1'

        # Account for cases where there are double ampersands
        if '&&' in query_string:
            furl = query_string.replace('&&', '&')
            params = dict(x.split('=') for x in furl.split('&'))
        else:
            try:
                params = dict(x.split('=') for x in query_string.split('&'))
            except ValueError:
                self.log_buffer.append(f"WARN: Invalid query string structure: `{query_string}`")
                return

        # Extract parameters to param counters, and log if we found our system params in the logs
        for _param in params:
            self.param_names[ _param ] += 1
            if _param in notify_params and full_url not in exclude_urls:
                self.log_buffer.append(f'System parameter `{_param}` found in request `{full_url}`')



    """ Process line from import_kcp, and increase counters for cache bypasses """

    def grok(self):

        text = self.line
        matches = kcp_log_regex.match(text)

        if matches is not None:
            
            if (matches['req_cache_status'] in ['BYPASS', 'MISS', '-', 'EXPIRED', 'STALE']):

                req_cookie          = matches['req_log_cookie']
                req_method          = matches['req_method']
                req_cache_zone      = matches['req_cache_zone']
                req_ip              = matches['req_ip']
                req_uri             = matches['req_uri']
                req_ts              = matches['req_ts']
                req_upstream_time   = float(matches['req_upstream_time'])
                query_string        = requests.utils.urlparse(req_uri).query

                if req_uri in exclude_urls:
                    return

                if '%3d' in req_uri.lower():
                    self.log_buffer.append(f'Encoded = (%3D) present in URL or query argument {req_uri}')
                    return

                is_json_query = json_endpoint.match(req_uri)
                if is_json_query is not None:
                    # make sure we pass the base wp-json URI only
                    jkey = req_uri.replace(query_string, '')
                    self.json_queries[ jkey ] += 1

                if '&' in req_uri:
                    self.dict_multiqs(self, query_string, req_uri)
                elif '?' in req_uri:
                    self.dict_qs(self, query_string)
                elif '&' not in req_uri and '?' not in req_uri:
                     pass
                    
                # Find specific requests that exceed the low TTFB threshold
                if req_upstream_time > long_ttfb_threshold:
                    rut_str = f'{req_ip}#{req_upstream_time}#{req_uri}'
                    self.long_running[rut_str] += 1
                    
                self.ts_index_count [ req_ts ]  += 1
                self.urls[ f'{req_method}##{req_uri}' ]            += 1
                self.ips[ req_ip ]              += 1
                self.cookies[ req_cookie ]      += 1
                self.methods[ req_method ]      += 1
                self.zones[ req_cache_zone ]    += 1

                self.upstream_time_total += float(req_upstream_time)
                self.upstream_times.append(req_upstream_time)
                self.upstream_time_reqs += 1

if __name__ == '__main__':

    g = Grok
    g.import_kcp(g, 'kinsta-cache-perf.log')

    print("Cache Stats Report")
    print("-----------------------------------")
    print("\n\n")
    print("Includes all requests which bypass or miss cache, excluding our own default cronjob and uptime monitoring requests")
    print("-----------------------------------")
    print("\n\n")
    print(f'Average upstream time: {g.upstream_time_avg}')
    print(f'Minimum upstream time: {g.upstream_time_min}')
    print(f'Maximum upstream time: {g.upstream_time_max}')
    print("\n\n")
    print(f'Average non-zero upstream time: {g.nz_upstream_time_avg}')
    print(f'Minimum non-zero upstream time: {g.nz_upstream_time_min}')
    print(f'Maximum non-zero upstream time: {g.nz_upstream_time_max}')
    print("\n\n")

    print("\n\n=====Top URLs:=====\n\n")
    print("\nExplanation: This table contains the top URLs, including the HTTP method and number of requests which caused the most bypassable requests, sorted by the URLs with the most requests bypassed\n\n")
    top_url_table = PrettyTable()
    top_url_table.field_names = ['URL', 'Method', 'Requests']
    top_url_table.align = "r"
    top_url_table.align['URL'] = "l"
    for _row in g.urls.most_common(20):
        (k, v) = _row
        method, url = k.split('##')
        top_url_table.add_row([url, method, v])
    print(top_url_table)

    print("\n\n=====Top IPs:=====\n\n")
    print("\nExplanation: This table contains the IPs which caused the most bypassable requests, sorted by most requests bypassed\n\n")
    top_ip_table = PrettyTable()
    top_ip_table.field_names = ['IP', 'Requests']
    top_ip_table.align = "r"
    top_ip_table.align['URL'] = "l"
    for _row in g.ips.most_common(20):
        (k, v) = _row
        top_ip_table.add_row([k, v])
    print(top_ip_table)

    print("\n\n=====Top Log Cookie statuses:=====\n\n")
    print("\nExplanation: This table contains the possible system default cookies we track, e.g. `0` (none?), `wplog` (logged in to wordpress), `cart` (item in cart), or `cauth_ppass` (password protected page/post)\n\n")
    top_cookie_table = PrettyTable()
    top_cookie_table.field_names = ['Cache Log Cookie Status', 'Requests']
    top_cookie_table.align = "r"
    top_cookie_table.align['Cache Log Cookie Status'] = "l"
    for _row in g.cookies.most_common(20):
        (k, v) = _row
        top_cookie_table.add_row([k, v])
    print(top_cookie_table)

    print("\n\n=====Top HTTP Methods:=====\n\n")
    print("\nExplanation: This table contains the top HTTP Method verbs sorted by the number of bypassable requests with those verbs\n\n")
    top_method_table = PrettyTable()
    top_method_table.field_names = ['Bypass Request Method', 'Requests']
    top_method_table.align = "r"
    top_method_table.align['Bypass Request Method'] = "l"
    for _row in g.methods.most_common(20):
        (k, v) = _row
        top_method_table.add_row([k, v])
    print(top_method_table)

    print("\n\n=====Top cache zones:=====\n\n")
    print("\nExplanation: This table contains the names of the FastCGI cache zones which were bypassed the most.  Our defaults are `KINSTAWP` for Desktop traffic, and `KINSTAWP_MOBILE` for clients detect as being from a mobile device (by User-Agent)\n\n")
    top_zone_table = PrettyTable()
    top_zone_table.field_names = ['Cache Zone', 'Bypasses']
    top_zone_table.align = "r"
    top_zone_table.align['Cache Zone'] = "l"
    for _row in g.zones.most_common(20):
        (k, v) = _row
        top_zone_table.add_row([k, v])
    print(top_zone_table)

    print("\n\n=====Top parameter names:=====\n\n")
    print("\nExplanation: This table contains the most used query string parameters\n\n")
    top_param_table = PrettyTable()
    top_param_table.field_names = ['Parameter Name', 'Bypasses with this parameter']
    top_param_table.align = "r"
    top_param_table.align['Parameter Name'] = "l"
    for _row in g.param_names.most_common(20):
        (k, v) = _row
        top_param_table.add_row([k, v])
    print(top_param_table)


    print("\n\n=====Outlier URLs:=====\n\n")
    print("\nExplanation: This table contains the LEAST visited URLs along with it's methods and number of requests that match, sorted by the number of requests descending\n\n")
    top_url_table = PrettyTable()
    top_url_table.field_names = ['URL', 'Method', 'Requests']
    top_url_table.align = "r"
    top_url_table.align['URL'] = "l"
    for _row in list(reversed(g.urls.most_common()[-20:-1])):
        (k, v) = _row
        method, url = k.split('##')
        top_url_table.add_row([url, method, v])
    print(top_url_table)

    print("\n\n=====Outlier IPs (Aggregated):=====\n\n")
    print("\nExplanation: This table contains the IP addresses which had the fewest visits.  They are grouped to slightly larger CIDR blocks if relevant to reduce the length of the output, single IP address visits are discarded from the stats\n\n")
    top_ip_table = PrettyTable()
    top_ip_table.field_names = ['IP', 'Requests']
    top_ip_table.align = "r"
    top_ip_table.align['IP'] = "l"
    for _row in list(reversed(g.ip_aggregates.most_common()[-100:-1])):
        (k, v) = _row
        top_ip_table.add_row([k, v])
    print(top_ip_table)

    print("\n\n=====Outlier cache zones:=====\n\n")
    print("\nExplanation: This table contains the least used FastCGI cache zones\n\n")
    top_zone_table = PrettyTable()
    top_zone_table.field_names = ['Cache Zone', 'Requests']
    top_zone_table.align = "r"
    top_zone_table.align['Cache Zone'] = "l"
    for _row in list(reversed(g.zones.most_common()[-50:-1])):
        (k, v) = _row
        top_zone_table.add_row([k, v])
    print(top_zone_table)

    print("\n\n=====Outlier parameter names:=====\n\n")
    print("\nExplanation: This table contains the least used query string parameters\n\n")
    top_param_table = PrettyTable()
    top_param_table.field_names = ['Parameter Name', 'Bypasses with this parameter']
    top_param_table.align = "r"
    top_param_table.align['Parameter Name'] = "l"
    for _row in list(reversed(g.param_names.most_common()[-20:-1])):
        (k, v) = _row
        top_param_table.add_row([k, v])
    print(top_param_table)

    print("\n\n=====Longest Response Time URLs:=====\n\n")
    print("\nExplanation: This table contains the IPs and URLs that took the longest amount of upstream response time.  NB: The sorting is currently attempted by integer sort not floating sort, so you'll still want to look for the highest number though it may not be at the top of the table\n\n")
    top_param_table = PrettyTable()
    top_param_table.field_names = ['IP', 'URL', 'Upstream Response Time']
    top_param_table.align = "r"
    top_param_table.align['IP'] = "l"
    top_param_table.align['URL'] = "l"
    top_param_table.align['Upstream Response Time'] = "l"
    top_param_table.sortby = 'Upstream Response Time'
    top_param_table.reversesort = True
    for _row in list(reversed(g.long_running.most_common()[-20:-1])):
        (k, v) = _row
        (ip, urt, url) = k.split('#')
        top_param_table.add_row([ip, url, urt])
    print(top_param_table)

    print("\n\n=====Top Bypass spikes in the same second (bypass/sec):=====\n\n")
    print("\nExplanation: This table contains the most common bypass timestamps to help identify spikes (when the timestamp is logged it's indicating the time the request was received, not the time it was logged)  The timestamp may help you derive context from additional log searches\n\n")
    top_spike_table = PrettyTable()
    top_spike_table.field_names = ['Timestamp', 'Count']
    top_spike_table.align = "l"
    top_spike_table.align['Count'] = "r"
    top_spike_table.sortby = 'Count'
    top_spike_table.reversesort = True
    for _row in list(g.ts_index_count.most_common(10)):
        (k, v) = _row
        if v != 1:
            top_spike_table.add_row([k, v])
    print(top_spike_table)


    print("\n\n=====Top JSON Endpoints:=====\n\n")
    print("\nExplanation: This table contains the most common WP-JSON endpoints ordered by requests received\n\n")
    top_json_table = PrettyTable()
    top_json_table.field_names = ['JSON Endpoint', 'Count']
    top_json_table.align = "l"
    top_json_table.align['Count'] = "r"
    top_json_table.sortby = 'Count'
    top_json_table.reversesort = True
    for _row in list(g.json_queries.most_common(10)):
        (k, v) = _row
        if v >= 1:
            top_json_table.add_row([k, v])
    print(top_json_table)


    print("\n\n=====Interesting Observations=====\n\n")
    print("\nExplanation: Any anomalous findings will be output here to hopefully identify secondary issues\n\n")

    for log in g.log_buffer:
        print(log)
