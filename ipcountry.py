#!/usr/bin/python3
# -*- coding: utf-8 -*- ########################################################
#                ____                     _ __                                 #
#     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           #
#    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           #
#   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            #
#                                            /___/ team                        #
#                                                                              #
# ipcountry                                                                    #
# Fetches IP ranges of given country in host and cidr format.                  #
#                                                                              #
# NOTES                                                                        #
# - quick'n'dirty                                                              #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


import os
import sys
import time
import json
import bisect
import shutil
import getopt
import requests
import ipaddress
import tarfile
import warnings


__author__ = 'noptrix'
__version__ = '2.3'
__copyright__ = 'santa clause'
__license__ = '1337 h4x0r'

NORM = '\033[0m'
BOLD = '\033[1;37;10m'
RED = '\033[1;31;10m'
GREEN = '\033[1;32;10m'
YELLOW = '\033[1;33;10m'
BLUE = '\033[1;34;10m'

SUCCESS = 0
FAILURE = 1

UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36'

BANNER = BLUE + r'''    _                              __
   (_)___  _________  __  ______  / /________  __
  / / __ \/ ___/ __ \/ / / / __ \/ __/ ___/ / / /
 / / /_/ / /__/ /_/ / /_/ / / / / /_/ /  / /_/ /
/_/ .___/\___/\____/\__,_/_/ /_/\__/_/   \__, /
 /_/                                    /____/
''' + NORM + '''
      --== [ by nullsecurity.net ] ==--'''

HELP = BOLD + '''usage''' + NORM + '''

  ipcountry <mode> [options] | <misc>

''' + BOLD + '''mode''' + NORM + '''

  -c <code>   - fetch ip ranges for country code(s), e.g.: am,gr,... ('all' = every one)
  -x <ip>     - reverse lookup ip(s) -> country code ('-' reads ips from stdin)

''' + BOLD + '''options''' + NORM + '''

  -t <type>   - ip range type to fetch (default: 'host,cidr')
  -o <file>   - write ranges to <file> ('-' for stdout) instead of per-country files
  -j          - write ranges as jsonl (one {country,type,range} object per line)
  -i          - get ipv6 ranges
  -r          - remove downloaded tar.gz and extracted zones dir after processing

''' + BOLD + '''misc''' + NORM + '''

  -l          - list all country codes and their full name
  -V          - print version information
  -H          - print this help

''' + BOLD + '''examples''' + NORM + '''

  # fetch cidr + host ranges for multiple countries
  $ ipcountry -c am,gr,cy

  # fetch ranges for all countries at once
  $ ipcountry -c all

  # stream ranges to stdout for piping ('-' = stdout)
  $ ipcountry -c ru -t cidr -o -

  # reverse lookup: which country owns an ip ('-' reads ips from stdin)
  $ ipcountry -x 8.8.8.8

'''

opts = {
  'type': ['cidr', 'host'],
  'ipv6': False,
  'cleanup': False,
}


COUNTRIES = {
    'af': 'Afghanistan',
    'ax': 'Åland',
    'al': 'Albania',
    'dz': 'Algeria',
    'ad': 'Andorra',
    'ao': 'Angola',
    'ai': 'Anguilla',
    'aq': 'Antarctica',
    'ag': 'Antigua and Barbuda',
    'ar': 'Argentina',
    'am': 'Armenia',
    'aw': 'Aruba',
    'ac': 'Ascension Island',
    'au': 'Australia',
    'at': 'Austria',
    'az': 'Azerbaijan',
    'bs': 'Bahamas',
    'bh': 'Bahrain',
    'bd': 'Bangladesh',
    'bb': 'Barbados',
    'by': 'Belarus',
    'be': 'Belgium',
    'bz': 'Belize',
    'bj': 'Benin',
    'bm': 'Bermuda',
    'bt': 'Bhutan',
    'bo': 'Bolivia',
    'ba': 'Bosnia and Herzegovina',
    'bw': 'Botswana',
    'bv': 'Bouvet Island',
    'br': 'Brazil',
    'io': 'British Indian Ocean Territory',
    'vg': 'British Virgin Islands',
    'bn': 'Brunei',
    'bg': 'Bulgaria',
    'bf': 'Burkina Faso',
    'bi': 'Burundi',
    'kh': 'Cambodia',
    'cm': 'Cameroon',
    'ca': 'Canada',
    'cv': 'Cape Verde',
    'ky': 'Cayman Islands',
    'cf': 'Central African Republic',
    'td': 'Chad',
    'cl': 'Chile',
    'cn': 'China',
    'cx': 'Christmas Island',
    'cc': 'Cocos (Keeling) Islands',
    'co': 'Colombia',
    'km': 'Comoros',
    'cd': 'Congo (Democratic Republic)',
    'cg': 'Congo (Republic)',
    'ck': 'Cook Islands',
    'cr': 'Costa Rica',
    'ci': 'Côte d’Ivoire',
    'hr': 'Croatia',
    'cu': 'Cuba',
    'cw': 'Curaçao',
    'cy': 'Cyprus',
    'cz': 'Czechia',
    'dk': 'Denmark',
    'dj': 'Djibouti',
    'dm': 'Dominica',
    'do': 'Dominican Republic',
    'tl': 'East Timor',
    'ec': 'Ecuador',
    'eg': 'Egypt',
    'sv': 'El Salvador',
    'gq': 'Equatorial Guinea',
    'er': 'Eritrea',
    'ee': 'Estonia',
    'et': 'Ethiopia',
    'eu': 'European Union',
    'fk': 'Falkland Islands',
    'fo': 'Faroe Islands',
    'fm': 'Micronesia',
    'fj': 'Fiji',
    'fi': 'Finland',
    'fr': 'France',
    'gf': 'French Guiana',
    'pf': 'French Polynesia',
    'tf': 'French Southern Territories',
    'ga': 'Gabon',
    'gm': 'Gambia',
    'ps': 'Palestine',
    'ge': 'Georgia',
    'de': 'Germany',
    'gh': 'Ghana',
    'gi': 'Gibraltar',
    'gr': 'Greece',
    'gl': 'Greenland',
    'gd': 'Grenada',
    'gp': 'Guadeloupe',
    'gu': 'Guam',
    'gt': 'Guatemala',
    'gg': 'Guernsey',
    'gn': 'Guinea',
    'gw': 'Guinea-Bissau',
    'gy': 'Guyana',
    'ht': 'Haiti',
    'hm': 'Heard Island and McDonald Islands',
    'hn': 'Honduras',
    'hk': 'Hong Kong',
    'hu': 'Hungary',
    'is': 'Iceland',
    'in': 'India',
    'id': 'Indonesia',
    'ir': 'Iran',
    'iq': 'Iraq',
    'ie': 'Ireland',
    'im': 'Isle of Man',
    'il': 'Israel',
    'it': 'Italy',
    'jm': 'Jamaica',
    'jp': 'Japan',
    'je': 'Jersey',
    'jo': 'Jordan',
    'kz': 'Kazakhstan',
    'ke': 'Kenya',
    'ki': 'Kiribati',
    'kw': 'Kuwait',
    'kg': 'Kyrgyzstan',
    'la': 'Laos',
    'lv': 'Latvia',
    'lb': 'Lebanon',
    'ls': 'Lesotho',
    'lr': 'Liberia',
    'ly': 'Libya',
    'li': 'Liechtenstein',
    'lt': 'Lithuania',
    'lu': 'Luxembourg',
    'mo': 'Macau',
    'mk': 'North Macedonia',
    'mg': 'Madagascar',
    'mw': 'Malawi',
    'my': 'Malaysia',
    'mv': 'Maldives',
    'ml': 'Mali',
    'mt': 'Malta',
    'mh': 'Marshall Islands',
    'mq': 'Martinique',
    'mr': 'Mauritania',
    'mu': 'Mauritius',
    'yt': 'Mayotte',
    'mx': 'Mexico',
    'md': 'Moldova',
    'mc': 'Monaco',
    'mn': 'Mongolia',
    'me': 'Montenegro',
    'ms': 'Montserrat',
    'ma': 'Morocco',
    'mz': 'Mozambique',
    'mm': 'Myanmar',
    'na': 'Namibia',
    'nr': 'Nauru',
    'np': 'Nepal',
    'nl': 'Netherlands',
    'nc': 'New Caledonia',
    'nz': 'New Zealand',
    'ni': 'Nicaragua',
    'ne': 'Niger',
    'ng': 'Nigeria',
    'nu': 'Niue',
    'nf': 'Norfolk Island',
    'kp': 'North Korea',
    'mp': 'Northern Mariana Islands',
    'no': 'Norway',
    'om': 'Oman',
    'pk': 'Pakistan',
    'pw': 'Palau',
    'pa': 'Panama',
    'pg': 'Papua New Guinea',
    'py': 'Paraguay',
    'pe': 'Peru',
    'ph': 'Philippines',
    'pn': 'Pitcairn Islands',
    'pl': 'Poland',
    'pt': 'Portugal',
    'pr': 'Puerto Rico',
    'qa': 'Qatar',
    'ro': 'Romania',
    'ru': 'Russia',
    'rw': 'Rwanda',
    're': 'Réunion',
    'bl': 'Saint Barthélemy',
    'sh': 'Saint Helena',
    'kn': 'Saint Kitts and Nevis',
    'lc': 'Saint Lucia',
    'mf': 'Saint Martin',
    'pm': 'Saint Pierre and Miquelon',
    'vc': 'Saint Vincent and the Grenadines',
    'ws': 'Samoa',
    'sm': 'San Marino',
    'st': 'São Tomé and Príncipe',
    'sa': 'Saudi Arabia',
    'sn': 'Senegal',
    'rs': 'Serbia',
    'sc': 'Seychelles',
    'sl': 'Sierra Leone',
    'sg': 'Singapore',
    'sx': 'Sint Maarten',
    'sk': 'Slovakia',
    'si': 'Slovenia',
    'sb': 'Solomon Islands',
    'so': 'Somalia',
    'za': 'South Africa',
    'gs': 'South Georgia and the South Sandwich Islands',
    'kr': 'South Korea',
    'ss': 'South Sudan',
    'es': 'Spain',
    'lk': 'Sri Lanka',
    'sd': 'Sudan',
    'sr': 'Suriname',
    'sj': 'Svalbard and Jan Mayen',
    'sz': 'Eswatini',
    'se': 'Sweden',
    'ch': 'Switzerland',
    'sy': 'Syria',
    'tw': 'Taiwan',
    'tj': 'Tajikistan',
    'tz': 'Tanzania',
    'th': 'Thailand',
    'tg': 'Togo',
    'tk': 'Tokelau',
    'to': 'Tonga',
    'tt': 'Trinidad and Tobago',
    'tn': 'Tunisia',
    'tr': 'Turkey',
    'tm': 'Turkmenistan',
    'tc': 'Turks and Caicos Islands',
    'tv': 'Tuvalu',
    'ug': 'Uganda',
    'ua': 'Ukraine',
    'ae': 'United Arab Emirates',
    'uk': 'United Kingdom',
    'us': 'United States of America',
    'vi': 'United States Virgin Islands',
    'uy': 'Uruguay',
    'uz': 'Uzbekistan',
    'vu': 'Vanuatu',
    'va': 'Vatican City',
    've': 'Venezuela',
    'vn': 'Vietnam',
    'wf': 'Wallis and Futuna',
    'eh': 'Western Sahara',
    'ye': 'Yemen',
    'zm': 'Zambia',
    'zw': 'Zimbabwe'
}


def list_countries():
  for code, name in COUNTRIES.items():
    log(f'{code} ({name})', 'verbose')

  return


def validate_codes(codes):
  unknown = [c for c in codes if c != 'all' and c not in COUNTRIES]
  if unknown:
    log(f'unknown country code(s): {", ".join(unknown)} (use -l to list codes)',
        'warn')

  return


def validate_types():
  invalid = [t for t in opts['type'] if t not in ('cidr', 'host')]
  if invalid:
    log(f'invalid range type(s): {", ".join(invalid)} (valid: cidr, host)',
        'error')

  return


def check_argv(opts):
  needed = ['-c', '-x', '-l', '-V', '-H']

  if set(needed).isdisjoint(set(sys.argv)):
    log('use -H for help', 'error')

  return


def parse_cmdline():
  global opts
  try:
    _opts, args = getopt.getopt(sys.argv[1:], 'c:t:o:x:jilrVH')
    for o, a in _opts:
      if o == '-c':
        opts['codes'] = a.split(',')
      if o == '-t':
        opts['type'] = a.split(',')
      if o == '-o':
        opts['outfile'] = a
      if o == '-x':
        opts['reverse'] = a.split(',')
      if o == '-j':
        opts['json'] = True
      if o == '-i':
        opts['ipv6'] = True
      if o == '-r':
        opts['cleanup'] = True
      if o == '-l':
        list_countries()
        sys.exit(SUCCESS)
      if o == '-V':
        log(f'ipcountry v{__version__}', 'info')
        sys.exit(SUCCESS)
      if o == '-H':
        log(HELP)
        sys.exit(SUCCESS)
  except (ValueError, getopt.GetoptError) as err:
    log(err.args[0].lower(), 'error')
  except Exception as err:
    log('unknown error', 'error')

  return


def check_argc():
  if len(sys.argv) < 2:
    log('use -H for help', 'error')

  return


def log(msg='', _type='normal', pref='', suf='\n', logfile=False):
  iprefix = f'{BOLD}{BLUE}[+]{NORM} '
  gprefix = f'{BOLD}{GREEN}[*]{NORM} '
  wprefix = f'{BOLD}{YELLOW}[!]{NORM} '
  eprefix = f'{BOLD}{RED}[-]{NORM} '
  vprefix = '    > '

  if _type == 'normal':
    sys.stdout.write(f'{msg}')
  elif _type == 'info':
    sys.stderr.write(f'{pref}{iprefix}{msg}{suf}')
  elif _type == 'good':
    sys.stderr.write(f'{pref}{gprefix}{msg}{suf}')
  elif _type == 'warn':
    sys.stderr.write(f'{pref}{wprefix}{msg}{suf}')
  elif _type == 'error':
    sys.stderr.write(f'{pref}{eprefix}{msg}{suf}')
    sys.exit(FAILURE)
  elif _type == 'verbose':
    sys.stdout.write(f'{pref}{vprefix}{msg}{suf}')
  elif _type == 'spin':
    sys.stderr.flush()
    for i in ('-', '\\', '|', '/'):
      sys.stderr.write(f'\r{BOLD}{BLUE}[{i}]{NORM}{msg} ')
      time.sleep(0.01)
  elif _type == 'file':
    try:
      print(msg, file=logfile)
    except:
      log('could not open or write to file', 'error')

  return


def download_and_extract_zones(ipv6=None):
  if ipv6 is None:
    ipv6 = opts['ipv6']

  if ipv6:
    url = 'https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz'
    tar_file = 'ipv6-all-zones.tar.gz'
    zones_dir = 'zones6'
  else:
    url = 'https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz'
    tar_file = 'all-zones.tar.gz'
    zones_dir = 'zones'

  log(f'downloading {tar_file}', 'info')
  try:
    response = requests.get(url, headers={'User-Agent': UA}, timeout=30)
    response.raise_for_status()
  except requests.RequestException as err:
    log(f'download failed: {err}', 'error')

  with open(tar_file, 'wb') as f:
    f.write(response.content)

  log(f'extracting {tar_file}', 'info')
  try:
    with tarfile.open(tar_file, 'r:gz') as tar:
      tar.extractall(path=zones_dir, filter=None)
  except tarfile.TarError as err:
    log(f'could not extract {tar_file}: {err}', 'error')

  return


def ensure_zones(ipv6):
  zones_dir = 'zones6' if ipv6 else 'zones'
  if not os.path.isdir(zones_dir) or not any(
      f.endswith('.zone') for f in os.listdir(zones_dir)):
    download_and_extract_zones(ipv6)

  return zones_dir


def cleanup_zones():
  if opts['ipv6']:
    tar_file = 'ipv6-all-zones.tar.gz'
    zones_dir = 'zones6'
  else:
    tar_file = 'all-zones.tar.gz'
    zones_dir = 'zones'

  if os.path.isfile(tar_file):
    os.remove(tar_file)
    log(f'removed {tar_file}', 'info')

  if os.path.isdir(zones_dir):
    shutil.rmtree(zones_dir)
    log(f'removed {zones_dir}/', 'info')

  return


def cidr_to_hostrange(cidr):
  network = ipaddress.IPv6Network(cidr) if opts['ipv6'] else \
    ipaddress.IPv4Network(cidr)
  if network.num_addresses == 1:
    return f'{network.network_address}'
  elif network.num_addresses == 2:
    return f'{network.network_address}-{network.broadcast_address}'
  return f'{network.network_address + 1}-{network.broadcast_address - 1}'


def build_reverse_index(zones_dir):
  index = []
  for fname in os.listdir(zones_dir):
    if not fname.endswith('.zone'):
      continue
    code = fname[:-len('.zone')]
    with open(os.path.join(zones_dir, fname), 'r') as f:
      for line in f:
        cidr = line.strip()
        if not cidr:
          continue
        try:
          network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
          continue
        index.append((int(network.network_address),
                      int(network.broadcast_address), code))
  index.sort()

  return index


def lookup_in_index(index, ip):
  ip_int = int(ip)
  # rightmost range whose start <= ip, then walk back through any enclosing nets
  j = bisect.bisect_right(index, (ip_int, float('inf'))) - 1
  while j >= 0 and index[j][0] <= ip_int:
    if ip_int <= index[j][1]:
      return index[j][2]
    j -= 1

  return None


def reverse_lookup(targets):
  raw = []
  for t in targets:
    if t == '-':
      for line in sys.stdin:
        line = line.strip()
        if line:
          raw.append(line)
    else:
      raw.append(t)

  parsed = []
  need = {4: False, 6: False}
  for s in raw:
    try:
      ip = ipaddress.ip_address(s)
    except ValueError:
      log(f'invalid ip: {s}', 'warn')
      parsed.append((s, None))
      continue
    parsed.append((s, ip))
    need[ip.version] = True

  indexes = {}
  if need[4]:
    indexes[4] = build_reverse_index(ensure_zones(False))
  if need[6]:
    indexes[6] = build_reverse_index(ensure_zones(True))

  out = opts.get('out') or sys.stdout
  for s, ip in parsed:
    if ip is None:
      out.write(f'{s}\t-\n')
      continue
    code = lookup_in_index(indexes[ip.version], ip)
    if code:
      out.write(f'{s}\t{code}\t{COUNTRIES.get(code, "?")}\n')
    else:
      out.write(f'{s}\t-\n')

  return


def process_country_file(country_code):
  if opts['ipv6']:
    zone_file_path = f'zones6/{country_code}.zone'
  else:
    zone_file_path = f'zones/{country_code}.zone'

  if not os.path.exists(zone_file_path):
    log(f'zone file for \'{country_code}\' not found', 'warn')
    return

  log(f'processing \'{country_code}\'', 'info')

  out = opts.get('out')

  if opts.get('json'):
    json_file = out if out else open(f'{country_code}.jsonl', 'w')
    with open(zone_file_path, 'r') as zone_file:
      for line in zone_file:
        cidr = line.strip()
        if not cidr:
          continue
        if 'cidr' in opts['type']:
          json_file.write(json.dumps(
            {'country': country_code, 'type': 'cidr', 'range': cidr}) + '\n')
        if 'host' in opts['type']:
          try:
            hostrange = cidr_to_hostrange(cidr)
          except ValueError as e:
            log(f'error processing line: {cidr} ({e})', 'warn')
            continue
          json_file.write(json.dumps(
            {'country': country_code, 'type': 'host', 'range': hostrange}) + '\n')

    if not out:
      json_file.close()
      log(f'ip ranges for {country_code} saved to {country_code}.jsonl', 'good')
    return

  cidr_file = (out if out else open(f'{country_code}-cidr.list', 'w')) \
    if 'cidr' in opts['type'] else None
  host_file = (out if out else open(f'{country_code}-host.list', 'w')) \
    if 'host' in opts['type'] else None

  with open(zone_file_path, 'r') as zone_file:
    for line in zone_file:
      cidr = line.strip()
      if not cidr:
        continue
      if cidr_file:
        cidr_file.write(f'{cidr}\n')
      if host_file:
        try:
          host_file.write(f'{cidr_to_hostrange(cidr)}\n')
        except ValueError as e:
          log(f'error processing line: {cidr} ({e})', 'warn')

  if not out:
    if cidr_file:
      cidr_file.close()
    if host_file:
      host_file.close()

    if 'cidr' in opts['type'] and 'host' in opts['type']:
      log(f'ip ranges for {country_code} saved to {country_code}-*.list', 'good')
    else:
      range_type = opts['type'][0]
      log(f'ip ranges for {country_code} saved to '
          f'{country_code}-{range_type}.list', 'good')

  return


def main():
  sys.stderr.write(f'{BANNER}\n\n')
  check_argc()
  parse_cmdline()
  check_argv(opts)

  log('w00t w00t, game started', 'info')

  dest = opts.get('outfile')
  if dest:
    try:
      opts['out'] = sys.stdout if dest == '-' else open(dest, 'w')
    except OSError as err:
      log(f'could not open output file: {err}', 'error')

  if opts.get('reverse'):
    reverse_lookup(opts['reverse'])
    if opts.get('out') and opts['out'] is not sys.stdout:
      opts['out'].close()
    log('game over', 'info')
    return

  codes = [c.strip() for c in opts['codes']]
  validate_codes(codes)
  validate_types()

  zones_dir = ensure_zones(opts['ipv6'])

  if 'all' in codes:
    codes = sorted(f[:-len('.zone')] for f in os.listdir(zones_dir)
                   if f.endswith('.zone'))
    log(f'processing all {len(codes)} countries', 'info')

  for code in codes:
    process_country_file(code)

  if opts.get('out') and opts['out'] is not sys.stdout:
    opts['out'].close()
    log(f'ip ranges saved to {dest}', 'good')

  if opts['cleanup']:
    cleanup_zones()

  log('game over', 'info')

  return


if __name__ == '__main__':
  warnings.simplefilter('ignore')
  main()


# EOF
