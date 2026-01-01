#!/usr/bin/python3
# -*- coding: utf-8 -*- ########################################################
#                ____                     _ __                                 #
#     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           #
#    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           #
#   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            #
#                                            /___/ team                        #
#                                                                              #
# ipcountry                                                                    #
# Fetches IPv4 ranges of given country in host and cidr format.                #
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
import getopt
import requests
import ipaddress
import tarfile
import warnings


__author__ = 'noptrix'
__version__ = '2.0'
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

  ipcountry -c <arg> [options] | <misc>

''' + BOLD + '''options''' + NORM + '''

  -c <code>   - country code, e.g.: am,gr,...
  -t <type>   - ipv4 range type to fetch (default: 'host,cidr')
  -i          - get ipv6 ranges

''' + BOLD + '''misc''' + NORM + '''

  -l          - list all country codes and their full name
  -V          - print version information
  -H          - print this help

'''

opts = {
  'type': ['cidr', 'host'],
  'ipv6': False,
}


def list_countries():
  countries = {
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
  for i, j in countries.items():
    log(f'{i} ({j})', 'verbose')

  return


def check_argv(opts):
  needed = ['-c', '-l', '-V', '-H']

  if set(needed).isdisjoint(set(sys.argv)):
    log('use -H for help', 'error')

  return


def parse_cmdline():
  global opts
  try:
    _opts, args = getopt.getopt(sys.argv[1:], 'c:t:ilVH')
    for o, a in _opts:
      if o == '-c':
        opts['codes'] = a.split(',')
      if o == '-t':
        opts['type'] = a.split(',')
      if o == '-i':
        opts['ipv6'] = True
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
  if len(sys.argv) == 0:
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


def download_and_extract_zones():
  if opts['ipv6']:
    log('downloading ipv6-all-zones.tar.gz', 'info')
    url = 'https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz'
    response = requests.get(url, headers={'User-Agent': UA})
    with open('ipv6-all-zones.tar.gz', 'wb') as f:
      f.write(response.content)

    log('extracting ipv6-all-zones.tar.gz', 'info')
    with tarfile.open('ipv6-all-zones.tar.gz', 'r:gz') as tar:
      tar.extractall(path='zones6', filter=None)
  else:
    log('downloading all-zones.tar.gz', 'info')
    url = 'https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz'
    response = requests.get(url, headers={'User-Agent': UA})
    with open('all-zones.tar.gz', 'wb') as f:
      f.write(response.content)

    log('extracting all-zones.tar.gz', 'info')
    with tarfile.open('all-zones.tar.gz', 'r:gz') as tar:
      tar.extractall(path='zones', filter=None)

  return


def process_country_file(country_code):
  if opts['ipv6']:
    zone_file_path = f'zones6/{country_code}.zone'
  else:
    zone_file_path = f'zones/{country_code}.zone'

  if not os.path.exists(zone_file_path):
    log(f'zone file for \'{country_code}\' not found', 'error')
    return

  log(f'processing \'{country_code}\'', 'info')

  cidr_file = open(f'{country_code}-cidr.txt', 'w') if 'cidr' in opts['type'] \
    else None
  host_file = open(f'{country_code}-host.txt', 'w') if 'host' in opts['type'] \
    else None

  with open(zone_file_path, 'r') as zone_file:
    for line in zone_file:
      line = line.strip()
      if line:
        cidr = line
        if cidr_file:
          cidr_file.write(f'{cidr}\n')
        if host_file:
          try:
            network = ipaddress.IPv6Network(cidr) if opts['ipv6'] else \
              ipaddress.IPv4Network(cidr)
            start_ip = network.network_address + 1
            end_ip = network.broadcast_address - 1
            host_file.write(f'{start_ip}-{end_ip}\n')
          except ValueError as e:
            log(f'error processing line: {line} ({e})', 'error')

  if cidr_file:
    cidr_file.close()
  if host_file:
    host_file.close()

  if 'cidr' in opts['type'] and 'host' in opts['type']:
    log(f'ip ranges for {country_code} saved to {country_code}-*.txt', 'good')
  else:
    log(f'ip ranges for {country_code} saved to '
        f'{country_code}-{opts['type'][0]}.txt', 'good')

  return


def main():
  log(f'{BANNER}\n\n')
  check_argc()
  parse_cmdline()
  check_argv(opts)

  zones_dir = 'zones6' if opts['ipv6'] else 'zones'
  if not os.path.exists(zones_dir):
    download_and_extract_zones()

  for code in opts['codes']:
    process_country_file(code.strip())

  log('game over', 'info')

  return


if __name__ == '__main__':
  warnings.simplefilter('ignore')
  main()


# EOF
