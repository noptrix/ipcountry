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
#import bs4
import ipaddress
import warnings


__author__ = 'noptrix'
__version__ = '1.2'
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

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0'

BANNER = BLUE + '''\
    _                              __
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

  -c <country>  - full country name
  -t <type>     - ipv4 range type to fetch (default: 'host,cidr')

''' + BOLD + '''misc''' + NORM + '''

  -l            - list all countries by name
  -V            - print version information
  -H            - print this help

'''

opts = {
  'type': ['cidr', 'host'],
}


def list_countries():
  countries = {
    "Afghanistan": "af",
    "Åland": "ax",
    "Albania": "al",
    "Algeria": "dz",
    "American Samoa": "",
    "Andorra": "ad",
    "Angola": "ao",
    "Anguilla": "ai",
    "Antarctica": "aq",
    "Antigua and Barbuda": "ag",
    "Argentina": "ar",
    "Armenia": "am",
    "Aruba": "aw",
    "Ascension Island": "ac",
    "Australia": "au",
    "Austria": "at",
    "Azerbaijan": "az",
    "Bahamas": "bs",
    "Bahrain": "bh",
    "Bangladesh": "bd",
    "Barbados": "bb",
    "Basque Country": "eus",
    "Belarus": "by",
    "Belgium": "be",
    "Belize": "bz",
    "Benin": "bj",
    "Bermuda": "bm",
    "Bhutan": "bt",
    "Bolivia": "bo",
    "Bonaire": "bq",
    "Bosnia and Herzegovina": "ba",
    "Botswana": "bw",
    "Bouvet Island": "bv",
    "Brazil": "br",
    "British Indian Ocean Territory": "io",
    "British Virgin Islands": "vg",
    "Brunei": "bn",
    "Bulgaria": "bg",
    "Burkina Faso": "bf",
    "Burma": "mm",
    "Burundi": "bi",
    "Cambodia": "kh",
    "Cameroon": "cm",
    "Canada": "ca",
    "Cape Verde": "cv",
    "Catalonia": "cat",
    "Cayman Islands": "ky",
    "Central African Republic": "cf",
    "Chad": "td",
    "Chile": "cl",
    "China": "cn",
    "Christmas Island": "cx",
    "Cocos (Keeling) Islands": "cc",
    "Colombia": "co",
    "Comoros": "km",
    "Congo Democratic Republic of the (Congo-Kinshasa)": "cd",
    "Congo Republic of the (Congo-Brazzaville)": "cg",
    "Cook Islands": "ck",
    "Costa Rica": "cr",
    "Côte d’Ivoire (Ivory Coast)": "ci",
    "Croatia": "hr",
    "Cuba": "cu",
    "Curaçao": "cw",
    "Cyprus": "cy",
    "Czechia": "cz",
    "Denmark": "dk",
    "Djibouti": "dj",
    "Dominica": "dm",
    "Dominican Republic": "do",
    "East Timor (Timor-Leste)": "tl",
    "Ecuador": "ec",
    "Egypt": "eg",
    "El Salvador": "sv",
    "Equatorial Guinea": "gq",
    "Eritrea": "er",
    "Estonia": "ee",
    "Ethiopia": "et",
    "European Union": "eu",
    "Falkland Islands": "fk",
    "Faeroe Islands": "fo",
    "Federated States of Micronesia": "fm",
    "Fiji": "fj",
    "Finland": "fi",
    "France": "fr",
    "French Guiana": "gf",
    "French Polynesia": "pf",
    "French Southern and Antarctic Lands": "tf",
    "Gabon": "ga",
    "Galicia": "gal",
    "Gambia": "gm",
    "Gaza Strip (Gaza)": "ps",
    "Georgia": "ge",
    "Germany": "de",
    "Ghana": "gh",
    "Gibraltar": "gi",
    "Greece": "gr",
    "Greenland": "gl",
    "Grenada": "gd",
    "Guadeloupe": "gp",
    "Guam": "gu",
    "Guatemala": "gt",
    "Guernsey": "gg",
    "Guinea": "gn",
    "Guinea-Bissau": "gw",
    "Guyana": "gy",
    "Haiti": "ht",
    "Heard Island and McDonald Islands": "hm",
    "Honduras": "hn",
    "Hong Kong": "hk",
    "Hungary": "hu",
    "Iceland": "is",
    "India": "in",
    "Indonesia": "id",
    "Iran": "ir",
    "Iraq": "iq",
    "Ireland": "ie",
    "Isle of Man": "im",
    "Israel": "il",
    "Italy": "it",
    "Jamaica": "jm",
    "Japan": "jp",
    "Jersey": "je",
    "Jordan": "jo",
    "Kazakhstan": "kz",
    "Kenya": "ke",
    "Kiribati": "ki",
    "Kosovo": "",
    "Kuwait": "kw",
    "Kyrgyzstan": "kg",
    "Laos": "la",
    "Latvia": "lv",
    "Lebanon": "lb",
    "Lesotho": "ls",
    "Liberia": "lr",
    "Libya": "ly",
    "Liechtenstein": "li",
    "Lithuania": "lt",
    "Luxembourg": "lu",
    "Macau": "mo",
    "Macedonia North": "mk",
    "Madagascar": "mg",
    "Malawi": "mw",
    "Malaysia": "my",
    "Maldives": "mv",
    "Mali": "ml",
    "Malta": "mt",
    "Marshall Islands": "mh",
    "Martinique": "mq",
    "Mauritania": "mr",
    "Mauritius": "mu",
    "Mayotte": "yt",
    "Mexico": "mx",
    "Moldova": "md",
    "Monaco": "mc",
    "Mongolia": "mn",
    "Montenegro": "me",
    "Montserrat": "ms",
    "Morocco": "ma",
    "Mozambique": "mz",
    "Myanmar": "mm",
    "Namibia": "na",
    "Nauru": "nr",
    "Nepal": "np",
    "Netherlands": "nl",
    "New Caledonia": "nc",
    "New Zealand": "nz",
    "Nicaragua": "ni",
    "Niger": "ne",
    "Nigeria": "ng",
    "Niue": "nu",
    "Norfolk Island": "nf",
    "North Cyprus": "nc.tr",
    "North Korea": "kp",
    "North Macedonia": "mk",
    "Northern Mariana Islands": "mp",
    "Norway": "no",
    "Oman": "om",
    "Pakistan": "pk",
    "Palau": "pw",
    "Palestine": "ps",
    "Panama": "pa",
    "Papua New Guinea": "pg",
    "Paraguay": "py",
    "Peru": "pe",
    "Philippines": "ph",
    "Pitcairn Islands": "pn",
    "Poland": "pl",
    "Portugal": "pt",
    "Puerto Rico": "pr",
    "Qatar": "qa",
    "Romania": "ro",
    "Russia": "ru",
    "Rwanda": "rw",
    "Réunion Island": "re",
    "Saba": "bq",
    "Saint Barthélemy": "bl",
    "Saint Helena": "sh",
    "Saint Kitts and Nevis": "kn",
    "Saint Lucia": "lc",
    "Saint Martin": "mf",
    "Saint-Pierre and Miquelon": "pm",
    "Saint Vincent and the Grenadines": "vc",
    "Samoa": "ws",
    "San Marino": "sm",
    "São Tomé and Príncipe": "st",
    "Saudi Arabia": "sa",
    "Senegal": "sn",
    "Serbia": "rs",
    "Seychelles": "sc",
    "Sierra Leone": "sl",
    "Singapore": "sg",
    "Sint Eustatius": "bq",
    "Sint Maarten": "sx",
    "Slovakia": "sk",
    "Slovenia": "si",
    "Solomon Islands": "sb",
    "Somalia": "so",
    "Somaliland": "so",
    "South Africa": "za",
    "South Georgia and the South Sandwich Islands": "gs",
    "South Korea": "kr",
    "South Sudan": "ss",
    "Spain": "es",
    "Sri Lanka": "lk",
    "Sudan": "sd",
    "Suriname": "sr",
    "Svalbard and Jan Mayen Islands": "sj",
    "Swaziland": "sz",
    "Sweden": "se",
    "Switzerland": "ch",
    "Syria": "sy",
    "Taiwan": "tw",
    "Tajikistan": "tj",
    "Tanzania": "tz",
    "Thailand": "th",
    "Togo": "tg",
    "Tokelau": "tk",
    "Tonga": "to",
    "Trinidad & Tobago": "tt",
    "Tunisia": "tn",
    "Turkey": "tr",
    "Turkmenistan": "tm",
    "Turks and Caicos Islands": "tc",
    "Tuvalu": "tv",
    "Uganda": "ug",
    "Ukraine": "ua",
    "United Arab Emirates": "ae",
    "United Kingdom": "uk",
    "United States of America": "us",
    "United States Virgin Islands": "vi",
    "Uruguay": "uy",
    "Uzbekistan": "uz",
    "Vanuatu": "vu",
    "Vatican City": "va",
    "Venezuela": "ve",
    "Vietnam": "vn",
    "Wallis and Futuna": "wf",
    "Western Sahara": "eh",
    "Yemen": "ye",
    "Zambia": "zm",
    "Zimbabwe": "zw"
  }
  for i, j in countries.items():
    log(f'{i} ({j})', 'verbose')

  #url = 'https://www.listofcountriesoftheworld.com/'
  #try:
  #  res = requests.get(url, verify=False, timeout=3, headers={'User-Agent': UA})
  #  soup = bs4.BeautifulSoup(res.text, 'html.parser')
  #  log('available countries: ', 'info', suf='\n\n')
  #  for i in soup.find_all('div', {'id': 'ctry'}):
  #    log(i.text.strip(), 'verbose')
  #except Exception as err:
  #  log(err.args[0].lower(), 'error')

  return


def host_range(country, sess):
  url = f'http://services.ce3c.be/ciprg/?countrys={country}'

  try:
    res = sess.get(url, verify=False, timeout=3)
    if len(res.content) == 0:
      os.remove(f'{country}-host.txt')
      os.remove(f'{country}-cidr.txt')
      log('wrong country name', 'error')
    for r in [x.split(':') for x in res.text.split()]:
      yield (r[1])
  except Exception as err:
    log(err.args[0].lower(), 'error')

  return


def check_argv(opts):
  needed = ['-c', '-l', '-V', '-H']

  if set(needed).isdisjoint(set(sys.argv)):
    log('use -H for help', 'error')

  return


def parse_cmdline():
  global opts
  try:
    _opts, args = getopt.getopt(sys.argv[1:], 'c:t:f:lVH')
    for o, a in _opts:
      if o == '-c':
        opts['country'] = a
      if o == '-t':
        opts['type'] = a.split(',')
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


def main():
  log(f'{BANNER}\n\n')
  check_argc()
  parse_cmdline()
  check_argv(opts)

  s = requests.Session()
  if 'host' in opts['type']:
    log(f"fetching ipv4 host-ranges for {opts['country']}", 'info')
    with open(f"{opts['country']}-host.txt", '+a') as f:
      for i, x in enumerate(host_range(opts['country'], s)):
        log(x, _type='file', logfile=f)
  if 'cidr' in opts['type']:
    log(f"fetching ipv4 cidr-ranges for {opts['country']}", 'info')
    with open(f"{opts['country']}-cidr.txt", '+a') as f:
      for i, x in enumerate(host_range(opts['country'], s)):
        splitted = x.split('-')
        startip = ipaddress.IPv4Address(splitted[0])
        endip = ipaddress.IPv4Address(splitted[1])
        for addr in ipaddress.summarize_address_range(startip, endip):
          log(addr, _type='file', logfile=f)
  log(f'found {i} ranges for {opts["country"]}', 'good')
  if 'cidr' in opts['type'] and 'host' in opts['type']:
    log(f"saved results to: {opts['country']}-*.txt", 'good')
  else:
    log(f"saved results to: {opts['country']}-{opts['type'][0]}.txt", 'good')
  log('game over', 'info')

  return


if __name__ == '__main__':
  warnings.simplefilter('ignore')
  main()


# EOF
