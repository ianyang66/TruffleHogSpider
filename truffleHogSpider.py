import sys
from argparse import ArgumentParser
from bs4 import BeautifulSoup
from colorama import Fore, init, Style
import tldextract
import jsbeautifier
import math
import re
import requests
from truffleHogRegexes.regexChecks import regexes

init(autoreset=True)
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"
BASE64_ENTROPY_THRESHOLD = 4.5
HEX_ENTROPY_THRESHOLD = 3


def read_pattern(r):
    if r.startswith("regex:"):
        return re.compile(r[6:])
    converted = re.escape(r)
    converted = re.sub(r"((\\*\r)?\\*\n|(\\+r)?\\+n)+", r"( |\\t|(\\r|\\n|\\\\+[rn])[-+]?)*", converted)
    return re.compile(converted)


def shannon_entropy(data, iterator):
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

# Use generators
def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    strings = []
    letters = ""
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings



def find_entropy(data: str):
    """
    Find high entropy strings in the data.

    Parameters:
    data (str): The data to search for high entropy strings.

    Returns:
    list: A list of high entropy strings.
    """
    secrets = []
    for line in data.splitlines():
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64_entropy = shannon_entropy(string, BASE64_CHARS)
                if b64_entropy > BASE64_ENTROPY_THRESHOLD:
                    secrets.append(string)
            for string in hex_strings:
                hex_entropy = shannon_entropy(string, HEX_CHARS)
                if hex_entropy > HEX_ENTROPY_THRESHOLD:
                    secrets.append(string)
    return secrets


def regex_check(data: str, custom_regexes: dict) -> list:
    regex_matches = []
    for regex in custom_regexes.values():
        regex_matches += regex.findall(data)
    return regex_matches


def get_secrets(data: str, custom_regexes: dict, do_entropy=True, do_regex=True) -> tuple:
    entropy = []
    regex = []
    if do_entropy:
        entropy += find_entropy(data)
    if do_regex:
        regex += regex_check(data, custom_regexes)
    return list(set(entropy)), list(set(regex))


def spiderlinks(target: str) -> list:
    result = tldextract.extract(target)
    basedomain = f'{result.domain}.{result.suffix}'
    tld = result.suffix
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0"}
    res = requests.get(target, headers=headers, verify=False)
    linklist = set()
    if res.status_code == 200:
        soup = BeautifulSoup(res.text, 'html.parser')
        for link in soup.find_all('a'):
            if link.has_attr('href'):
                link['href'] = link['href'].split('#')[0]
                link['href'] = link['href'].split('?')[0]
                if link['href'].startswith('/'):
                    linklist.add(target + link['href'])
                elif link['href'].startswith('http'):
                    newresult = tldextract.extract(link['href'])
                    newsub, newdom, newtld = newresult.subdomain, newresult.domain, newresult.suffix
                    if f'{newdom}.{tld}' == basedomain:
                        linklist.add(link['href'])
                else:
                    linklist.add(target + '/' + link['href'])
    return list(linklist)

# Avoid repeated computations
def extract_secrets(interestingscript):
    js = requests.get(interestingscript, headers=headers, verify=False).text
    beautiful = jsbeautifier.beautify(js)
    entropy_results, regex_results = get_secrets(beautiful, regexes, do_entropy=args.no_entropy, do_regex=args.no_regex)
    duplist = set()
    for regex_result in regex_results:
        splat = beautiful.split('\n')
        for k, v in enumerate(splat):
            if regex_result in v and k not in duplist:
                print(f'{Style.BRIGHT}[+] regex match found, row {k + 1} on {interestingscript}:')
                print(Fore.LIGHTYELLOW_EX + splat[k - 1])
                print(Fore.LIGHTYELLOW_EX + splat[k])
                print(Fore.LIGHTYELLOW_EX + splat[k + 1])
                duplist.update({k - 1, k, k + 1})
    for entropy_result in entropy_results:
        splat = beautiful.split('\n')
        for k, v in enumerate(splat):
            if entropy_result in v and 'data:image' not in v and k not in duplist:
                print(f'{Style.BRIGHT}[+] high entropy found, row {k + 1} on {interestingscript}:')
                print(Fore.LIGHTCYAN_EX + splat[k - 1])
                print(Fore.LIGHTCYAN_EX + splat[k])
                print(Fore.LIGHTCYAN_EX + splat[k + 1])
                duplist.update({k - 1, k, k + 1})
    if entropy_results or regex_results:
        newfilename = f'latruffe_{interestingscript.split("?")[0].replace("://", "_").replace(":", "_").replace("/", "_")}'
        print(f'[*] file saved as: {newfilename}\n{"-" * 40}')
        with open(newfilename, 'w') as f:
            f.write(f'Interesting lines:\n{duplist}\n')
            f.write(beautiful)
    else:
        if not args.no_entropy:
            print(f'{Fore.LIGHTRED_EX}[-] no high entropy strings found in script {interestingscript}')
        elif not args.no_regex:
            print(f'{Fore.LIGHTRED_EX}[-] no regex matches found in script {interestingscript}')
        else:
            print(f'{Fore.LIGHTRED_EX}[-] no regex or high entropy found in script {interestingscript}')


if __name__ == '__main__':
    parser = ArgumentParser(description='Spider a target website, find its .JS files and search for secrets there')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('url', type=str, nargs='?', help='the url to scan')
    source.add_argument('-s', type=str, nargs='?', help='a direct link to .js file to test. no spidering.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--no-entropy', action='store_false', default=True, help='do not search secrets by entropy')
    group.add_argument('--no-regex', action='store_false', default=True, help='do not search secrets by regex')
    parser.add_argument('--no-limit', action='store_true', default=False, help='do not limit searching js files to the same domain')
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    if args.s:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0"}
        res = requests.get(args.s, headers=headers, verify=False)
        if res.status_code == 200:
            print(f'{Fore.LIGHTBLUE_EX}[*]{Fore.RESET} now searching secrets on: {Fore.LIGHTMAGENTA_EX + args.s + Fore.RESET}')
            extract_secrets(args.s)
    elif args.url:
        site = args.url
        if site.endswith('/'):
            site = site[:-1]
        result = tldextract.extract(site)
        basedomain = f'{result.domain}.{result.suffix}'
        print(f'{Fore.LIGHTBLUE_EX}[*]{Fore.RESET} now running on: {Fore.LIGHTMAGENTA_EX + site + Fore.RESET}, scope is anything with {Fore.LIGHTMAGENTA_EX + result.domain}')
        runlist = []
        scriptlist = set()
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0"}
        res = requests.get(site, headers=headers, verify=False)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, 'html.parser')
            for script in soup.find_all('script'):
                if script.attrs.get('src'):
                    url = script.attrs.get('src')
                    if url.startswith('/'):
                        scriptlist.add(site + url)
                    elif url.startswith('http'):
                        scriptlist.add(url)
                    else:
                        scriptlist.add(site + '/' + url)
            if scriptlist:
                nlt = '\n\t'
                print(f'{Fore.LIGHTGREEN_EX}[+]{Fore.RESET} scripts found:\n\t{nlt.join(scriptlist)}\n{Fore.LIGHTGREEN_EX}[+]{Fore.RESET} now crunching, hold on.')
                for interestingscript in scriptlist:
                    if result.domain in interestingscript or args.no_limit:
                        extract_secrets(interestingscript)
            else:
                print(f'{Fore.LIGHTRED_EX}[-] no scripts found')
        else:
            print(f'{Fore.LIGHTRED_EX}[-] Error\n{res.status_code}\n{res.headers}')
    print('\n' + Fore.LIGHTBLUE_EX + 'OK. Not Found.\n')