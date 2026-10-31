#!/usr/bin/env python3
"""
extractor.py - Contact and Indicator Extractor

Based on the "Phone Number and Email Address Extractor" project from
Automate the Boring Stuff with Python by Al Sweigart (regular expressions chapter).

The original project reads text from the clipboard, finds phone numbers and
email addresses with regular expressions, and copies the matches back to the
clipboard. This version keeps that idea and adds:
    - URL and IPv4 address extraction (useful for pulling indicators out of
      logs or suspicious emails during security work)
    - Reading input from a text file, with the clipboard as an option
    - Duplicate removal while keeping the original order
    - IP address validation (rejects things like 999.10.10.10)
    - An optional "defang" mode so URLs and IPs are safe to paste into reports
    - A CSV report of everything that was found

Usage examples:
    python extractor.py sample_input.txt
    python extractor.py sample_input.txt -o results.csv --defang
    python extractor.py --clipboard --copy
"""

import argparse
import csv
import ipaddress
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

# Phone numbers. This follows the pattern from the book: an optional area code
# (with or without parentheses), a separator, 3 digits, a separator, 4 digits,
# and an optional extension. The (?<!\d) and (?!\d) lookarounds stop the
# pattern from matching a piece of a longer number such as an account ID.
PHONE_REGEX = re.compile(r'''(
    (?<!\d)
    (\d{3}|\(\d{3}\))?              # group 1: area code (optional)
    (\s|-|\.)?                      # group 2: separator
    (\d{3})                         # group 3: first 3 digits
    (\s|-|\.)                       # group 4: separator
    (\d{4})                         # group 5: last 4 digits
    (?!\d)
    (\s*(ext|x|ext\.)\s*(\d{2,5}))? # groups 6-8: extension (optional)
)''', re.VERBOSE | re.IGNORECASE)

# Email addresses: username @ domain . top-level domain.
# The book limits the TLD to 2-4 letters; this allows longer ones like .online.
EMAIL_REGEX = re.compile(r'''(
    [a-zA-Z0-9._%+-]+       # username
    @
    [a-zA-Z0-9.-]+          # domain name
    \.[a-zA-Z]{2,}          # top-level domain
)''', re.VERBOSE)

# URLs that start with http:// or https:// and run until whitespace or a
# character that usually ends a URL in normal text.
URL_REGEX = re.compile(r'https?://[^\s<>"\'()]+', re.IGNORECASE)

# IPv4 addresses: four groups of 1-3 digits separated by dots.
# The regex only checks the shape; validate_ipv4() checks the actual values.
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def unique(items):
    """Remove duplicates but keep the order in which items first appeared."""
    return list(dict.fromkeys(items))


def extract_phones(text):
    """Find phone numbers and rewrite them in one standard format (555-555-5555 x99)."""
    phones = []
    for groups in PHONE_REGEX.findall(text):
        area_code = groups[1].strip('()')
        parts = [p for p in (area_code, groups[3], groups[5]) if p]
        number = '-'.join(parts)
        if groups[8]:                      # an extension was found
            number += ' x' + groups[8]
        phones.append(number)
    return unique(phones)


def extract_emails(text):
    """Find email addresses. Lowercase them so duplicates in different case merge."""
    return unique(match.lower().rstrip('.') for match in EMAIL_REGEX.findall(text))


def extract_urls(text):
    """Find URLs and trim punctuation that belongs to the sentence, not the URL."""
    return unique(match.rstrip('.,;:!?') for match in URL_REGEX.findall(text))


def validate_ipv4(candidate):
    """Return True if the string is a real IPv4 address (each part 0-255)."""
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ipaddress.AddressValueError:
        return False


def extract_ips(text):
    """Find IPv4 addresses. Returns (valid_ips, rejected_candidates)."""
    candidates = unique(IPV4_REGEX.findall(text))
    valid = [ip for ip in candidates if validate_ipv4(ip)]
    rejected = [ip for ip in candidates if not validate_ipv4(ip)]
    return valid, rejected


def defang(value):
    """
    Make a URL or IP non-clickable, the way security analysts write them in reports.
    Example: http://bad.example.com -> hxxp://bad[.]example[.]com
    """
    return value.replace('http', 'hxxp').replace('.', '[.]')


def read_input(args):
    """Get the text to scan, either from a file or from the clipboard."""
    if args.clipboard:
        try:
            import pyperclip
        except ImportError:
            sys.exit('Error: --clipboard needs the pyperclip module. '
                     'Install it with: pip install pyperclip')
        text = pyperclip.paste()
        if not text:
            sys.exit('Error: the clipboard is empty.')
        return text

    path = Path(args.input_file)
    if not path.is_file():
        sys.exit(f'Error: file not found: {path}')
    # errors='replace' keeps the script from crashing on odd characters in logs
    return path.read_text(encoding='utf-8', errors='replace')


def write_csv(results, output_path):
    """Save every match to a CSV file with two columns: type and value."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['type', 'value'])
        for kind, values in results.items():
            for value in values:
                writer.writerow([kind, value])


def print_report(results, rejected_ips):
    """Print the results to the screen, grouped by type."""
    total = sum(len(v) for v in results.values())
    print('=' * 50)
    print('  Extraction Report')
    print('=' * 50)
    for kind, values in results.items():
        print(f'\n{kind.upper()} ({len(values)} found)')
        if values:
            for value in values:
                print(f'  - {value}')
        else:
            print('  (none)')
    if rejected_ips:
        print(f'\nIgnored {len(rejected_ips)} invalid IP-like value(s): '
              + ', '.join(rejected_ips))
    print(f'\nTotal unique items: {total}')


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------

def main():
    # Set up command-line options
    parser = argparse.ArgumentParser(
        description='Extract phone numbers, emails, URLs, and IPv4 addresses from text.')
    parser.add_argument('input_file', nargs='?',
                        help='text file to scan (not needed with --clipboard)')
    parser.add_argument('--clipboard', action='store_true',
                        help='read text from the clipboard instead of a file')
    parser.add_argument('-o', '--output', default='results.csv',
                        help='CSV file to save results to (default: results.csv)')
    parser.add_argument('--defang', action='store_true',
                        help='defang URLs and IPs in the output (hxxp, [.])')
    parser.add_argument('--copy', action='store_true',
                        help='copy the results to the clipboard, like the original project')
    args = parser.parse_args()

    if not args.clipboard and not args.input_file:
        parser.error('give an input file or use --clipboard')

    # Step 1: read the text
    text = read_input(args)

    # Step 2: run each extractor
    valid_ips, rejected_ips = extract_ips(text)
    results = {
        'phone': extract_phones(text),
        'email': extract_emails(text),
        'url': extract_urls(text),
        'ipv4': valid_ips,
    }

    # Step 3: optionally defang URLs and IPs so they can't be clicked by accident
    if args.defang:
        results['url'] = [defang(u) for u in results['url']]
        results['ipv4'] = [defang(ip) for ip in results['ipv4']]

    # Step 4: show the results and save them
    print_report(results, rejected_ips)
    write_csv(results, args.output)
    print(f'Results saved to {args.output}')

    # Step 5: optionally copy to the clipboard (the original book behavior)
    if args.copy:
        try:
            import pyperclip
            lines = [v for values in results.values() for v in values]
            pyperclip.copy('\n'.join(lines))
            print('Results copied to the clipboard.')
        except ImportError:
            print('Could not copy: pyperclip is not installed.')


if __name__ == '__main__':
    main()
