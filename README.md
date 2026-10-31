# Cyber301-Automation-Project

**Contact and Indicator Extractor**: a Python script that scans text for phone numbers, email addresses, URLs, and IPv4 addresses.

## Project Selected

This project is based on the **Phone Number and Email Address Extractor** from the regular expressions chapter of *Automate the Boring Stuff with Python* by Al Sweigart.

In the book, the script reads text from the clipboard, uses regular expressions to find phone numbers and email addresses, and copies the matches back to the clipboard. The example scenario is going through a long web page or document and pulling out contact information by hand, which the script does in a second.

I picked it because pattern matching in text is something security analysts do all the time. When you review a phishing email or a firewall log, you need to pull out the URLs, IP addresses, and email addresses involved. So I kept the book's project as the base and extended it toward that use.

## What the Script Does

`extractor.py` reads a text file (or the clipboard) and finds:

| Type | Example match |
|------|---------------|
| Phone numbers | `(610) 555-0142`, `610.555.0199 ext 204`, `555-0123` |
| Email addresses | `support-team@example.org` |
| URLs | `http://login-verify.example.net/secure/update.php?id=88231` |
| IPv4 addresses | `203.0.113.45` |

It then:

1. Converts phone numbers to one standard format (`610-555-0199 x204`).
2. Removes duplicates while keeping the order they first appeared.
3. Checks that each IP address is real (every part between 0 and 255) and reports the ones it rejected.
4. Prints a grouped report to the screen.
5. Saves everything to a CSV file with `type` and `value` columns.
6. Optionally "defangs" URLs and IPs (`hxxp://bad[.]example[.]com`) so they can't be clicked by accident when pasted into a report.
7. Optionally copies the results to the clipboard, like the original project.

## How to Run It

**Requirements:** Python 3.8 or newer. The script only uses the standard library. The clipboard options need `pyperclip`:

```bash
pip install pyperclip
```

**Clone the repository:**

```bash
git clone https://github.com/rayhanahmedshium/Cyber301-Automation-Project.git
cd Cyber301-Automation-Project
```

**Run it on the included sample file:**

```bash
python extractor.py sample_input.txt
```

**Other options:**

```bash
# Choose the CSV output file name
python extractor.py sample_input.txt -o my_results.csv

# Defang URLs and IP addresses in the output
python extractor.py sample_input.txt --defang

# Read from the clipboard and copy the results back (original book behavior)
python extractor.py --clipboard --copy

# Show all options
python extractor.py --help
```

On macOS or Linux you may need to type `python3` instead of `python`.

## Sample Input and Output

`sample_input.txt` is a made-up help desk email with a forwarded phishing message and a short firewall log. All addresses and numbers in it are reserved example values (`example.com` domains, documentation IP ranges, 555 phone numbers).

Running `python extractor.py sample_input.txt` prints:

```
==================================================
  Extraction Report
==================================================

PHONE (4 found)
  - 610-555-0142
  - 610-555-0199 x204
  - 484-555-0177
  - 555-0123

EMAIL (4 found)
  - helpdesk@example.edu
  - account.security@example.net
  - support-team@example.org
  - security@example.edu

URL (3 found)
  - http://login-verify.example.net/secure/update.php?id=88231
  - https://example.com/reset
  - https://cdn.example.org/assets/logo.png

IPV4 (3 found)
  - 203.0.113.45
  - 10.0.4.12
  - 198.51.100.7

Ignored 1 invalid IP-like value(s): 999.20.1.300

Total unique items: 14
Results saved to results.csv
```

The same results are saved in `sample_output.csv`.

With `--defang`, the URLs and IPs look like this:

```
  - hxxp://login-verify[.]example[.]net/secure/update[.]php?id=88231
  - 203[.]0[.]113[.]45
```

## Challenges I Encountered

- **Phone numbers inside other numbers.** Because the area code is optional, the book's pattern can match part of a longer number, such as a 10+ digit ID or timestamp. I added lookarounds (`(?<!\d)` and `(?!\d)`) so a match can't start or end in the middle of a run of digits.
- **Punctuation stuck to URLs.** A URL at the end of a sentence was picked up with the period attached (`...id=88231.`). I strip trailing punctuation like `.`, `,`, and `;` after matching.
- **Fake IP addresses.** A regex like `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` also matches `999.20.1.300`, which isn't a valid address. Writing a regex that checks 0–255 is long and hard to read, so I let the regex find candidates and used Python's `ipaddress` module to validate them.
- **Duplicate emails in different case.** `Account.Security@Example.net` and `account.security@example.net` are the same address. I lowercase emails before removing duplicates.
- **Long top-level domains.** The book's email pattern allows only 2–4 letters after the last dot, which misses domains like `.online` or `.technology`. I changed it to 2 or more.
- **Clipboard support isn't available everywhere.** `pyperclip` fails on systems without a clipboard (like a remote server). I made file input the default and made the script print a clear message instead of crashing if `pyperclip` is missing.

## Improvements and Modifications

Compared to the original project in the book:

- Added **URL** and **IPv4 address** extraction.
- Added **IP validation** with the `ipaddress` module.
- Added **file input** as the default, with the clipboard as an option (`--clipboard`).
- Added **command-line arguments** with `argparse` (`-o`, `--defang`, `--copy`, `--help`).
- Added **duplicate removal** that keeps the original order.
- **Normalized phone numbers**, including extensions, to one format.
- Added **CSV export** so results can be opened in Excel or used by other tools.
- Added a **defang** option, a common practice when sharing indicators in security reports.
- Added **error handling** for missing files, an empty clipboard, and a missing `pyperclip` module.
- Split the code into small functions with comments explaining each section.

## Files

| File | Description |
|------|-------------|
| `extractor.py` | The main script |
| `sample_input.txt` | Sample text to test the script |
| `sample_output.csv` | Output from running the script on the sample |
| `README.md` | This file |

## Reference

Sweigart, A. *Automate the Boring Stuff with Python*. https://automatetheboringstuff.com/

## Author

Rayhan Ahmed Shium, CYBER 301, Immaculata University
