# ThreatFox IOC IPs by Abuse.ch

![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
![AIOHTTP](https://img.shields.io/badge/AIOHTTP-2C5BB4?style=for-the-badge&logo=aiohttp&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)

[![GitHub license](https://img.shields.io/badge/LICENSE-BSD--3--CLAUSE-GREEN?style=for-the-badge)](LICENSE)
[![update](https://img.shields.io/github/actions/workflow/status/elliotwutingfeng/ThreatFox-IOC-IPs/update.yml?branch=main&label=UPDATE&style=for-the-badge)](https://github.com/elliotwutingfeng/ThreatFox-IOC-IPs/actions/workflows/update.yml)
<img src="https://tokei-rs.onrender.com/b1/github/elliotwutingfeng/ThreatFox-IOC-IPs?label=Total%20Blocklist%20IPs&style=for-the-badge" alt="Total Blocklist IPs"/>

Machine-readable `.txt` IP blocklist from [ThreatFox](https://threatfox.abuse.ch) by [Abuse.ch](https://abuse.ch), updated every hour.

The IPs in this blocklist are compiled by **Abuse.ch** under the [Creative Commons Zero v1.0 Universal](https://threatfox.abuse.ch/faq) license.

**Disclaimer:** _This project is not sponsored, endorsed, or otherwise affiliated with Abuse.ch._

## Blocklist download

| File | Download |
|:-:|:-:|
| ips.txt | [:floppy_disk:](ips.txt?raw=true) |

## Requirements

- Python 3.11+

## Setup instructions

`git clone` and `cd` into the project directory, then run the following

```bash
python3 -m venv venv
venv/bin/python3 -m pip install --upgrade pip
venv/bin/python3 -m pip install -r requirements.txt
```

## Usage

```bash
venv/bin/python3 update.py
```

&nbsp;

<sup>These files are provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, arising from, out of or in connection with the files or the use of the files.</sup>

<sub>Any and all trademarks are the property of their respective owners.</sub>
