# netscaler-certbot-hook

This is a small script for installing and updating ssl certificates (e.g. from Letsencrypt) on a Citrix NetScaler.

Use it in combination with the DNS-01 challenge to fully automate the renewal process for your Letsencrypt certificates on your Citrix NetScaler ADC.

## Features

- **Command-line Arguments**: Configure NetScaler connection via CLI arguments or environment variables
- **Development Mode**: Use `--dev-mode` for local testing with custom certificate directories
- **Auto-update Chain Certificates**: Automatically detects and updates chain certificates when serial numbers differ
- **Backward Compatible**: Still supports environment variables for legacy configurations

## Architecture

![Architecture](architecture.png)

## Installation

Install required Python dependencies:

```bash
pip3 install -r requirements.txt
```

Or install manually:

```bash
pip3 install pyOpenSSL requests 'urllib3<2.0'
```

## Usage

```
usage: netscaler-certbot-hook.py [-h] --name <string> [--chain <string>]
                                 [--cert <file>] [--privkey <file>]
                                 [--chain-cert <file>] [--ns-url <url>]
                                 [--ns-login <string>]
                                 [--ns-password <string>]
                                 [--ns-verify-ssl <yes|no>] [--dev-mode]
                                 [--cert-dir <directory>]

optional arguments:
  -h, --help            show this help message and exit
  --name <string>       object name of the ssl certificate
  --chain <string>      object name of the ssl chain certificate
  --cert <file>         path to the ssl certificate (default:
                        /etc/letsencrypt/live/name/cert.pem)
  --privkey <file>      path to the ssl private key (default:
                        /etc/letsencrypt/live/name/privkey.pem)
  --chain-cert <file>   path to the ssl chain certificate (default:
                        /etc/letsencrypt/live/name/chain.pem)
  --ns-url <url>        NetScaler URL (e.g., https://netscaler.example.com)
  --ns-login <string>   NetScaler login username (default: nsroot)
  --ns-password <string>
                        NetScaler login password (default: nsroot)
  --ns-verify-ssl <yes|no>
                        Verify NetScaler SSL certificate (default: no)
  --dev-mode            Enable development mode (uses ../cert as default cert-
                        dir)
  --cert-dir <directory>
                        Base directory for certificates (default:
                        /etc/letsencrypt/live in production, ../cert in dev
                        mode)
```

## Enroll an letsencrypt certificate via certbot

For example using Cloudflare DNS.
```
certbot --text --agree-tos --non-interactive certonly \
  --cert-name 'lauger.de' \
  -d 'lauger.de' \
  -d 'www.lauger.de' \
  -a dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --keep-until-expiring
```

## Run netscaler-certbot-hook

### Method 1: Using Command-line Arguments (Recommended)

```bash
python3 netscaler-certbot-hook.py \
  --name lauger.de \
  --ns-url https://192.168.10.10 \
  --ns-login nsroot \
  --ns-password nsroot
```

### Method 2: Using Environment Variables (Legacy)

Set the required environment variables:

```bash
export NS_URL=https://192.168.10.10
export NS_LOGIN=nsroot
export NS_PASSWORD=nsroot
```

Run script and push certificate to your NetScaler:

```bash
python3 netscaler-certbot-hook.py --name lauger.de
```

### Method 3: Development Mode

For local testing with custom certificate directory:

```bash
python3 netscaler-certbot-hook.py \
  --name example.com \
  --dev-mode \
  --ns-url https://192.168.10.10 \
  --ns-login nsroot \
  --ns-password nsroot
```

This will use certificates from `../cert/example.com/` directory.

### Custom Certificate Paths

By default, the script assumes your certificate in `/etc/letsencrypt/live`. If your certificate is stored somewhere else, use `--cert-dir` or specify individual paths:

```bash
# Using --cert-dir
python3 netscaler-certbot-hook.py \
  --name lauger.de \
  --cert-dir /custom/path \
  --ns-url https://192.168.10.10

# Or specify individual paths
python3 netscaler-certbot-hook.py \
  --name lauger.de \
  --cert /custom/path/cert.pem \
  --privkey /custom/path/privkey.pem \
  --chain-cert /custom/path/chain.pem \
  --ns-url https://192.168.10.10
```

## Example Output

### Initial Setup

```
$ python3 netscaler-certbot-hook.py --name lauger.de --ns-url https://192.168.10.10
chain certificate letsencrypt not found
uploading chain certificate as letsencrypt-1581896753.crt
installing chain certificate with serial 13298795840390663119752826058995181320
certificate lauger.de not found
uploading certificate as lauger.de-1581896753.crt
uploading private key as lauger.de-1581896753.key
installing certificate with serial 409596789458967997345847308430335698529007
link certificate lauger.de to chain certificate letsencrypt
saving configuration
```

### Update Check (No Changes)

```
$ python3 netscaler-certbot-hook.py --name lauger.de --ns-url https://192.168.10.10
chain certificate letsencrypt found with serial 13298795840390663119752826058995181320
installed chain certificate matches our serial - nothing to do
certificate lauger.de found with serial 409596789458967997345847308430335698529007
installed certificate matches our serial - nothing to do
```

### Update Chain Certificate (Auto-detected)

```
$ python3 netscaler-certbot-hook.py --name lauger.de --ns-url https://192.168.10.10
chain certificate letsencrypt found with serial 234397126118090224789023519560838753080
installed chain certificate serial 234397126118090224789023519560838753080 does not match our serial 226581164312556911225609404641709439649
uploading new chain certificate as letsencrypt-1762616314.crt
updating chain certificate with serial 226581164312556911225609404641709439649
certificate lauger.de found with serial 409596789458967997345847308430335698529007
installed certificate matches our serial - nothing to do
```

## Authors

- [slauger](https://github.com/slauger)
