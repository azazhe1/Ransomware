# Ransomware
> [!WARNING]
> EDUCATIONAL PURPOSES ONLY
>
>This project is intended solely for educational and research purposes in the context of cybersecurity training. It is designed to study and understand ransomware mechanics in a legal and controlled environment.
>
>DO NOT use this code for malicious purposes. Deploying ransomware on any system without explicit permission is illegal and can result in severe legal consequences.
>
>By using this project, you agree to abide by all applicable laws and take full responsibility for your actions. The author assumes no liability for any misuse.

## Generating RSA Keys
Before anything else, we need to generate our RSA key pair.

Run the following commands to create your private and public keys:
```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048  
openssl rsa -pubout -in private.pem -out public.pem  
```
