#!/usr/bin/env python3
"""
Subdomain Enumerator - Enumeración de subdominios
CREADOR: phishbroker
CONTACTO: https://x.com/phishbroker
"""

import dns.resolver
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

class SubdomainEnum:
    def __init__(self, domain, wordlist, threads=50, timeout=3):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = []
        
    def check_subdomain(self, subdomain):
        """
        Verifica si un subdominio existe
        """
        full_domain = f"{subdomain}.{self.domain}"
        try:
            # Intento con DNS
            answers = dns.resolver.resolve(full_domain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            # Intento verificar si el sitio está activo
            try:
                response = requests.get(f"http://{full_domain}", 
                                       timeout=self.timeout, 
                                       allow_redirects=True)
                status = response.status_code
            except:
                status = "N/A"
            
            result = {
                'subdomain': full_domain,
                'ips': ips,
                'status': status
            }
            
            print(f"[+] ENCONTRADO: {full_domain} -> {', '.join(ips)} [HTTP: {status}]")
            return result
            
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.Timeout:
            return None
        except Exception as e:
            return None
    
    def enumerate(self):
        """
        Enumera subdominios usando el wordlist
        """
        print(f"\n[*] Enumerando subdominios de: {self.domain}")
        print(f"[*] Wordlist: {self.wordlist}")
        print(f"[*] Threads: {self.threads}\n")
        
        try:
            with open(self.wordlist, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Error: Wordlist no encontrado: {self.wordlist}")
            sys.exit(1)
        
        print(f"[*] Cargadas {len(subdomains)} palabras del diccionario")
        print(f"[*] Iniciando enumeración...\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub 
                      for sub in subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.found_subdomains.append(result)
        
        return self.found_subdomains
    
    def save_results(self, output_file):
        """
        Guarda los resultados en un archivo
        """
        with open(output_file, 'w') as f:
            f.write(f"# Subdomain Enumeration Results\n")
            f.write(f"# Domain: {self.domain}\n")
            f.write(f"# CREADOR: phishbroker\n")
            f.write(f"# CONTACTO: phishbroker@proton.me\n\n")
            
            for sub in self.found_subdomains:
                f.write(f"{sub['subdomain']},{','.join(sub['ips'])},{sub['status']}\n")
        
        print(f"\n[*] Resultados guardados en: {output_file}")

def create_default_wordlist():
    """
    Crea un wordlist básico si no se proporciona uno
    """
    common_subs = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
        'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 
        'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 
        'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old', 
        'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop',
        'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
        'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
        'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
        'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn',
        'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
        'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db',
        'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live',
        'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4'
    ]
    
    wordlist_file = 'subdomains.txt'
    with open(wordlist_file, 'w') as f:
        for sub in common_subs:
            f.write(f"{sub}\n")
    
    return wordlist_file

def main():
    parser = argparse.ArgumentParser(
        description='Subdomain Enumerator by phishbroker',
        epilog='Contacto: phishbroker@proton.me'
    )
    parser.add_argument('domain', help='Dominio objetivo (ej: example.com)')
    parser.add_argument('-w', '--wordlist', help='Archivo wordlist')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Número de threads (default: 50)')
    parser.add_argument('-o', '--output', help='Archivo de salida')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Timeout para conexiones HTTP (default: 3)')
    
    args = parser.parse_args()
    
    print("="*70)
    print("SUBDOMAIN ENUMERATOR")
    print(f"CREADOR: phishbroker")
    print(f"CONTACTO: phishbroker@proton.me")
    print("="*70)
    
    # Si no se proporciona wordlist, usar el default
    if not args.wordlist:
        print("[!] No se especificó wordlist, usando diccionario básico...")
        args.wordlist = create_default_wordlist()
    
    enumerator = SubdomainEnum(
        args.domain, 
        args.wordlist, 
        args.threads,
        args.timeout
    )
    
    results = enumerator.enumerate()
    
    print(f"\n{'='*70}")
    print(f"[*] Enumeración completada")
    print(f"[*] Subdominios encontrados: {len(results)}")
    print(f"{'='*70}")
    
    if args.output:
        enumerator.save_results(args.output)

if __name__ == "__main__":
    main()
