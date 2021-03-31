import dpkt
import socket
import ast
import statistics
from statistics import mode

f = open('tcudumpTeste.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

adsServers = []         ## LISTA CONTENDO TODOS OS DOMINIOS COM ADS
domainFound = []        ## LISTA CONTENDO TODAS AS REQUISICOES DNS COM SEUS DOMINIOS
dnsIPFound = []         ## DELETAR
novaLista = []          ## LISTA CONTENDO A JUNÇÃO DE DOMINIOS COM ADS E DOMINIOS ACESSADOS
listIpADs = []

dictionaryAds = {}

with open ('finalList.txt', 'r') as filehandle:
    adsServers = filehandle.read().split('\n')

for ts, buf in pcap:
    # CHECA SE ESTÁ LENDO TRAFEGO IP
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except:
        continue
    if eth.type != 2048:
        continue
    # UDP CHECK
    try:
        ip = eth.data
    except:
        continue
    if ip.p != 17:
        continue
    # FILTRA OS PACOTES REFERENTES A PORTA DO DNS
    try:
        udp = ip.data
    except:
        continue
    if udp.sport != 53 and udp.dport != 53:
        continue
    try:
        dns = dpkt.dns.DNS(udp.data)
    except:
        continue
    if dns.qr != dpkt.dns.DNS_R:
        continue
    if dns.opcode != dpkt.dns.DNS_QUERY:
        continue
    if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
        continue
    if len(dns.an) < 1:
        continue

    for qname in dns.qd:
        # SALVA OS DOMINIOS
        for answer in dns.an:
            if answer.type == 1 and socket.inet_ntoa(answer.rdata) not in dnsIPFound and qname.name in adsServers: ### INCLUIR APENAS DOMINIOS QUE SAO ADS
                # SALVA OS IPS
                if (qname.name in dictionaryAds):
                    dictionaryAds[qname.name].append(socket.inet_ntoa(answer.rdata))
                else:
                    dictionaryAds[qname.name] = [socket.inet_ntoa(answer.rdata)]
                print(" DOMINIO " + qname.name)
                domainFound.append(qname.name)
                dnsIPFound.append(socket.inet_ntoa(answer.rdata))
                print(socket.inet_ntoa(answer.rdata))

print(dictionaryAds)



### PEGAR IP DAS RESOLUCOES DNS - DONE
### PEGAR DOMINIO DAS RESOLUCOES DNS - DONE
### LER LISTA DE ADS - DONE
### IDENTIFICAR QUAIS DOMINIOS SÃO ADS - DONE
### ENCONTRA O DOMINIO E BUSCA O IP - DONE
### SOMAR TODOS OS PACOTES RECEBIDOS - ...
### SOMAR SOMENTE OS PACOTES DE ADS
### PLOTAR
### REALIZAR BUSCA NO ARQUIVO E SALVAR OS PACOTES PARA OS DETERMINADOS DOMINIOS - ...
### SOMAR TAMANHO DOS PACOTES E SALVA-LOS NUMA VARIAVEL INCREMENTAVEL - ... (IP.LEN)

