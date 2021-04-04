import dpkt
import socket

f = open('tcudumpTeste.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

adsServers = []         ## LISTA CONTENDO TODOS OS DOMINIOS COM ADS
domainFound = []        ## LISTA CONTENDO TODAS AS REQUISICOES DNS COM SEUS DOMINIOS
dnsIPFound = []         ## DELETAR


dictionaryAds = {}

with open ('finalList.txt', 'r') as filehandle:
    adsServers = filehandle.read().split('\n')


    def inet_to_str(inet):
        """Convert inet object to a string

            Args:
                inet (inet struct): inet network address
            Returns:
                str: Printable/readable IP address
        """
        # First try ipv4 and then ipv6
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)


    def print_http_requests():

        sizelen = 0
        qtd = 0

        for timestamp, buf in pcap:

            eth = dpkt.ethernet.Ethernet(buf)

            if not isinstance(eth.data, dpkt.ip.IP):
                print
                'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
                continue

            ip = eth.data

            do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
            more_fragments = bool(ip.off & dpkt.ip.IP_MF)
            fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

            if inet_to_str(ip.src) == "192.168.1.7" and isinstance(ip.data, dpkt.tcp.TCP):
                # Print out the info
                print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
                      (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments,
                       fragment_offset))
                sizelen = sizelen + ip.len
                print(sizelen)
                qtd = qtd + 1
                print(qtd)


    def loadData ():
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
                        print(" DOMINIO " + qname.name)             ## APAGAR
                        domainFound.append(qname.name)
                        dnsIPFound.append(socket.inet_ntoa(answer.rdata))
                        print(socket.inet_ntoa(answer.rdata))

        print(dictionaryAds)

#loadData()
print_http_requests()



### PEGAR IP DAS RESOLUCOES DNS - DONE
### PEGAR DOMINIO DAS RESOLUCOES DNS - DONE
### LER LISTA DE ADS - DONE
### IDENTIFICAR QUAIS DOMINIOS SÃO ADS - DONE
### ENCONTRA O DOMINIO E BUSCA O IP - DONE
### SOMAR TODOS OS PACOTES RECEBIDOS - DONE
### SOMAR SOMENTE OS PACOTES DE ADS - ...
### PLOTAR - ...
### REALIZAR BUSCA NO ARQUIVO E SALVAR OS PACOTES PARA OS DETERMINADOS DOMINIOS - DONE
### SOMAR TAMANHO DOS PACOTES E SALVA-LOS NUMA VARIAVEL INCREMENTAVEL - ... (IP.LEN)

