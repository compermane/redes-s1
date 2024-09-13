import ipaddress

from iputils import *
from tcputils import *


class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.tabela_encaminhamento = []

    def __raw_recv(self, datagrama): 
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            if ttl <= 1:
                print("TTL expirado. Datagram descartado.")
                checksum = calc_checksum(struct.pack(
                    '>BBHI', 
                    11, 
                    0, 
                    0, 
                    0) + datagrama[:28])
                self.enviar((struct.pack(
                    '>BBHI', 
                    11, 
                    0, 
                    0, 
                    checksum) + datagrama[:28]), src_addr, 1)
                return

            ttl -= 1

            ip_header = struct.pack(
                '!BBHHHBBHII',
                (4 << 4) | 5,                           # Versão e IHL
                0,                                      # DSCP e ECN
                len(datagrama),                         # Comprimento total
                identification,                         # Identificação
                flags << 13 | frag_offset,              # Flags e deslocamento do fragmento
                ttl,                                    # Novo TTL
                proto,                                  # Protocolo
                0,                                      # Checksum (será corrigido depois)
                int.from_bytes(str2addr(src_addr), "big"),     # Endereço IP de origem
                int.from_bytes(str2addr(dst_addr), "big")      # Endereço IP de destino
            )

            # Zera o campo de checksum no cabeçalho IP (bytes 10 e 11)
            ip_header = ip_header[:10] + b'\x00\x00' + ip_header[12:]
            checksum_corrigido = calc_checksum(ip_header)
            ip_header = ip_header[:10] + struct.pack('!H', checksum_corrigido) + ip_header[12:]

            datagrama = ip_header + payload

            next_hop = self._next_hop(dst_addr)
            
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        dest_ip = ipaddress.ip_address(dest_addr)
        
        best_match = None
        longest_prefix_length = -1

        for rede, next_hop in self.tabela_encaminhamento:
            if dest_ip in rede:
                # Verifica o comprimento do prefixo da rede
                prefix_length = rede.prefixlen
                if prefix_length > longest_prefix_length:
                    longest_prefix_length = prefix_length
                    best_match = next_hop

        return best_match

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela_encaminhamento = []
        for cidr, next_hop in tabela:
            rede = ipaddress.ip_network(cidr, strict=False)
            self.tabela_encaminhamento.append((rede, next_hop))

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, protocol = IPPROTO_TCP):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        version = 4
        ihl = 5  # O tamanho do cabeçalho IP em palavras de 32 bits
        dscp = 0
        ecn = 0
        ttl = 64  # Valor padrão para TTL
        protocolo = protocol  # Protocolo TCP
        src_addr = self.meu_endereco
        dst_addr = dest_addr
        
        # Calcula o comprimento total do datagrama
        total_len = 20 + len(segmento)  # 20 bytes para o cabeçalho IP + comprimento do segmento TCP

        print("Valores do Cabeçalho IP:")
        print(f"Versão: {version}")
        print(f"IHL: {ihl}")
        print(f"DSCP: {dscp}")
        print(f"ECN: {ecn}")
        print(f"TTL: {ttl}")
        print(f"Protocolo: {protocolo}")
        print(f"Comprimento Total: {total_len}")
        print(f"Endereço IP de Origem: {str2addr(src_addr)}")
        print(f"Endereço IP de Destino: {str2addr(dst_addr)}")
        # Monta o cabeçalho IP
        ip_header = struct.pack(
            '!BBHHHBBHII',                          # Formato do cabeçalho IP
            (version << 4) | ihl,                   # Versão e IHL
            (dscp << 2) | ecn,                      # DSCP e ECN
            total_len,                              # Comprimento total
            0,                                      # Identificação (0 para simplificação)
            0,                                      # Flags e deslocamento do fragmento
            ttl,                                    # TTL
            protocolo,                              # Protocolo
            0,                                      # Checksum (será calculado depois)
            int.from_bytes(str2addr(src_addr), "big"),     # Endereço IP de origem
            int.from_bytes(str2addr(dst_addr), "big")      # Endereço IP de destino
        )

        # Zera o campo de checksum no cabeçalho IP (bytes 10 e 11)
        ip_header = ip_header[:10] + b'\x00\x00' + ip_header[12:]
        checksum_corrigido = calc_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', checksum_corrigido) + ip_header[12:]
        # Monta o datagrama IP
        datagrama = ip_header + segmento


        self.enlace.enviar(datagrama, next_hop)
