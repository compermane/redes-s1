class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.frame = bytearray()
        self.estado = "normal"

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        dados = bytearray()
        dados.append(0xC0)  # Início do quadro

        for byte in datagrama:
            if byte == 0xC0:
                dados.extend([0xDB, 0xDC])  # Escape para 0xC0
            elif byte == 0xDB:
                dados.extend([0xDB, 0xDD])  # Escape para 0xDB
            else:
                dados.append(byte)
        
        dados.append(0xC0)  # Fim do quadro

        self.linha_serial.enviar(dados)

    def __raw_recv(self, dados):
        for byte in dados:
            if byte == 0xC0:  # Delimitador de fim de quadro
                if self.frame:
                    try:
                        # Chama o callback apenas se o quadro não for vazio
                        if len(self.frame) > 0:
                            self.callback(bytes(self.frame))
                    except Exception:
                        import traceback
                        traceback.print_exc()
                    finally:
                        # Limpa o buffer para o próximo quadro
                        self.frame = bytearray()
            elif byte == 0xDB:  # Byte de escape
                self.estado = 'escape'
            else:
                if self.estado == 'escape':
                    # Verifica o byte escapado
                    if byte == 0xDC:
                        self.frame.append(0xC0)
                    elif byte == 0xDD:
                        self.frame.append(0xDB)
                    self.estado = 'normal'
                else:
                    self.frame.append(byte)

