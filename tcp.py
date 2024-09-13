import asyncio
from tcputils import *
import random
import time
import math

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no)
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None

        # Estabelencedo Conexão
        src_addr, src_port, dst_addr, dst_port = id_conexao
        self.seq_no = random.randint(0, 10000) #Seq_no precisa ser aleatório
        self.ack_no = seq_no + 1
        # Envia o segmento com a flag SYN+ACK
        header = fix_checksum(
                make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_SYN + FLAGS_ACK),
                dst_addr, src_addr)
        self.servidor.rede.enviar(header, src_addr)
        self.Send_Base = self.seq_no + 1 #Send_Base = InitialSeqNun
        self.seq_no += 1 #FlagSYS = 1 bit

        self.temp = b'' 
        self.Pending_Segments = b''
        self.Current_Segment = b''
        self.Close_Con_Flag = False

        # Passo 6
        self.timer = None
        self.timebegin = None
        self.timeend = None
        self.Sample_RTT = None
        self.Estimated_RTT = None
        self.Dev_RTT = None
        self.alpha = 0.125
        self.beta = 0.25
        self.Timeout_Interval = 1
        self.Congestion_Window = 1

    def _Timer(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        Current_Segment = self.Pending_Segments[:MSS]
        header = fix_checksum(make_header(dst_port, src_port, self.Send_Base, self.ack_no, FLAGS_ACK) + Current_Segment,
                        dst_addr, src_addr)
        self.servidor.rede.enviar(header, src_addr)
        self.timebegin = None
        self.Congestion_Window = math.ceil(self.Congestion_Window / 2)
        self.timer = asyncio.get_event_loop().call_later(self.Timeout_Interval, self._Timer)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao

        if seq_no == self.ack_no and len(payload) > 0:
            self.callback(self, payload)
            self.ack_no += len(payload)
            header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK),
                            dst_addr, src_addr)
            self.servidor.rede.enviar(header, src_addr)

        elif (flags & FLAGS_FIN) == FLAGS_FIN:
            self.callback(self, b'')
            self.ack_no = seq_no + 1
            header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK),
                            dst_addr, src_addr)
            self.servidor.rede.enviar(header, src_addr)

        elif (flags & FLAGS_ACK) == FLAGS_ACK:
            if self.Close_Con_Flag and ack_no == self.seq_no + 1:
                del self.servidor.conexoes[self.id_conexao]
            elif ack_no > self.Send_Base:
                self._process_ack(ack_no)        

    def _process_ack(self, ack_no):
        self.timer.cancel()
        if self.timebegin is not None:
            self._rtt()

        self.Pending_Segments = self.Pending_Segments[ack_no - self.Send_Base:]
        self.Send_Base = ack_no

        if len(self.Pending_Segments) == 0:
            self.timer = None
        else:
            self.timer = asyncio.get_event_loop().call_later(self.Timeout_Interval, self._Timer)    

        if len(self.temp) > 0:
            self.enviar(b'')

    def _rtt(self):
        self.timeend = time.time()
        self.Congestion_Window += 1
        self.Sample_RTT = self.timeend - self.timebegin
        if self.Estimated_RTT and self.Dev_RTT:
            self.Estimated_RTT = (1 - self.alpha) * self.Estimated_RTT + self.alpha * self.Sample_RTT
            self.Dev_RTT = (1 - self.beta) * self.Dev_RTT + self.beta * abs(self.Sample_RTT - self.Estimated_RTT)
        else:
            self.Estimated_RTT = self.Sample_RTT
            self.Dev_RTT = self.Sample_RTT / 2                
        self.Timeout_Interval = self.Estimated_RTT + 4 * self.Dev_RTT

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        self.temp += dados

        print(f'Enviando {math.ceil(len(self.temp)/MSS)} segmento(s)...') 

        for i in range(self.Congestion_Window):
            if len(self.temp) > 0:
                Current_Segment = self.temp[:MSS]
                self.temp = self.temp[MSS:]
                header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_ACK) + Current_Segment,
                            dst_addr, src_addr)
                self.servidor.rede.enviar(header, src_addr)
                self.Pending_Segments += Current_Segment
                self.seq_no += len(Current_Segment)

        self.timebegin = time.time()
        if not self.timer:
            self.timer = asyncio.get_event_loop().call_later(self.Timeout_Interval, self._Timer)

    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        header = fix_checksum(make_header(dst_port, src_port, self.seq_no, self.ack_no, FLAGS_FIN),
                            dst_addr, src_addr)
        self.servidor.rede.enviar(header, src_addr)
        self.Close_Con_Flag = True
