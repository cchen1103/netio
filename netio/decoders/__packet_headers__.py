# protocol defination
class Ethernet:
    name = 'ethernet'
    protocol = 255
    h_len = 14


class Ip:
    name = 'ip'
    protocol = 8
    h_len = 20


class Tcp:
    name = 'tcp'
    protocol = 6
    h_len = 20
    fin, syn, rst, psh, ack, urg = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
    def __call__(self, data):
        """
            data: ip:port
        """
        self.ip, self.port = data.split(':')


class Udp:
    name = 'udp'
    protocol = 17
    h_len = 8
