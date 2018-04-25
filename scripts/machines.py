class Machine(object):
   def __init__(self, name, mac=None, ip=None):
      self.name = name
      self.mac = mac
      self.ip = ip

target = Machine('target', mac='08:00:27:b2:89:86', ip='192.168.56.20')
attacker = Machine('attacker', mac='08:00:27:46:7b:6a', ip='192.168.56.10')
