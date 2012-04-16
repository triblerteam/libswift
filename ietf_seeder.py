#! /usr/bin/env python

import os
import subprocess
import time
import logging

from pymdht.core.pymdht import Pymdht
from pymdht.core.identifier import Id, RandomId
from pymdht.core.node import Node
import pymdht.plugins.routing_nice_rtt as routing_m_mod
import pymdht.plugins.lookup_a4 as lookup_m_mod
import pymdht.core.exp_plugin_template as experimental_m_mod

SWIFT_PORT = 20050
PATH = "~/swiftcontent-march2012/"

HASHES = ["2b2fe5f1462e5b7ac4d70fa081e0169160b2d3a6", # SirKenRobinson_2006-480p.ts
          "a004e583a05de39f87ceb7a6eb5608c89415e2f0", # JillBolteTaylor_2008-480p.ts
          "23f99be0f5198efceb4da15fd196106b70216e1e", # PranavMistry_2009I-480p.ts
          "022e1c308d991c653c5e3549fee247cfabc7cf55", # DavidGallo_2007-480p.ts
          "5e615dfdf66953f63be284ae0763f80cb70f0892", # PattieMaes_2009-480p.ts
          "e5478e34e01551a2925fc12f4d28a523b2911af5", # SimonSinek_2009X-480p.ts
          "ec677ff98abe4a0b2b5c122065c080f14ad4a272", # ArthurBenjamin_2005-480p.ts
          "71ccb9341537a9a5738650e6842c97fc88306582", # HansRosling_2006.ts
          "ad2fa2dd346f67583ab327a14d739bdccd44cdb3", # RobReid_2012-480p.ts
          "2dcb65253916e44a791ac7a1a0ee56f51f30086f", # BreneBrown_2012-480p.ts
          "5692014fadcdb33792f0cfa7cc87287bfb8deb91", # SusanCain_2012-480p.ts
          "dbfcbf3e5ca676d1e4ea8a88375ea95ce2f2184f", # VijayKumar_2012-480p.ts
          "db5dabb90a3cbd61a90866a4cc208ae959440ec9", # I.Think.Were.Alone.Now.2008.720p.x264-VODO.ts
          "071d43828a3291defa073008b601aacfb09fd281", # L5.Part.1.2012.Xvid-VODO.ts
          "cbc48a70222e37230bf3f2b3bd84eaef5ae16b41", # Pioneer.One.S01E06.Xvid-VODO.ts
          "3ce3f4a5bb785d5e8eb7bf3f2615e37095eb5170", # An.Honest.Man.Xvid-VODO.ts
          ]


def start_swift(path):
    os.system("./swift -l 0.0.0.0:" + str(SWIFT_PORT) + " -d " + path + " &")

def start_pymdht():
    my_node = Node(('127.0.0.1', 7000), RandomId())
    dht = Pymdht(my_node, '.',
                 routing_m_mod,
                 lookup_m_mod,
                 experimental_m_mod,
                 None,
                 logging.DEBUG,
                 False)
    while 1:
        for h in HASHES:
            time.sleep(10) #time between announcements
            # lookup and announcement
            dht.get_peers(None, Id(h), None, SWIFT_PORT)
        # Wait a long while till next announcement round
        time.sleep(20 * 60)




if __name__ == '__main__':
    start_swift(PATH)
    start_pymdht()
