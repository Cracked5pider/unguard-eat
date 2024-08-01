import struct

import PySide6
from PySide6.QtCore import *
from PySide6.QtGui import *
from PySide6.QtWidgets import *

from os.path import exists, dirname, basename
from pyhavoc.agent import *
from pyhavoc.ui    import HcSwitch

def file_read( path: str ) -> bytes:
    handle    = open( path, 'rb' )
    obj_bytes = handle.read()

    handle.close()

    return obj_bytes

class KnAntiShellcodeMitigation( HcKaineBuildModule, priority=0 ):

    def __init__(self):
        super().__init__()

        self.cfg_mov_rax = 1 << 0

        self.opt_mov_rax = "mov rax, [rax]"

        return

    def interface( self, layout: QFormLayout ):

        self.horizontal_layout = QHBoxLayout()
        self.check_enabled     = HcSwitch()
        self.combo_gadgets     = QComboBox()

        self.combo_gadgets.addItem( self.opt_mov_rax )

        self.horizontal_layout.addWidget( self.check_enabled )
        self.horizontal_layout.addWidget( self.combo_gadgets )

        layout.addRow( "Anti-Shellcode mitigation: ", self.horizontal_layout )

        return

    def configuration( self, config: dict ) -> bytes:
        ##
        ## we won't be packing the configuration
        ## via the config section in the agent
        ##
        return b''

    def module( self ) -> bytes:
        extension = b''
        config    = 0

        ##
        ## get the extension code and encode the
        ## configuration into the binary
        ##
        if self.check_enabled.isChecked():
            extension = file_read( dirname( __file__ ) + "/bin/unguard-eat.x64.bin" )

            ##
            ## get gadget to use from configuration
            ##
            if self.combo_gadgets.currentText() == self.opt_mov_rax:
                config |= self.cfg_mov_rax

            ##
            ## patch the configuration
            ##
            extension = extension.replace( b'Cain', struct.pack( '<L', config ) )

        return extension
