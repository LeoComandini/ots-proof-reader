import sys
import os
from functools import partial
import hashlib
import base64

from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QWidget, QLabel, QFileDialog, QMessageBox, \
    QLineEdit, QGridLayout, QVBoxLayout, QHBoxLayout, QToolBar, QAction, QStatusBar, QDialog, QTextEdit
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import Qt, QSize
from opentimestamps.core.serialize import BytesDeserializationContext, BadMagicError, DeserializationError
from opentimestamps.core.timestamp import DetachedTimestampFile
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation


default_folder = os.path.expanduser("~")
window_geometry = (50, 50, 970, 350)
column_width = [230, 550, 25, 100]
row_height = 25
icon_size = (25, 25)
title_font = QFont()
title_font.setBold(True)
help_str_file_hash = \
    "In the timestamp (.ots) it is written the hash value of the original file. " \
    "To verify that the timestamp is proving the existence of your file " \
    "(and not something else), " \
    "you need to check that the two hash values match.\n\n" \
    "You can compute the hash value somewhere else and paste it or " \
    "you can browse the file and compute the hash directly."
help_merkle_root = \
    "To verify that your file existed prior to a certain block, " \
    "it is needed to check that the data stored in your file are committed to that Bitcoin block " \
    "(more specifically, to a part of it: the Merkle root). \n\n" \
    "To do so it is necessary to start from the hash of your file and " \
    "then execute locally the cryptographic operations contained in the timestamp. " \
    "Those operations end in an attestation which indicates which is the block to look at. " \
    "The verification consist in checking that the Merkle root computed locally " \
    "is equal to the one retrieved from a trusted source. \n\n" \
    "Note that changing the file (and thus its hash) or " \
    "changing an operation inside the timestamp makes the proof invalid. " \
    "This is due to the cryptographic proprerties of the operations used."


def find_best_attestation(timestamp):
    """Find the best Bitcoin attestation"""

    merkle_root, best_attestation = None, None
    for msg, a in timestamp.all_attestations():
        if a.__class__ == BitcoinBlockHeaderAttestation:
            if best_attestation:
                if a < best_attestation:
                    merkle_root, best_attestation = msg, a
            else:
                merkle_root, best_attestation = msg, a
    return merkle_root, best_attestation


def verifier(w_res: QLabel, w_comp: QLineEdit, s_comp):
    p = w_res.palette()
    if w_comp.text() == s_comp:
        w_res.setText(" Verified!")
        w_res.setAutoFillBackground(True)
        p.setColor(w_res.backgroundRole(), Qt.green)
        w_res.setPalette(p)
    else:
        w_res.setText(" Failed!")
        w_res.setAutoFillBackground(True)
        p.setColor(w_res.backgroundRole(), Qt.red)
        w_res.setPalette(p)


class InitialWindow(QWidget):
    """Initial window, before the OTS file is uploaded"""

    def __init__(self, parent=None):
        super(InitialWindow, self).__init__(parent)

        parent.action_close.setDisabled(True)
        parent.action_show.setDisabled(True)

        vbox = QVBoxLayout()

        long_description = QLabel(
            "Welcome to the OpenTimestamps proof reader.\n\n"
            "Upload your timestamp and verify locally that:\n"
            " - the hash value written in the proof is the same of your file;\n"
            " - the Merkle root computed from your hash value is the one committed in the Bitcoin blockchain.\n\n"
            "If both verification are correct, then the timestamp proves that your file existed prior to that Bitcoin block.")
        long_description.setWordWrap(True)
        vbox.addWidget(long_description)
        doubts = QLabel("For any doubts please visit <a href=\'https://opentimestamps.org\'>OpenTimestamps</a> "
                        "or have a look at the "
                        "<a href=\'https://github.com/LeoComandini/ots-proof-reader\'>source code</a>.")
        doubts.setOpenExternalLinks(True)
        vbox.addWidget(doubts)

        self.setLayout(vbox)


class DisplayProofWindow(QWidget):
    """Display proof, after the OTS is uploaded"""

    def __init__(self, parent=None):
        super(DisplayProofWindow, self).__init__(parent)

        parent.action_close.setDisabled(False)
        parent.action_show.setDisabled(False)

        vbox = QVBoxLayout()
        self.init_verify_hash(parent, vbox)
        self.init_verify_attestation(parent, vbox)
        self.setLayout(vbox)

    def init_verify_hash(self, parent, vbox):
        hash_op = parent.detached_timestamp.file_hash_op
        hash_value = parent.detached_timestamp.timestamp.msg.hex()

        t1 = QLabel("Verify Hash")
        t1.setFont(title_font)
        t1.setAlignment(Qt.AlignCenter)

        button_help_hash = QPushButton("", self)
        button_help_hash.setIcon(QIcon('images/question.png'))
        button_help_hash.clicked.connect(partial(parent.dialog, help_str_file_hash, "info"))
        button_help_hash.setFixedSize(*icon_size)
        button_help_hash.setStatusTip("Help on hash verification")

        hbox_top = QHBoxLayout()
        hbox_top.addWidget(t1, alignment=Qt.AlignRight)
        hbox_top.addWidget(button_help_hash, alignment=Qt.AlignLeft)

        vbox.addLayout(hbox_top)

        grid_hash = QGridLayout()

        wh00 = QLabel("Hash used: ")
        wh00.setFixedWidth(column_width[0])
        wh00.setAlignment(Qt.AlignRight)
        grid_hash.addWidget(wh00, 0, 0)

        wh10 = QLabel("Hash value from ots: ")
        wh10.setFixedWidth(column_width[0])
        wh10.setAlignment(Qt.AlignRight)
        grid_hash.addWidget(wh10, 1, 0)

        wh20 = QLabel("Hash value from file: ")
        wh20.setAlignment(Qt.AlignRight)
        wh20.setFixedWidth(column_width[0])
        grid_hash.addWidget(wh20, 2, 0)

        wh01 = QLabel(hash_op.TAG_NAME)
        wh01.setFixedWidth(column_width[1])
        wh01.setStatusTip("Hash function used to hash the original file")
        grid_hash.addWidget(wh01, 0, 1)

        wh11 = QLabel(hash_value)
        wh11.setTextInteractionFlags(Qt.TextSelectableByMouse)
        wh11.setFixedWidth(column_width[1])
        wh11.setStatusTip("Hash value of the original file written in the timestamp")
        grid_hash.addWidget(wh11, 1, 1)

        wh21 = self.hash_value_from_file = QLineEdit()
        wh21.setFixedWidth(column_width[1])
        grid_hash.addWidget(wh21, 2, 1)

        bh22 = QPushButton("", self)
        bh22.setIcon(QIcon('images/blue-folder-open-document.png'))
        bh22.clicked.connect(partial(self.open_and_hash_file, hash_op, parent))
        bh22.setFixedWidth(column_width[2])
        bh22.setFixedHeight(row_height)
        bh22.setStatusTip("Choose the file and hash it")
        grid_hash.addWidget(bh22, 2, 2)

        vbox_verify_hash = QVBoxLayout()
        button_verify_hash = QPushButton("Verify\nHash", self)
        button_verify_hash.setFixedWidth(column_width[3])
        button_verify_hash.setStatusTip("Verify that the hash value from the timestamp and "
                                        "from the original file are the same")

        self.result_hash_verification = QLabel()
        self.result_hash_verification.setFixedWidth(column_width[3])
        button_verify_hash.clicked.connect(partial(verifier, self.result_hash_verification,
                                                   self.hash_value_from_file,
                                                   parent.detached_timestamp.timestamp.msg.hex()))

        vbox_verify_hash.addWidget(button_verify_hash, alignment=Qt.AlignCenter)
        vbox_verify_hash.addWidget(self.result_hash_verification, alignment=Qt.AlignCenter)

        hbox = QHBoxLayout()
        hbox.addLayout(grid_hash)
        hbox.addLayout(vbox_verify_hash)

        vbox.addLayout(hbox)

    def init_verify_attestation(self, parent, vbox):
        t2 = QLabel("Verify Attestation")
        t2.setFont(title_font)
        t2.setAlignment(Qt.AlignCenter)

        button_help_att = QPushButton("", self)
        button_help_att.setIcon(QIcon('images/question.png'))
        button_help_att.clicked.connect(partial(parent.dialog, help_merkle_root, "info"))
        button_help_att.setFixedSize(*icon_size)
        button_help_att.setStatusTip("Help on attestation verification")

        hbox_top = QHBoxLayout()
        hbox_top.addWidget(t2, alignment=Qt.AlignRight)
        hbox_top.addWidget(button_help_att, alignment=Qt.AlignLeft)

        vbox.addStretch()
        vbox.addLayout(hbox_top)

        merkle_root, best_attestation = find_best_attestation(parent.detached_timestamp.timestamp)
        if not best_attestation:
            vbox.addWidget(QLabel("Timestamp seems incomplete, "
                                  "try to upgrade it with the aid of a calendar. \n\n"
                                  "If you still have issues, "
                                  "print the proof in a human readable format by clicking on 'Show information…'."))
        else:
            merkle_root_ots = merkle_root[::-1].hex()
            grid_att = QGridLayout()

            wa00 = QLabel("Best attestation: ")
            wa00.setFixedWidth(column_width[0])
            wa00.setAlignment(Qt.AlignRight)
            grid_att.addWidget(wa00, 0, 0)

            wa01 = QLabel("Bitcoin block " + str(best_attestation.height))
            wa01.setFixedWidth(column_width[0])
            wa01.setStatusTip("Best (oldest) attestation found in the timestamp")
            grid_att.addWidget(wa01, 0, 1)

            wa10 = QLabel("Merkle root from ots: ")
            wa10.setFixedWidth(column_width[0])
            wa10.setAlignment(Qt.AlignRight)
            grid_att.addWidget(wa10, 1, 0)

            wa11 = QLabel(merkle_root_ots)
            wa11.setTextInteractionFlags(Qt.TextSelectableByMouse)
            wa11.setFixedWidth(column_width[1])
            wa11.setStatusTip("Merkle root computed from the timestamp")
            grid_att.addWidget(wa11, 1, 1)

            wa20 = QLabel("Merkle root from trusted source: ")
            wa20.setFixedWidth(column_width[0])
            wa20.setAlignment(Qt.AlignRight)
            grid_att.addWidget(wa20, 2, 0)

            wa21 = self.merkle_root_blockchain = QLineEdit()
            wa21.setFixedWidth(column_width[1])
            grid_att.addWidget(wa21, 2, 1)

            ba22 = QPushButton("", self)
            ba22.setIcon(QIcon('images/magnifier-left.png'))
            ba22.clicked.connect(partial(parent.dialog_block_explorer, best_attestation.height))
            ba22.setFixedWidth(column_width[2])
            ba22.setFixedHeight(row_height)
            ba22.setStatusTip("Search on block explorer(s)")
            grid_att.addWidget(ba22, 2, 2)

            vbox_verify_att = QVBoxLayout()
            button_verify_att = QPushButton("Verify\nAttestation", self)
            button_verify_att.setFixedWidth(column_width[3])
            button_verify_att.setStatusTip("Verify that the Merkle root from the timestamp and "
                                           "from the blockchain are the same")

            self.result_att_verification = QLabel()
            self.result_att_verification.setFixedWidth(column_width[3])
            button_verify_att.clicked.connect(partial(verifier, self.result_att_verification,
                                                      self.merkle_root_blockchain, merkle_root_ots))

            vbox_verify_att.addWidget(button_verify_att, alignment=Qt.AlignCenter)
            vbox_verify_att.addWidget(self.result_att_verification, alignment=Qt.AlignCenter)

            hbox = QHBoxLayout()
            hbox.addLayout(grid_att)
            hbox.addLayout(vbox_verify_att)

            vbox.addLayout(hbox)

    def open_and_hash_file(self, hasher, parent):
        # FIXME: use parent.filename_ots to guess where the file is
        filename, __ = QFileDialog.getOpenFileName(self, "Choose file to hash", default_folder)  # self??
        if not filename:
            return
        try:
            with open(filename, 'rb') as f:
                file_binary = f.read()
                self.hash_value_from_file.setText(hashlib.new(hasher.HASHLIB_NAME, file_binary).digest().hex())
        except FileNotFoundError:
            parent.dialog("File not found", "critical")


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)

        self.detached_timestamp = None
        self.filename_ots = None

        self.setGeometry(*window_geometry)
        self.setMinimumSize(*window_geometry[2:])

        self.status = QStatusBar()
        self.setStatusBar(self.status)

        timestamp_menu = self.menuBar().addMenu("&Timestamp")

        timestamp_toolbar = QToolBar("Timestamp")
        timestamp_toolbar.setIconSize(QSize(*icon_size))
        self.addToolBar(timestamp_toolbar)

        action_open_timestamp = QAction(QIcon(os.path.join('images', 'favicon-16x16.ico')),
                                        "Open…", self)
        action_open_timestamp.setStatusTip("Open a timestamp and show its content")
        action_open_timestamp.triggered.connect(self.read_from_ots)

        action_paste_hex = QAction("Hex", self)
        action_paste_hex.setStatusTip("Paste timestamp in hex")
        action_paste_hex.triggered.connect(partial(self.read_from_str, "hex"))

        action_paste_b64 = QAction("Base64", self)
        action_paste_b64.setStatusTip("Paste timestamp in base64")
        action_paste_b64.triggered.connect(partial(self.read_from_str, "base64"))

        self.action_close = action_close_timestamp = QAction("Close", self)
        action_close_timestamp.setStatusTip("Close timestamp")
        action_close_timestamp.triggered.connect(self.start_initial_window)

        self.action_show = action_show_timestamp = QAction(QIcon(os.path.join('images', 'printer.png')),
                                                           "Show information…", self)
        action_show_timestamp.setStatusTip("Show the whole timestamp in human readable format")
        action_show_timestamp.triggered.connect(self.dialog_info)

        timestamp_menu.addAction(action_open_timestamp)
        paste_menu = timestamp_menu.addMenu("Paste")
        paste_menu.addAction(action_paste_hex)
        paste_menu.addAction(action_paste_b64)
        timestamp_menu.addAction(action_close_timestamp)
        timestamp_menu.addSeparator()
        timestamp_menu.addAction(action_show_timestamp)

        timestamp_toolbar.addAction(action_open_timestamp)
        timestamp_toolbar.addAction(action_show_timestamp)

        self.start_initial_window()

    def start_initial_window(self):
        self.window = InitialWindow(self)
        self.setWindowTitle("OpenTimestamps proof reader")
        self.setCentralWidget(self.window)
        self.show()

    def start_display_proof_window(self):
        if not self.detached_timestamp:
            return
        title = ((self.filename_ots + " - ") if self.filename_ots else "") + "OpenTimestamps proof reader"
        self.window = DisplayProofWindow(self)
        self.setWindowTitle(title)
        self.setCentralWidget(self.window)
        self.show()

    def bin_to_ots(self, proof_binary, filename):
        try:
            ctx = BytesDeserializationContext(proof_binary)
            self.detached_timestamp = DetachedTimestampFile.deserialize(ctx)
        except BadMagicError:
            self.dialog("Error! %r is not a timestamp file." % filename, "critical")
        except DeserializationError as exp:
            self.dialog("Invalid timestamp file %r: %s" % (filename, exp), "critical")
        except Exception as exp:  # which errors occur here?
            self.dialog("Invalid file %r: %s" % (filename, exp), "critical")

    def upload_ots(self):
        filename, __ = QFileDialog.getOpenFileName(self, "Choose an ots proof to upload", default_folder)
        if not filename:
            return

        with open(filename, 'rb') as f:
            proof_binary = f.read()
            self.bin_to_ots(proof_binary, filename)

        self.filename_ots = filename

    def read_from_ots(self):
        self.upload_ots()
        self.start_display_proof_window()

    def read_from_str(self, enc):

        def str_to_ots(t, enc):
            s = t.toPlainText()
            if enc == "hex":
                try:
                    proof_binary = bytes.fromhex(s)
                except ValueError:
                    self.dialog("Error! Non-hexadecimal number", "critical")
                    return
            elif enc == "base64":
                try:
                    proof_binary = base64.b64decode(s.encode())
                except Exception as e:
                    self.dialog("Error! %s" % str(e), "critical")
                    return
            else:
                return

            self.bin_to_ots(proof_binary, s)
            d.close()
            self.start_display_proof_window()

        d = QDialog(self)
        d.setWindowTitle("Paste timestamp in " + enc)
        vbox = QVBoxLayout()
        text = QTextEdit(d)

        hbox = QHBoxLayout()
        button_ok = QPushButton("Ok", d)
        button_cancel = QPushButton("Cancel", d)
        button_ok.clicked.connect(partial(str_to_ots, text, enc))
        button_cancel.clicked.connect(d.close)
        hbox.addWidget(button_ok)
        hbox.addWidget(button_cancel)

        vbox.addWidget(text)
        vbox.addLayout(hbox)

        d.setLayout(vbox)
        d.show()

    def dialog(self, s, context=None):
        dlg = QMessageBox(self)
        dlg.setText(s)
        if context == "info":
            dlg.setWindowTitle("Help")
            dlg.setIcon(QMessageBox.Information)
        elif context == "critical":
            dlg.setWindowTitle("Warning")
            dlg.setIcon(QMessageBox.Critical)
        dlg.show()

    def dialog_info(self):
        dlg = QDialog(self)
        title = "ots info " + (self.filename_ots if self.filename_ots else "")
        dlg.setWindowTitle(title)

        ok_button = QPushButton("Ok", self)
        ok_button.setFixedSize(row_height * 4, row_height)
        ok_button.clicked.connect(dlg.close)

        vbox = QVBoxLayout()
        if self.detached_timestamp:
            dlg.setMinimumSize(950, 450)

            hash_op_name = self.detached_timestamp.file_hash_op.TAG_NAME
            hash_value = self.detached_timestamp.timestamp.msg.hex()
            timestamp_tree = self.detached_timestamp.timestamp.str_tree()

            text = QTextEdit()
            text.setReadOnly(True)
            p = text.viewport().palette()
            p.setColor(text.viewport().backgroundRole(), Qt.black)
            text.viewport().setPalette(p)
            text.setTextColor(Qt.white)
            text.setText("File " + hash_op_name + " hash: " + hash_value + "\nTimestamp:\n" + timestamp_tree)

            vbox.addWidget(text)
        else:
            vbox.addWidget(QLabel("No proof detected."))

        vbox.addWidget(ok_button, alignment=Qt.AlignRight)
        dlg.setLayout(vbox)
        dlg.show()

    def dialog_block_explorer(self, height):
        dlg = QDialog(self)
        dlg.setMinimumWidth(250)
        dlg.setWindowTitle("Retrieve Merkle root from block explorer")

        ok_button = QPushButton("Ok", self)
        ok_button.setFixedSize(100, 25)
        ok_button.clicked.connect(dlg.close)

        vbox = QVBoxLayout()

        remind = QLabel("Remember that block explorers may lie, so don't trust them too much. "
                        "Using them is a lazy solution and could be dangerous, "
                        "use a trusted Bitcoin node to avoid these issues.\n\n"
                        "Here there is a short list of block explorers you may use "
                        "to copy and paste the Merkle root from:")
        final = QLabel(
            "If you are not satisfied with those, search for block " + str(height) + " on another block explorer.")
        remind.setWordWrap(True)
        final.setWordWrap(True)

        url_blockchaininfo = "https://blockchain.info/block-height/" + str(height)
        blockchaininfo = QLabel(" - <a href=\'" + url_blockchaininfo + "\'>blockchain.info</a>")
        blockchaininfo.setOpenExternalLinks(True)

        url_blockcypher = "https://api.blockcypher.com/v1/btc/main/blocks/" + str(height)
        blockcypher = QLabel(" - <a href=\'" + url_blockcypher + "\'>blockcypher.com</a>")
        blockcypher.setOpenExternalLinks(True)

        url_btccom = "https://btc.com/" + str(height)
        btccom = QLabel(" - <a href=\'" + url_btccom + "\'>btc.com</a>")
        btccom.setOpenExternalLinks(True)

        vbox.addWidget(remind)
        vbox.addWidget(blockchaininfo)
        vbox.addWidget(blockcypher)
        vbox.addWidget(btccom)
        vbox.addWidget(final)
        vbox.addWidget(ok_button, alignment=Qt.AlignRight)

        dlg.setLayout(vbox)

        dlg.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MainWindow()
    sys.exit(app.exec_())
