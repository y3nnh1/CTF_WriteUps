#!/usr/bin/env python3
import os
import random
import socketserver
import datetime
from logger import Logger
from exhibits import SubstitutionExhibitHandler, TranspositionExhibitHandler
from Crypto.Cipher import AES

HOST = '0.0.0.0'
PORT = 31337
ECB_KEY_PATH = './keys/ecb-key.bin'
CTR_KEY_PATH = './keys/ctr-key.bin'
LOG_PATH = 'museum.log'
logger = Logger(LOG_PATH)


# Utility functions

def read_key(path):
    with open(path, 'rb') as f:
        return f.read()


def fit_to_size(text, size):
    raw = text.encode()[:size]
    return raw.ljust(size, b' ')


def parse_fields(s):
    out = {}
    for part in s.split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
            out[k] = v
    return out


def serialize_fields(d):
    return '&'.join(f'{k}={v}' for k, v in d.items())


# Handling of badges

def create_badge(name):
    version_field = fit_to_size('1', 2)
    name_field = fit_to_size(name, 30)
    issuer_field = fit_to_size('MAC', 16)
    role_field = fit_to_size('visitor', 16)
    badge = version_field + name_field + issuer_field + role_field

    ecb_key = read_key(ECB_KEY_PATH)
    cipher = AES.new(ecb_key, AES.MODE_ECB)
    return cipher.encrypt(badge).hex()


def parse_badge(encrypted_badge):
    ecb_key = read_key(ECB_KEY_PATH)
    cipher = AES.new(ecb_key, AES.MODE_ECB)
    badge = cipher.decrypt(bytes.fromhex(encrypted_badge))

    if len(badge) != 64:
        raise ValueError('Invalid badge length')
    return {
        'version': badge[0:2].rstrip(b' ').decode(),
        'name': badge[2:32].rstrip(b' ').decode(),
        'issuer': badge[32:48].rstrip(b' ').decode(),
        'role': badge[48:64].rstrip(b' ').decode()
    }


class ChallengeHandler(socketserver.StreamRequestHandler):
    def setup(self):
        super().setup()
        self.rng = random.Random(int.from_bytes(os.urandom(16), 'big'))
        self.remote = self.client_address[0]
        self.logger = logger
        self.user_name = None
        self.user_role = None
        self.logger.log('connect', remote=self.remote)

    def finish(self):
        try:
            self.logger.log('disconnect', remote=self.remote)
        finally:
            super().finish()

    def send(self, msg=''):
        if not msg.endswith('\n'):
            msg += '\n'
        self.wfile.write(msg.encode())
        self.wfile.flush()

    def recvline(self, prompt='> '):
        self.send(prompt)
        data = self.rfile.readline(8192)
        if not data:
            raise ConnectionResetError
        return data.rstrip(b'\n').decode()

    def handle(self):
        self.send(
            'Welcome to the MAC - Museum of Ancient Cryptography!\n\n'
            'Dive into the mysteries of classical ciphers through our carefully designed, hands-on exhibits.\n'
            'Discover their weaknesses and learn how to exploit them to recover the hidden plaintexts.\n\n'
            'Have fun... and crack them all!'
        )
        while True:
            try:
                self.main_menu()
                return
            except (BrokenPipeError, ConnectionResetError):
                break
            except Exception as e:
                self.logger.log('handler_error', remote=self.remote, error=str(e))
                self.send(f'[!] error: {e}')

    def main_menu(self):
        choice = None
        while choice != '6':
            self.send(
                '\n=== Main menu ===\n'
                '1) Obtain a new visitor badge\n'
                '2) Present a badge\n'
                '3) Visit the substitution cipher exhibit (visitor or curator badge required)\n'
                '4) Visit the transposition cipher exhibit (visitor or curator badge required)\n'
                '5) Access the exhibit control console (curator badge required)\n'
                '6) Quit\n'
            )
            choice = self.recvline('What would you like to do? (1-6)').strip()

            if choice == '1':
                self.issue_badge()
            elif choice == '2':
                self.present_badge()
            elif choice == '3':
                if self.user_role in ['visitor', 'curator']:
                    SubstitutionExhibitHandler(self).visit_exhibit()
                else:
                    self.send('Access denied. Present a visitor or curator badge first.')
            elif choice == '4':
                if self.user_role in ['visitor', 'curator']:
                    TranspositionExhibitHandler(self).visit_exhibit()
                else:
                    self.send('Access denied. Present a visitor or curator badge first.')
            elif choice == '5':
                if self.user_role == 'curator':
                    self.exhibit_control_console()
                else:
                    self.send('Access denied. Present a curator badge first.')
            elif choice == '6':
                self.send('Disconnecting.')
            else:
                self.send('Invalid choice.')

    def issue_badge(self):
        name = self.recvline('Dear visitor, welcome! What is your name? (max 30 bytes)')
        if len(name.encode()) > 30:
            self.send('Name too long. Try again.')
            return

        encrypted_badge = create_badge(name)

        self.logger.log('badge_issued', remote=self.remote, name=name, role='visitor')
        self.send(
            'Here is your badge (encrypted, hex-encoded):\n\n'
            f'    {encrypted_badge}\n\n'
            'Enjoy your stay!'
        )

    def present_badge(self):
        encrypted_badge = self.recvline('Please present your badge (encrypted, hex-encoded):').strip()

        try:
            badge = parse_badge(encrypted_badge)
        except:
            self.logger.log('badge_rejected', remote=self.remote, reason='invalid_ciphertext')
            self.send('Badge rejected: invalid ciphertext.')
            return

        self.logger.log('badge_presented', remote=self.remote, name=badge['name'],
                        issuer=badge['issuer'], role=badge['role'])

        self.send(
            'Badge fields:\n'
            f'  name   = {badge['name']}\n'
            f'  issuer = {badge['issuer']}\n'
            f'  role   = {badge['role']}\n'
        )

        if badge['issuer'] != 'MAC' or badge['role'] not in ['visitor', 'curator']:
            self.send('Badge rejected: invalid issuer or role.')
            return

        self.user_name = badge['name']
        self.user_role = badge['role']

    def exhibit_control_console(self):
        choice = None
        while choice != '3':
            self.send(
                '\n=== Exhibit control console ===\n'
                '1) Request encrypted control ticket\n'
                '2) Execute encrypted control ticket\n'
                '3) Back\n'
            )
            choice = self.recvline('What would you like to do? (1-3)').strip()

            if choice == '1':
                self.issue_ticket()
            elif choice == '2':
                self.execute_ticket()
            elif choice != '3':
                self.send('Invalid option.')

    def issue_ticket(self):
        expires = datetime.datetime.now() + datetime.timedelta(days=1)
        ticket_fields = {
            'version': '1.2.194.23',
            'target': 'logs',
            'cmd': 'read',
            'expires': expires.strftime('%d/%m/%Y %H:%M:%S')
        }
        ticket = serialize_fields(ticket_fields).encode()

        ctr_key = read_key(CTR_KEY_PATH)
        cipher = AES.new(ctr_key, AES.MODE_CTR)
        enc_ticket = (cipher.nonce + cipher.encrypt(ticket)).hex()

        self.logger.log('ticket_issued', remote=self.remote, name=self.user_name)

        self.send(
            'Here is your encrypted ticket (nonce || ciphertext, hex-encoded):\n\n'
            f'    {enc_ticket}\n\n'
            'We currently issue only tickets to read the museum logs.'
        )

    def execute_ticket(self):
        ticket_hex = self.recvline('Please provide your ticket (nonce || ciphertext, hex-encoded):').strip()

        try:
            ticket_raw = bytes.fromhex(ticket_hex)
            nonce, ciphertext = ticket_raw[:8], ticket_raw[8:]
            ctr_key = read_key(CTR_KEY_PATH)
            cipher = AES.new(ctr_key, AES.MODE_CTR, nonce=nonce)
            ticket = parse_fields(cipher.decrypt(ciphertext).decode())
        except Exception:
            self.logger.log('ticket_rejected', remote=self.remote, reason='invalid_format')
            self.send('Ticket rejected: invalid format.')
            return

        if any(c not in ticket for c in ['version', 'target', 'cmd', 'expires']):
            self.logger.log('ticket_rejected', remote=self.remote, reason='missing_fields')
            self.send('Ticket rejected: missing fields.')
            return

        expires = datetime.datetime.strptime(ticket['expires'], '%d/%m/%Y %H:%M:%S')
        if expires < datetime.datetime.now():
            self.logger.log('ticket_rejected', remote=self.remote, reason='expired')
            self.send('Ticket rejected: expired.')
            return

        self.send('Decrypted ticket:')
        for k, v in ticket.items():
            self.send(f'  {k}: {v}')

        if ticket['cmd'] == 'read' and ticket['target'] == 'logs':
            self.send('Most recent events in the museum log:')
            for line in self.logger.tail(30):
                self.send('  ' + line.rstrip('\n'))
        elif ticket['cmd'] == 'read' and ticket['target'] == 'flag':
            self.send('Congratulations! You have solved our secret challenge. Here is your flag:\n')
            self.send('  ' + os.getenv('CTFORGE_INSTANCER_FLAG'))
        else:
            self.send('Command or target not supported.')


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    print(f'Listening on {HOST}:{PORT}')
    try:
        with ThreadedTCPServer((HOST, PORT), ChallengeHandler) as server:
            server.serve_forever()
    finally:
        logger.close()


if __name__ == '__main__':
    main()
