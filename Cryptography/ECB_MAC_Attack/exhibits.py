import string
import datetime

ALPHABET = string.ascii_uppercase
PLAINTEXTS_FILE = 'plaintexts.txt'


def load_plaintexts(path):
    with open(path) as f:
        plaintexts = []
        for line in f:
            normalized_line = ''.join(ch for ch in line.upper() if ch in ALPHABET + ' ')
            if len(normalized_line) > 0:
                plaintexts.append(normalized_line)
        return plaintexts


class SubstitutionExhibitHandler:
    @staticmethod
    def substitute(text, key):
        return ''.join(key.get(ch, ch) for ch in text)

    def __init__(self, req_handler):
        self.req_handler = req_handler
        self.plaintext = self.req_handler.rng.choice(load_plaintexts(PLAINTEXTS_FILE))
        shuffled = list(ALPHABET)
        self.req_handler.rng.shuffle(shuffled)
        key = {p: c for p, c in zip(ALPHABET, shuffled)}
        self.ciphertext = self.substitute(self.plaintext, key)
        self.guessed_key = {letter: '?' for letter in ALPHABET}

    def add_key_guess(self):
        ciphertext_letter = self.req_handler.recvline('Enter the ciphertext letter (A-Z): ').strip().upper()
        if len(ciphertext_letter) != 1 or ciphertext_letter not in ALPHABET:
            self.req_handler.send('Invalid letter. Try again.')
            return
        plaintext_letter = self.req_handler.recvline('Enter the corresponding plaintext letter (A-Z): ').strip().upper()
        if len(plaintext_letter) != 1 or plaintext_letter not in ALPHABET:
            self.req_handler.send('Invalid letter. Try again.')
            return
        self.guessed_key[ciphertext_letter] = plaintext_letter

    def delete_key_guess(self):
        ciphertext_letter = self.req_handler.recvline('Enter the ciphertext letter (A-Z): ').strip().upper()
        if len(ciphertext_letter) != 1 or ciphertext_letter not in ALPHABET:
            self.req_handler.send('Invalid letter. Try again.')
            return
        self.guessed_key[ciphertext_letter] = '?'

    def visit_exhibit(self):
        self.req_handler.logger.log('exhibit_visited', type='substitution', remote=self.req_handler.remote,
                                    name=self.req_handler.user_name)
        self.req_handler.send(
            f'Dear {self.req_handler.user_name}, welcome to the exhibit of the monoalphabetic substitution cipher!\n'
            'Your task is to decrypt the following ciphertext:\n\n'
            f'    {self.ciphertext}\n\n'
            'You can define mappings between ciphertext and plaintext letters and remove them.\n'
            'At every iteration, we show the plaintext resulting from applying the defined mappings,\n'
            'where "?" is used to replace ciphertext letters without a defined mapping.'
        )

        choice = '0'
        completed = False
        curr_plaintext = self.substitute(self.ciphertext, self.guessed_key)
        start_time = datetime.datetime.now()
        while choice != '3' and not completed:
            self.req_handler.send(
                '\n=== Substitution cipher exhibit ===\n'
                '1) Define a new mapping\n'
                '2) Delete an existing mapping\n'
                '3) Give up and leave the exhibit\n\n'
                f'Ciphertext: {self.ciphertext}\n'
                f'Plaintext:  {curr_plaintext}\n\n'
            )
            choice = self.req_handler.recvline('What would you like to do? (1-3)').strip()
            if choice == '1':
                self.add_key_guess()
            elif choice == '2':
                self.delete_key_guess()
            elif choice != '3':
                self.req_handler.send('Invalid option. Try again.')
            curr_plaintext = self.substitute(self.ciphertext, self.guessed_key)
            completed = self.plaintext == curr_plaintext
        if completed:
            elapsed_time = datetime.datetime.now() - start_time
            self.req_handler.logger.log('exhibit_solved', type='substitution', remote=self.req_handler.remote,
                                        name=self.req_handler.user_name, time=elapsed_time.total_seconds())
            self.req_handler.send(f'Congratulations! You solved the exhibit in {elapsed_time.total_seconds()} seconds.')
        else:
            self.req_handler.logger.log('exhibit_given_up', type='substitution', remote=self.req_handler.remote,
                                        name=self.req_handler.user_name)
            self.req_handler.send(f'You gave up.')
        self.req_handler.send(f'Plaintext:\n    {self.plaintext}')


class TranspositionExhibitHandler:
    @staticmethod
    def encrypt(plaintext, key):
        rows = []
        for i in range(0, len(plaintext), len(key)):
            row = plaintext[i:i + len(key)]
            rows.append(row)
        columns = [None for _ in range(len(key))]
        for idx, col in enumerate(key):
            columns[col - 1] = ''.join(row[idx] for row in rows)
        return ''.join(columns)

    @staticmethod
    def decrypt(ciphertext, key):
        num_rows = len(ciphertext) // len(key)
        grid = [['?'] * len(key) for _ in range(num_rows)]

        for idx_col, col in enumerate(key):
            if col is not None:
                part = ciphertext[(col-1) * num_rows:col * num_rows]
                for i in range(num_rows):
                    grid[i][idx_col] = part[i]
        plaintext = []
        for row in grid:
            plaintext.extend(row)
        return ''.join(plaintext)

    def __init__(self, req_handler):
        self.req_handler = req_handler
        key_size = self.req_handler.rng.randint(4, 9)
        self.key = list(range(1, key_size + 1))
        self.req_handler.rng.shuffle(self.key)

        plaintext = self.req_handler.rng.choice(load_plaintexts(PLAINTEXTS_FILE))
        if len(plaintext) % key_size != 0:
            plaintext = plaintext + ' ' * (key_size - len(plaintext) % key_size)
        self.plaintext = plaintext
        self.ciphertext = self.encrypt(self.plaintext, self.key)
        self.guessed_key = [None for _ in range(key_size)]

    def add_key_guess(self):
        try:
            key_idx = int(self.req_handler.recvline(f'Enter the position in the key (1-{len(self.key)}):').strip())
            if key_idx < 1 or key_idx > len(self.key):
                self.req_handler.send('Invalid value. Try again.')
                return
            key_val = int(self.req_handler.recvline(f'Enter the value at this position (1-{len(self.key)}): ').strip())
            if key_val < 1 or key_val > len(self.key):
                self.req_handler.send('Invalid value. Try again.')
                return
            self.guessed_key[key_idx-1] = key_val
        except ValueError:
            self.req_handler.send('Not a number. Try again.')

    def delete_key_guess(self):
        try:
            key_idx = int(self.req_handler.recvline(f'Enter the position in the key (1-{len(self.key)}): ').strip())
            if key_idx < 1 or key_idx > len(self.key):
                self.req_handler.send('Invalid value. Try again.')
                return
            self.guessed_key[key_idx-1] = None
        except ValueError:
            self.req_handler.send('Not a number. Try again.')

    def print_table(self, current_plaintext):
        key_len = len(self.guessed_key)
        table = [list(current_plaintext[idx:idx+key_len]) for idx in range(0, len(current_plaintext), key_len)]

        key_line = ' '.join('?' if ke is None else str(ke) for ke in self.guessed_key)
        self.req_handler.send("Key:  " + key_line)
        for idx, row in enumerate(table):
            line = ('      ' if idx != 0 else 'Text: ') + ' '.join(row)
            self.req_handler.send(line)

    def visit_exhibit(self):
        self.req_handler.logger.log('exhibit_visited', type='substitution', remote=self.req_handler.remote,
                             name=self.req_handler.user_name)
        self.req_handler.send(
            f'Dear {self.req_handler.user_name}, welcome to the exhibit of the transposition cipher!\n'
            'Your task is to decrypt the following ciphertext:\n\n'
            f'    {self.ciphertext}\n\n'
            'The length of the key is fixed and cannot be changed.\n'
            'You can assign numbers and remove numbers associated to each key position.'
        )

        choice = '0'
        completed = False
        curr_plaintext = self.decrypt(self.ciphertext, self.guessed_key)
        start_time = datetime.datetime.now()
        while choice != '3' and not completed:
            self.req_handler.send(
                '\n=== Transposition cipher exhibit ===\n'
                '1) Assign a value to a key position\n'
                '2) Delete the value assigned to a key position\n'
                '3) Give up and leave the exhibit\n\n'
                f'Ciphertext: {self.ciphertext}\n'
                f'Plaintext:  {curr_plaintext}\n\n'
            )
            self.print_table(curr_plaintext)
            choice = self.req_handler.recvline('What would you like to do? (1-3)').strip()
            if choice == '1':
                self.add_key_guess()
            elif choice == '2':
                self.delete_key_guess()
            elif choice != '3':
                self.req_handler.send('Invalid option. Try again.')
            curr_plaintext = self.decrypt(self.ciphertext, self.guessed_key)
            completed = self.plaintext == curr_plaintext
        if completed:
            elapsed_time = datetime.datetime.now() - start_time
            self.req_handler.logger.log('exhibit_solved', remote=self.req_handler.remote,
                                        name=self.req_handler.user_name, time=elapsed_time.total_seconds())
            self.req_handler.send(f'Congratulations! You solved the exhibit in {elapsed_time.total_seconds()} seconds.')
        else:
            self.req_handler.logger.log('exhibit_given_up', type='substitution', remote=self.req_handler.remote,
                                        name=self.req_handler.user_name)
            self.req_handler.send(f'You gave up.')
        self.req_handler.send(f'Plaintext:\n    {self.plaintext}')
