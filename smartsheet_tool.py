#!/usr/bin/env python3
import os
import sys
import smartsheet

API_KEY_SALT = b'F\xd5\xe7d\xb7Z\xee\xc0\xf9\xf3\x95\xb7\xd8Iio'

class Crypto:
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Hash import SHA512
    from Crypto.Hash import HMAC
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    @staticmethod
    def pad(s):
        return s + (Crypto.AES.block_size - len(s) % Crypto.AES.block_size) \
            * bytes([Crypto.AES.block_size - len(s) % Crypto.AES.block_size])

    @staticmethod
    def unpad(s):
        return s[0:-s[-1]]

class ApiKey:
    def __init__(self, password):
        self.key, self.iv = self.derive_key(password)

    def derive_key(self, password):
        material = Crypto.PBKDF2(password,
                API_KEY_SALT,
                max(Crypto.AES.key_size) + Crypto.AES.block_size,
                count=1000, prf=lambda p, s: Crypto.HMAC.new(p, s, Crypto.SHA512).digest())
        key = material[:max(Crypto.AES.key_size)]
        iv = material[max(Crypto.AES.key_size):]
        return key, iv

    def encrypted_api_key(self, api_key):
        return Crypto.AES.new(self.key, Crypto.AES.MODE_CBC, self.iv).encrypt(Crypto.pad(api_key.encode('ascii')))

    def api_key(self, encrypted_api_key):
        return Crypto.unpad(Crypto.AES.new(self.key, Crypto.AES.MODE_CBC, self.iv).decrypt(encrypted_api_key)).decode('ascii')

class SmartsheetTool:
    def __init__(self, name, password=None, api_key=None, encrypted_api_key=None, api_key_file=None, encrypted_api_key_file=None):
        if api_key_file:
            with open(api_key_file, 'r') as f:
                api_key = f.read()
        if encrypted_api_key_file:
            with open(encrypted_api_key_file, 'rb') as f:
                encrypted_api_key = f.read()

        if (api_key and (password or encrypted_api_key)) or (not api_key and not (password and encrypted_api_key)):
            raise ValueError('Must provide either api_key or (encrypted_api_key and password)')
        if api_key:
            self.smartsheet = smartsheet.Smartsheet(access_token=api_key)
        else:
            self.smartsheet = smartsheet.Smartsheet(access_token=ApiKey(password).api_key(encrypted_api_key))

        self.smartsheet.errors_as_exceptions()
        self.sheet = self.smartsheet.Sheets.get_sheet_by_name(name)
        self.changes = {}

    def column(self, column):
        return self.sheet.columns[column]

    def column_title(self, column):
        return self.column(column).title

    def num_columns(self):
        return len(self.sheet.columns)

    def num_rows(self):
        return len(self.sheet.rows)

    def at(self, row, column):
        return self.sheet.rows[row].cells[column]

    def value_at(self, row, column):
        return self.at(row, column).value

    def assign_value(self, row, column, value):
        if row not in self.changes:
            self.changes[row] = {column: value}
        else:
            self.changes[row].update({column: value})

    def clear(self):
        self.changes = {}

    def refresh(self):
        if self.changes:
            raise ValueError('Cannot refresh while there are changes.')
        self.sheet = self.smartsheet.Sheets.get_sheet(self.sheet.id)

    def sort(self, column, direction):
        if self.changes:
            raise ValueError('Cannot sort while there are changes.')

        if type(column) is str:
            column_id = None
            for c in self.sheet.columns:
                if c.title == column:
                    column_id = c.id
                    break
                if c.title.lower() == column.lower():
                    column_id = c.id
            if not column_id:
                raise ValueError('No such column {}'.format(column_id))
        else:
            column_id = self.column(column).id

        self.sheet = self.smartsheet.Sheets.sort_sheet(
            self.sheet.id, smartsheet.models.SortSpecifier(
            {
                'sort_criteria': [smartsheet.models.SortCriterion({
                    'column_id': column_id,
                    'direction': direction.upper()
                })]
            }
        ))

    def save(self):
        updates = []

        for row, changes in self.changes.items():
            new_row = self.smartsheet.models.Row()
            new_row.id = self.sheet.rows[row].id

            for column, value in changes.items():
                new_cell = self.smartsheet.models.Cell()
                new_cell.column_id = self.at(row, column).column_id
                new_cell.value = value
                new_row.cells.append(new_cell)

            updates.append(new_row)

        self.smartsheet.Sheets.update_rows(self.sheet.id, updates)
        self.changes = {}
