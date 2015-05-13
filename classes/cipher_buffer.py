

class CipherBuffer(object):

    def __init__(self):
        self._buffer = []

    def append(self, hashed_value, secret):
        if len(self._buffer) > 10:
            self._buffer.pop(0)
        self._buffer.append((hashed_value, secret))

    def retrieve_secret(self, hashed_value):
        for tpl in self._buffer:
            if hashed_value == tpl[0]:
                return tpl[1]
        else:
            return None

cipher_buffer = CipherBuffer()
