

class LastSecret(object):

    SECRET = 1

    def __init__(self):
        self._last_secret = []

    def set(self, hash_value, secret):
        if len(self._last_secret) > 10:
            self._last_secret.pop()
        self._last_secret.append((hash_value, secret))

    def get(self, hash_value):
        for index, tpl in enumerate(self._last_secret):
            if hash_value in tpl:
                return self._last_secret[index][self.SECRET]
        else:
            return None

last_secret = LastSecret()
