import unittest
import jwt
import os
from pyjwt import sign_token, verify_token

class TestJWTMethods(unittest.TestCase):

    def setUp(self):
        self.payload = {"data": "test"}
        self.base_64_secret_key = os.environ.get('JWT_PRIVATE_KEY')
        self.secret_key = self.base_64_secret_key.encode('utf-8')
        self.token = jwt.encode(self.payload, self.secret_key, algorithm='HS256')

    def test_sign_token(self):
        token = sign_token(self.payload)
        self.assertIsNotNone(token)

    def test_verify_token(self):
        payload = verify_token(self.token)
        self.assertEqual(payload, self.payload)

    def test_verify_token_expired(self):
        expired_token = jwt.encode({ "exp": -1, "data": "tests" }, self.secret_key, algorithm='HS256')
        payload = verify_token(expired_token)
        self.assertIsNone(payload)

if __name__ == '__main__':
    unittest.main()