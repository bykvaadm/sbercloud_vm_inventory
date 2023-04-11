import hashlib
import hmac
import binascii
from datetime import datetime
from yarl import URL
import requests


def hmacsha256(keyByte, message):
    return hmac.new(
        keyByte.encode("utf-8"), message.encode("utf-8"), digestmod=hashlib.sha256
    ).digest()


def hex_encode_sha256_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


class Signer:
    basic_date_format = "%Y%m%dT%H%M%SZ"
    algorithm = "SDK-HMAC-SHA256"
    header_x_date = "X-Sdk-Date"
    header_host = "host"
    header_authorization = "Authorization"
    header_content_sha256 = "x-sdk-content-sha256"

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        method: str,
        url: str,
        headers: dict = None,
        body: str = "",
    ):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.method = method
        self.url = URL(url)
        self.headers = headers if headers else {}
        self.body = body.encode("utf-8")

    def get_canonical_headers(self, signed_headers: list[str]):
        a = []
        __headers = {}
        for key in self.headers:
            key_encoded = key.lower()
            value = self.headers[key]
            value_encoded = value.strip()
            __headers[key_encoded] = value_encoded

            self.headers[key] = value_encoded.encode("utf-8").decode("iso-8859-1")
        for key in signed_headers:
            a.append(key + ":" + __headers[key])
        return "\n".join(a) + "\n"

    def auth_header_value(self, signature, signed_headers: list[str]):
        return (
            f"{self.algorithm} Access={self.access_key_id}, SignedHeaders={';'.join(signed_headers)},"
            f" Signature={signature}"
        )

    def find_header(self, header: str):
        for k in self.headers:
            if k.lower() == header.lower():
                return self.headers[k]
        return None

    def get_signed_headers(self):
        return list(sorted([key.lower() for key in self.headers]))

    def sign(self):
        header_time = self.find_header(self.header_x_date)
        if header_time is None:
            t = datetime.utcnow()
            self.headers[self.header_x_date] = datetime.strftime(
                t, self.basic_date_format
            )
        else:
            t = datetime.strptime(header_time, self.basic_date_format)

        if not any(
            map(lambda header_key: header_key.lower() == "host", self.headers.keys())
        ):
            self.headers["host"] = self.url.host
        signed_headers = self.get_signed_headers()
        canonical_request = self.get_canonical_request(signed_headers)
        string_to_sign = self.get_string_to_sign(canonical_request, t)
        signature = self.sign_str_to_sign(string_to_sign)
        auth_value = self.auth_header_value(signature, signed_headers)
        self.headers[self.header_authorization] = auth_value
        self.headers["content-length"] = str(len(self.body))

    def sign_str_to_sign(self, string_to_sign):
        hm = hmacsha256(self.secret_access_key, string_to_sign)
        return binascii.hexlify(hm).decode()

    def get_canonical_request(self, signed_headers: list[str]):
        canonical_headers = self.get_canonical_headers(signed_headers)
        encoded_hex = self.find_header(self.header_content_sha256)
        return (
            f"{self.method.upper()}\n{self.get_canonical_uri()}\n{self.get_canonical_query_string()}"
            f"\n{canonical_headers}\n{';'.join(signed_headers)}\n"
            f"{encoded_hex if encoded_hex else hex_encode_sha256_hash(self.body)}"
        )

    def get_string_to_sign(self, canonical_request, time):
        return (
            f"{self.algorithm}\n{datetime.strftime(time, self.basic_date_format)}\n"
            f"{hex_encode_sha256_hash(canonical_request.encode('utf-8'))}"
        )

    def get_canonical_uri(self):
        return self.url.path + "/" if not self.url.path.endswith("/") else self.url.path

    def get_canonical_query_string(self):
        keys = sorted(self.url.query)
        return "&".join([f"{key}={self.url.query.get(key)}" for key in keys])

    def gen_next_page(self):
        page = 1
        while page:
            self.url = self.url.with_query({"offset": page, "limit": 15})
            self.sign()
            response = requests.request(
                self.method, self.url, headers=self.headers, data=self.body
            )
            self.headers.pop("Authorization")
            response_data = response.json()
            page = page + 1 if response_data["servers"] else None
            yield response_data
