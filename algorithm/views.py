import binascii

from django.shortcuts import render
from algorithm.models import AlgorithmTypes, CipherInstructions
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from html import unescape
from algorithm.serializers import *
from django.http import HttpResponse
import base64
import json

from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii


def encrypt_aes(aess, key):
    import pyaes
    aes = pyaes.AESModeOfOperationCTR(key.encode())
    ciphertext = aes.encrypt(aess)
    aes = pyaes.AESModeOfOperationCTR(key.encode())
    detext = aes.decrypt(ciphertext)
    return binascii.hexlify(ciphertext)


def decrypt_aes(text, key):
    import pyaes
    aes = pyaes.AESModeOfOperationCTR(key.encode())
    detext = aes.decrypt(binascii.unhexlify(text))
    return detext


def des(text, key):
    from pyDes import des
    from pyDes import CBC
    from pyDes import PAD_PKCS5
    # d = des(key)
    # ciphered = d.encrypt(key, text)
    # plain = d.decrypt(key, ciphered)
    # return str(ciphered)
    data = "Please encrypt my data"
    k = des(key, CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
    d = k.encrypt(text)
    print("Encrypted: %r" % d)
    print("Decrypted: %r" % k.decrypt(d))
    return binascii.hexlify(d)


def decrypt_des(encrypted_text, key):
    from pyDes import des
    from pyDes import CBC
    from pyDes import PAD_PKCS5
    k = des(key, CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
    return k.decrypt(binascii.unhexlify(encrypted_text))


def cipherFormFilter(type):
    a = CipherInstructions.objects.get(algorithm_option__exact=type).form

    # a = a.replace("\r\n", " ")

    if a is None:
        return " "
    else:
        return a


@api_view(http_method_names=['POST'])
def algorithmsymmetric(request):
    enc = request.data["text"]
    type = request.data["type"]
    key = request.data["key"]
    # --------AES---------
    if type == "e_aes":
        if len(str(key)) == 32:
            return Response({
                "success": {
                    "text": request.data["text"],
                    "type": request.data["type"],
                    "output": encrypt_aes(enc, key),
                    "form": cipherFormFilter(request.data["type"])
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "error": {
                    "error_type": "key size must be 32"
                }
            }, status=status.HTTP_400_BAD_REQUEST)
    elif type == "d_aes":
        if len(str(key)) == 32:
            return Response({
                "success": {
                    "text": request.data["text"],
                    "type": request.data["type"],
                    "output": decrypt_aes(enc, key),
                    "form": cipherFormFilter(request.data["type"])
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "error": {
                    "error_type": "key size must be 32"
                }
            }, status=status.HTTP_400_BAD_REQUEST)
    # --------AES----------

    # ---------DES----------
    elif type == "e_des":
        if len(str(key)) == 8:
            return Response({
                "success": {
                    "text": request.data["text"],
                    "type": type,
                    "output": des(enc, key),
                    "form": cipherFormFilter(type)
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "error": {
                    "error_type": "key size must be 8"
                }
            }, status=status.HTTP_400_BAD_REQUEST)
    elif type == "d_des":
        if len(str(key)) == 8:
            return Response({
                "success": {
                    "text": request.data["text"],
                    "type": type,
                    "output": decrypt_des(enc, key),
                    "form": cipherFormFilter(type)
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "error": {
                    "error_type": "key size must be 8"
                }
            }, status=status.HTTP_400_BAD_REQUEST)
    # ---------DES----------


@api_view(http_method_names=['POST'])
def algorithmassymetric(request):
    text = request.data["text"]
    type = request.data["type"]

    if type == "rsa":
        return algorithmassymetric_rsa(request)
    elif type == "ecc":
        return algorithmassymetric_ecc(request)


def algorithmassymetric_rsa(request):
    text = request.data["text"]
    keyPair = RSA.generate(3072)
    print(keyPair)
    pubKey = keyPair.publickey()
    # print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
    pubKeyPEM = pubKey.exportKey()
    # print(pubKeyPEM.decode('ascii'))

    # print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
    privKeyPEM = keyPair.exportKey()
    # print(privKeyPEM)

    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(text.encode())
    # print("Encrypted:", binascii.hexlify(encrypted))

    decryptor = PKCS1_OAEP.new(keyPair)
    decrypted = decryptor.decrypt(encrypted)
    print(decryptor)
    print('Decrypted:', decrypted)

    out = "public key: %s \n rsa_private_key: %s \n encrypted: %s \n" % (
    str(pubKeyPEM.decode('ascii')), str(privKeyPEM.decode('ascii')), binascii.hexlify(encrypted))

    if len(str(text)) > 0:
        return Response({
            "success": {
                "text": text,
                "type": request.data["type"],
                "output": out,
                "form": cipherFormFilter(request.data["type"])
            }}, status=status.HTTP_200_OK)


def algorithmassymetric_ecc(request):
    msg = request.data["text"].encode()

    def encrypt_AES_GCM(msg, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
        return (ciphertext, aesCipher.nonce, authTag)

    def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext

    def ecc_point_to_256_bit_key(point):
        sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
        sha.update(int.to_bytes(point.y, 32, 'big'))
        return sha.digest()

    curve = registry.get_curve('brainpoolP256r1')

    def encrypt_ECC(msg, pubKey):
        ciphertextPrivKey = secrets.randbelow(curve.field.n)
        sharedECCKey = ciphertextPrivKey * pubKey
        secretKey = ecc_point_to_256_bit_key(sharedECCKey)
        ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
        ciphertextPubKey = ciphertextPrivKey * curve.g
        return (ciphertext, nonce, authTag, ciphertextPubKey)

    def decrypt_ECC(encryptedMsg, privKey):
        (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
        sharedECCKey = privKey * ciphertextPubKey
        secretKey = ecc_point_to_256_bit_key(sharedECCKey)
        plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
        return plaintext

    print("original msg:", msg)
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g

    encryptedMsg = encrypt_ECC(msg, pubKey)
    # encryptedMsgObj = {
    #     'ciphertext': binascii.hexlify(encryptedMsg[0]) + '\n',
    #     'nonce': binascii.hexlify(encryptedMsg[1]) + '\n',
    #     'authTag': binascii.hexlify(encryptedMsg[2])+ '\n',
    #     'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:] + '\n'
    # }

    out = "ciphertext: %s \n nonse: %s \n, authTag: %s \n, ciphertextPubkey: %s" % (str(binascii.hexlify(encryptedMsg[0])), binascii.hexlify(encryptedMsg[1]), binascii.hexlify(encryptedMsg[2]), str(hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]))
    # print("encrypted msg:", encryptedMsgObj)

    decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
    print("decrypted msg:", decryptedMsg)

    if len(str(msg, 'utf-8')) > 0:
        return Response({
            "success": {
                "text": request.data["text"],
                "type": request.data["type"],
                "output": str(out),
                "form": cipherFormFilter(request.data["type"])
        }}, status=status.HTTP_200_OK)
    else:
        return Response({
            "error": {
                "error_type": "text is empty"
            }
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(http_method_names=['POST'])
def basics(request):
    text = request.data["text"]
    type = request.data["type"]

    if type == "e_binary":
        return e_binary(request)
    elif type == "d_binary":
        return d_binary(request)
    elif type == "e_caesar":
        return e_caesar(request)
    elif type == "d_caesar":
        return d_caesar(request)
    elif type == "e_vigenere":
        return e_vigenere(request)
    elif type == "d_vigenere":
        return d_vigenere(request)


class AlgorithmList(ListCreateAPIView):
    serializer_class = AlgorithmListSerializers

    def get_queryset(self):
        return AlgorithmTypes.objects.all()


class CipherList(ListCreateAPIView):
    serializer_class = CipherListSerializers

    def get_queryset(self):
        return CipherInstructions.objects.filter(algorithm_class_id__exact=self.kwargs["pk"])


@api_view(http_method_names=['POST'])
def hash_functions(request):
    text = request.data["text"]
    data = text.encode("utf8")

    sha256hash = hashlib.sha256(data).digest()
    print("SHA-256:   ", binascii.hexlify(sha256hash))

    sha3_256 = hashlib.sha3_256(data).digest()
    print("SHA3-256:  ", binascii.hexlify(sha3_256))

    blake2s = hashlib.new('blake2s', data).digest()
    print("BLAKE2s:   ", binascii.hexlify(blake2s))

    ripemd160 = hashlib.new('ripemd160', data).digest()
    print("RIPEMD-160:", binascii.hexlify(ripemd160))

    out = "SHA-256: %s \n SHA3-256: %s \n BLAKE2s: %s \n RIPEMD-160: %s \n " % (binascii.hexlify(sha256hash), binascii.hexlify(sha3_256), binascii.hexlify(blake2s), binascii.hexlify(ripemd160))

    if len(text.encode("utf8")) > 0:
        return Response({
            "success": {
                "text": request.data["text"],
                "type": request.data["type"],
                "output": str(out),
                "form": cipherFormFilter(request.data["type"])
            }}, status=status.HTTP_200_OK)
    else:
        return Response({
            "error": {
                "error_type": "text is empty"
            }
        }, status=status.HTTP_400_BAD_REQUEST)


def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return int2bytes(n).decode(encoding, errors)


def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


def e_binary(request):
    text = request.data["text"]
    type = request.data["type"]

    b = text_to_bits(text)
    return Response({
        "success": {
            "text": text,
            "type": type,
            "output": str(b),
            "form": cipherFormFilter("e_binary")
        }
    }, status=status.HTTP_200_OK)


def d_binary(request):
    text = request.data["text"]
    type = request.data["type"]

    c = text_from_bits(text)
    return Response({
        "success": {
            "text": request.data["text"],
            "type": type,
            "output": str(c),
            "form": cipherFormFilter(request.data["type"])
        }
    }, status=status.HTTP_200_OK)


def e_caesar(request):
    text = request.data["text"]
    type = request.data["type"]

    key = 'abcdefghijklmnopqrstuvwxyz'
    result = ''

    n = 3

    for l in text.lower():
        try:
            i = (key.index(l) + n) % 26
            result += key[i]
        except ValueError:
            result += l

    return Response({
        "success": {
            "text": request.data["text"],
            "type": type,
            "output": str(result.lower()),
            "form": cipherFormFilter(request.data["type"])
        }
    }, status=status.HTTP_200_OK)


def d_caesar(request):
    text = request.data["text"]
    type = request.data["type"]

    key = 'abcdefghijklmnopqrstuvwxyz'
    result = ''

    n = 3

    for l in text:
        try:
            i = (key.index(l) - n) % 26
            result += key[i]
        except ValueError:
            result += l

    return Response({
        "success": {
            "text": request.data["text"],
            "type": type,
            "output": str(result),
            "form": cipherFormFilter(request.data["type"])
        }
    }, status=status.HTTP_200_OK)


def e_vigenere(request):
    string = request.data["text"]
    type = request.data["type"]

    string = string.upper()
    keyword = "AYUSH"
    key = generateKey(string, keyword)
    cipher_text = cipherText(string, key)

    return Response({
        "success": {
            "text": request.data["text"],
            "type": type,
            "output": str(cipher_text.lower()),
            "form": cipherFormFilter(request.data["type"])
        }
    }, status=status.HTTP_200_OK)


def d_vigenere(request):
    string = request.data["text"]
    type = request.data["type"]

    string = string.upper()
    keyword = "AYUSH"
    key = generateKey(string, keyword)
    cipher_text = string

    return Response({
        "success": {
            "text": request.data["text"],
            "type": type,
            "output": str(originalText(string, key).lower()),
            "form": cipherFormFilter(request.data["type"])
        }
    }, status=status.HTTP_200_OK)


def generateKey(string, key):
    key = list(key)
    if len(string) == len(key):
        return (key)
    else:
        for i in range(len(string) -
                       len(key)):
            key.append(key[i % len(key)])
    return ("".join(key))


def cipherText(string, key):
    cipher_text = []
    for i in range(len(string)):
        x = (ord(string[i]) +
             ord(key[i])) % 26
        x += ord('A')
        cipher_text.append(chr(x))
    return ("".join(cipher_text))


def originalText(cipher_text, key):
    orig_text = []
    for i in range(len(cipher_text)):
        x = (ord(cipher_text[i]) -
             ord(key[i]) + 26) % 26
        x += ord('A')
        orig_text.append(chr(x))
    return ("".join(orig_text))
