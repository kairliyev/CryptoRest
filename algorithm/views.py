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
                    "encrypted": encrypt_aes(enc, key),
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
                    "decrypted": decrypt_aes(enc, key),
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
                    "encrypted": des(enc, key)}
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
                    "decrypted": decrypt_des(enc, key)}
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "error": {
                    "error_type": "key size must be 8"
                }
            }, status=status.HTTP_400_BAD_REQUEST)
    # ---------DES----------


@api_view(http_method_names=['POST'])
def algorithmassymetric_rsa(request):
    text = request.data["text"]
    keyPair = RSA.generate(3072)

    pubKey = keyPair.publickey()
    # print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
    pubKeyPEM = pubKey.exportKey()
    # print(pubKeyPEM.decode('ascii'))

    # print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
    privKeyPEM = keyPair.exportKey()
    # print(privKeyPEM)

    msg = b'A message for encryption'
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(text.encode())
    # print("Encrypted:", binascii.hexlify(encrypted))

    return Response({
        "success": {
            "public_key": pubKeyPEM.decode('ascii'),
            "rsa_private_key": privKeyPEM.decode('ascii'),
            "encrypted": binascii.hexlify(encrypted)}
    }, status=status.HTTP_200_OK)


@api_view(http_method_names=['POST'])
def algorithmassymetric_dsa(request):
    pass


class AlgorithmList(ListCreateAPIView):
    serializer_class = AlgorithmListSerializers

    def get_queryset(self):
        return AlgorithmTypes.objects.all()


class CipherList(RetrieveUpdateDestroyAPIView):
    serializer_class = CipherSerializers

    def get_object(self):
        return CipherInstructions.objects.get(id=self.kwargs['pk'])
