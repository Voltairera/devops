# leader logs proof of concept - all credit goes to @andrewwestberg of BCSH for the algo extraction from cardano-node

import math
import binascii
from datetime import datetime, timezone 
import time
import pytz
import hashlib
from ctypes import *
from urllib.request import urlopen
import requests
import json
from lxml import etree
import os
import argparse

parser = argparse.ArgumentParser(description="Calculate the leadership log.")
parser.add_argument('--vrf-skey', dest='skey', help='provide the path to the pool.vrf.skey file', required=True)
parser.add_argument('--sigma', dest='sigma', type=float, help='the controlled stake sigma value of the pool [e.g. 0.0034052348379780869]')
parser.add_argument('--pool-id', dest='poolId', help='the pool ID')
parser.add_argument('--epoch', dest='epoch', type=int, help='the epoch number [e.g. 221]')
parser.add_argument('--epoch-nonce', dest='eta0', help='the epoch nonce to check')
parser.add_argument('--d-param', dest='d', type=float, help='the current decentralization parameter [e.g. 0.0 - 1.0]')
args = parser.parse_args()

url = 'https://epoch-api.crypto2099.io:2096/epoch'
try:
    args.epoch
except NameError:
    print("No epoch provided. Using current epoch")
else:
    url = url + "/" + str(args.epoch)

# {"number":222,"eta0":"171625aef5357dfccfeaeedecd5de49f71fb6e05953f2799d3ff84419dbef0ac","magic":764824073,"d":0.6}
# epoch_data = json.loads(urlopen(url).read().decode("utf-8"))
epoch_data = {"number":222,"eta0":"171625aef5357dfccfeaeedecd5de49f71fb6e05953f2799d3ff84419dbef0ac","magic":764824073,"d":0.6}

epoch = epoch_data['number']
poolId = 'a10865dae2d543ee9f13e98bff70ea81565bb6e4343b15b765f78174'
eta0 = epoch_data['eta0']
decentralizationParam = epoch_data['d']
sigma = 0.008490722547355082
poolVrfSkeyFile = args.skey

with open(poolVrfSkeyFile) as f:
    skey = json.load(f)

poolVrfSkey = skey['cborHex'][4:]

# Bindings are not avaliable so using ctypes to just force it in for now.
libsodium = cdll.LoadLibrary("../cardano-wallet-macos/libsodium.23.dylib")
libsodium.sodium_init()

# Hard code these for now.
epochLength = 432000
activeSlotCoeff = 0.05
slotLength = 1
epoch211firstslot = 5788800
epoch211firstslottime = 1586814291

# more hard coded values
local_tz = pytz.timezone('Europe/Amsterdam') # use your local timezone name here
firstSlotOfEpoch = epoch211firstslot + (epoch - 211)*epochLength
firstSlotOfEpochTime = epoch211firstslottime + (epoch - 211)*epochLength*slotLength

def getBlockMinter(epoch, slot):
    url = 'https://cardanoscan.io/block?epoch='+ str(epoch) + '&slot=' + str(slot)
    headers = {'Content-Type': 'text/html'}    
    response = requests.get(url, headers=headers)
    html = response.text
    tree = etree.HTML(html)
    pool = tree.xpath('/html/body/div[2]/main/div/div/div[2]/div/div/div/div/div[2]/div[2]/div[2]/div/a/text()')
    return str(pool)



def isOverlaySlot(firstSlotOfEpoch, currentSlot, decentralizationParam):
   diff_slot = float(currentSlot - firstSlotOfEpoch)
   if math.ceil( diff_slot * decentralizationParam ) < math.ceil( (diff_slot + 1) * decentralizationParam ):
      return True
   return False

def mkSeed(slot,eta0):

    h = hashlib.blake2b(digest_size=32)
    h.update(bytearray([0,0,0,0,0,0,0,1])) #neutral nonce
    seedLbytes=h.digest()

    h = hashlib.blake2b(digest_size=32)
    h.update(slot.to_bytes(8,byteorder='big') + binascii.unhexlify(eta0))
    slotToSeedBytes = h.digest()

    seed = [x ^ slotToSeedBytes[i] for i,x in enumerate(seedLbytes)]

    return bytes(seed)

def vrfEvalCertified(seed, tpraosCanBeLeaderSignKeyVRF):
    if isinstance(seed, bytes) and isinstance(tpraosCanBeLeaderSignKeyVRF, bytes):
        proof = create_string_buffer(libsodium.crypto_vrf_ietfdraft03_proofbytes())

        libsodium.crypto_vrf_prove(proof, tpraosCanBeLeaderSignKeyVRF,seed, len(seed))

        proofHash = create_string_buffer(libsodium.crypto_vrf_outputbytes())

        libsodium.crypto_vrf_proof_to_hash(proofHash,proof)

        return proofHash.raw

    else:
        print("error.  Feed me bytes")
        exit()


# Determine if our pool is a slot leader for this given slot
# @param slot The slot to check
# @param activeSlotCoeff The activeSlotsCoeff value from protocol params
# @param sigma The controlled stake proportion for the pool
# @param eta0 The epoch nonce value
# @param poolVrfSkey The vrf signing key for the pool

def isSlotLeader(slot,activeSlotCoeff,sigma,eta0,poolVrfSkey):
    seed = mkSeed(slot, eta0)
    tpraosCanBeLeaderSignKeyVRFb = binascii.unhexlify(poolVrfSkey)
    cert=vrfEvalCertified(seed,tpraosCanBeLeaderSignKeyVRFb)
    certNat  = int.from_bytes(cert, byteorder="big", signed=False)
    certNatMax = math.pow(2,512)
    denominator = certNatMax - certNat
    q = certNatMax / denominator
    c = math.log(1.0 - activeSlotCoeff)
    sigmaOfF = math.exp(-sigma * c)
    return q <= sigmaOfF


slotcount=0
previousSlot = 0
outputFilename = str(epoch) + "-leader-schedule.csv"
if os.path.exists(outputFilename):
  os.remove(outputFilename)
f = open(outputFilename, "a")
f.write("blockNo,slotOfEpoch,dateTime,timeSinceLast,mintedBy\n")
now = datetime.now(tz=local_tz)

for slot in range(firstSlotOfEpoch,epochLength+firstSlotOfEpoch):
    if isOverlaySlot(firstSlotOfEpoch,slot,decentralizationParam):
        continue

    slotLeader = isSlotLeader(slot,activeSlotCoeff,sigma,eta0,poolVrfSkey)
    if slotLeader:
        slotcount+=1
        timeSinceLast = time.strftime('%H:%M:%S', time.gmtime((slot - previousSlot)*slotLength))
        previousSlot = slot
        timestamp = datetime.fromtimestamp(slot*slotLength + firstSlotOfEpochTime, tz=local_tz)
        blockMinter = "Future block"
        if now > timestamp:
            blockMinter = getBlockMinter(epoch, slot-firstSlotOfEpoch)
        f.write(str(slotcount) + "," +str(slot-firstSlotOfEpoch) + "," + timestamp.strftime('%Y-%m-%d %H:%M:%S') +  "," + timeSinceLast + "," + blockMinter + "\n")
        print(str(slotcount) + "," +str(slot-firstSlotOfEpoch) + "," + timestamp.strftime('%Y-%m-%d %H:%M:%S') +  "," + timeSinceLast + "," + blockMinter)

f.close()


