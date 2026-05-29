"""PII-exposure check.

Scans well-formed OFX for personally-identifiable / sensitive information
leaking into fields where it does not belong -- the bug-bounty fintech angle
is free-text memos and names echoing SSNs, full account numbers, and routing
numbers that should never travel in a statement export.

Detection classes:
- ``ssn``                     : SSN-shaped strings (NNN-NN-NNNN) in free text.
- ``itin``                    : a US Individual Taxpayer Identification Number --
                                an SSN-shaped value (NNN-NN-NNNN) whose area is
                                900-999 and whose middle group falls in the
                                IRS-assigned ranges -- a distinct piece of US tax
                                PII issued to people ineligible for an SSN.
                                Checked before the SSN detector so an ITIN is
                                named as the ITIN it is, not mislabelled "SSN".
- ``email_address``           : an RFC-5321-shaped email address (a ``local@domain``
                                with a dotted, registrable domain and a 2+ letter
                                TLD) in free text -- a direct, high-precision PII
                                leak (GDPR/CCPA "personal data") that should never
                                travel in a statement export.
- ``credit_card``             : a 13-19 digit run (allowing the conventional
                                space/dash grouping) that passes the Luhn
                                checksum -- a near-certain payment-card (PAN)
                                leak, PCI-DSS sensitive.
- ``iban``                    : an International Bank Account Number (ISO 13616)
                                whose country code, length, and mod-97 check
                                digits all validate -- a near-certain
                                international bank-account leak.
- ``lei``                     : a Legal Entity Identifier (ISO 17442) -- a 20-char
                                alphanumeric code (18-char entity portion + two
                                ISO 7064 mod-97-10 check digits) -- whose check
                                digits validate, a near-certain counterparty /
                                legal-entity disclosure.
- ``bic``                     : a Bank Identifier Code / SWIFT code (ISO 9362) --
                                an 8- or 11-char code (bank + ISO 3166-1 country
                                + location [+ branch]) -- whose structure, country
                                code, and location-code rules all validate, a
                                near-certain financial-institution disclosure.
- ``isin``                    : an International Securities Identification Number
                                (ISO 6166) -- a 12-char country-code + NSIN +
                                Luhn check digit -- whose check digit validates,
                                a near-certain securities-holding leak.
- ``cusip``                    : a CUSIP -- the 9-char US/Canada securities
                                identifier (8-char base + modulus-10 check
                                digit) -- whose check digit validates, a
                                near-certain securities-holding leak. A letter
                                is required in the base so a purely numeric
                                9-digit run is never confused with a routing
                                number.
- ``sedol``                    : a SEDOL -- the 7-char UK/Ireland securities
                                identifier (6-char base + weighted modulus-10
                                check digit) -- whose check digit validates, a
                                near-certain securities-holding leak. Vowels are
                                forbidden in the base and a letter is required so
                                a purely numeric 7-digit run is never confused
                                with a coincidental digit run.
- ``uk_sort_code``            : a UK sort code (the six-digit ``NN-NN-NN``
                                hyphenated routing code that identifies a UK
                                bank and branch) whose hyphenated structure and
                                assigned clearing-range prefix validate -- the
                                UK domestic equivalent of an ABA routing number,
                                and (paired with an account number) the data a
                                wire-fraud attacker needs.
- ``ca_routing_number``       : a Canadian routing number in its MICR cheque
                                presentation (``TTTTT-III`` -- a five-digit branch
                                transit number and a three-digit Payments Canada
                                institution number) whose hyphenated structure and
                                assigned institution number validate -- the
                                Canadian domestic equivalent of an ABA routing
                                number / UK sort code, the value an Interac
                                e-Transfer / EFT / PAD payment routes against.
- ``au_bsb``                  : an Australian BSB (Bank-State-Branch) code in its
                                canonical ``NNN-NNN`` presentation (a six-digit
                                routing code -- a bank/institution prefix, a state
                                identifier, and a branch) whose hyphenated structure
                                and assigned bank-prefix range validate -- the
                                Australian domestic equivalent of an ABA routing
                                number / UK sort code / Canadian routing number, the
                                value a BSB-and-account payment (BECS / PayTo /
                                direct entry) routes against.
- ``ifsc``                    : an Indian Financial System Code (the RBI-defined
                                11-character ``BBBB0BRANCH`` routing code -- a
                                four-letter bank code, a mandatory reserved ``0``,
                                and a six-character alphanumeric branch code) whose
                                structure validates -- the Indian domestic
                                equivalent of an ABA routing number / UK sort code /
                                Australian BSB, the value a NEFT / RTGS / IMPS
                                payment routes against.
- ``kr_giro``                 : a South Korean Giro number -- the 7-digit
                                payee-routing code (a 6-digit payee/biller block
                                plus one trailing mod-10 weighted check digit)
                                printed on Korean utility/tax bills in its
                                canonical ``NNNNN-NN`` (5-2) grouped form -- whose
                                hyphenated structure, non-zero payee block, and
                                public mod-10 weighted check digit all validate, a
                                near-certain South Korean biller-routing leak. The
                                hyphenated 5-2 split is distinct from every other
                                hyphenated detector (SSN's 3-2-4, the UK sort
                                code's 2-2-2, the Canadian routing number's 5-3,
                                the Australian BSB's 3-3) so the detectors never
                                collide.
- ``th_natid``                : a Thai national ID (เลขประจำตัวประชาชน) -- the
                                13-digit citizen identification number that is the
                                most common Thai PromptPay payee "proxy id" --
                                printed in its canonical ``N-NNNN-NNNNN-NN-N``
                                (1-4-5-2-1) grouped form, whose hyphenated
                                structure, 1-8 category digit, and public mod-11
                                weighted check digit all validate, a near-certain
                                Thai PII / PromptPay payment-routing leak. The
                                1-4-5-2-1 split is distinct from every other
                                hyphenated detector so they never collide; the
                                compact 13-digit run is reserved under the card /
                                account namespaces so the card scanner never
                                re-reports it.
- ``br_cpf``                  : a Brazilian CPF (Cadastro de Pessoas Físicas) --
                                the 11-digit individual taxpayer registry number
                                that is both a national tax id and the most common
                                Pix payee "chave" (key) -- printed in its canonical
                                ``NNN.NNN.NNN-NN`` (3.3.3-2 dotted-and-dashed) form,
                                whose dotted structure, all-same-digit rejection, and
                                two public mod-11 weighted check digits all validate,
                                a near-certain Brazilian PII / Pix payment-routing
                                leak. The dotted-and-dashed presentation is distinct
                                from every other detector -- it is the only one that
                                uses ``.`` separators -- so it never collides with the
                                hyphenated routing codes or the contiguous digit runs.
- ``clabe``                   : a Mexican CLABE (Clave Bancaria Estandarizada) --
                                the 18-digit standardized bank-account number
                                (3-digit bank code + 3-digit branch/plaza code +
                                11-digit account + 1 control digit) -- whose
                                non-zero bank code and mod-10 weighted control
                                digit both validate, a near-certain Mexican
                                bank-account leak. Checked before the generic
                                account-number run so a valid CLABE is named as
                                the account identifier it is.
- ``curp``                    : a Mexican CURP (Clave Única de Registro de
                                Población) -- the 18-character unique
                                population-registry identity key (four name
                                initials + a YYMMDD birth date + a sex marker + a
                                two-letter birth-state code + three consonants + a
                                homoclave + a mod-10 check digit) -- whose
                                structure, embedded birth date, registered state
                                code, and check digit all validate, a near-certain
                                Mexican identity-PII leak. Unlike the CLABE (18
                                digits) a CURP leads with four letters, so the two
                                18-character Mexican identifiers never collide; the
                                value encodes a named individual, so it is reported
                                as an identity disclosure, not an account leak.
- ``account_number``          : a long account-number-shaped digit run leaking
                                into a transaction name/memo.
- ``routing_number``          : a 9-digit run that passes the ABA weighted
                                checksum -- a near-certain routing-number leak.
- ``probable_routing_number`` : a 9-digit run that fails the ABA checksum. Most
                                likely a coincidental digit run (zip+4, EIN-like
                                value, order/phone number). Emitted at ``info``
                                severity to preserve visibility without raising a
                                high-severity false positive.

For investment (INVSTMTRS) statements the same free-text scan runs over the
transaction memo, and the security identifier (``UNIQUEID`` / CUSIP) is scanned
with a narrower rule -- SSN-shaped values and over-long digit runs only -- so a
legitimate 9-digit numeric CUSIP is never mistaken for a routing number.

All evidence is redacted before it leaves the scanner -- ferryman reports the
presence of a leak, not the secret itself.
"""

from __future__ import annotations

import re

from ferryman.findings import Finding
from ferryman.parsing import parse_statements

# SSN: NNN-NN-NNNN, optionally with spaces. Word-bounded to avoid matching
# inside longer digit runs.
_SSN_RE = re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")

# ITIN (US Individual Taxpayer Identification Number) candidate. An ITIN shares
# the SSN nine-digit ``NNN-NN-NNNN`` presentation exactly, so this matcher is
# deliberately identical to ``_SSN_RE``; the structural gate that distinguishes
# an ITIN from an SSN lives in ``_itin_valid`` (area always begins with ``9``,
# and the IRS-assigned middle-group ranges). The two detectors share the
# ``ssn`` dedupe namespace so a matched run is classified exactly once.
_ITIN_RE = re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b")
# IRS-assigned ITIN middle-group (4th-5th digit) ranges. An ITIN's area is
# always 900-999, and the middle group is drawn only from these ranges; the
# gaps (66-69, 89, 93) are reserved (89 and 93 for other IRS programs -- 93 is
# the ATIN range) and never assigned to a live ITIN. Gating the middle group to
# these ranges is the precision lever that keeps a coincidental 9XX-NN-NNNN
# token from being reported as an ITIN.
_ITIN_MIDDLE_RANGES = (
    (50, 65),
    (70, 88),
    (90, 92),
    (94, 99),
)

# Email address. A deliberately conservative, high-precision pattern -- the goal
# is near-zero false positives, not RFC-5322 completeness. We require:
#   - a local part of the common atom characters, not starting/ending with a dot;
#   - an ``@``;
#   - a domain of one or more dot-separated labels (each starting and ending with
#     an alphanumeric), ending in a top-level domain of at least two letters.
# The leading/trailing lookarounds keep an address embedded in a larger token
# (e.g. ``mailto:a@b.com`` or ``a@b.com.``) from over- or under-matching at the
# boundary. The ``@`` plus the dotted, letter-TLD domain makes this structurally
# unambiguous, so unlike the phone-shaped digit runs an email is safe to report
# at high precision with no checksum.
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"[A-Za-z0-9_%+\-]+(?:\.[A-Za-z0-9_%+\-]+)*"   # local part (dot-separated atoms)
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+"  # one or more domain labels
    r"[A-Za-z]{2,}"                                  # TLD: 2+ letters
    r"(?![A-Za-z0-9.\-])"
)
# Routing/ABA number: exactly 9 digits, word-bounded.
_ROUTING_RE = re.compile(r"\b\d{9}\b")
# Account-number-shaped run: 8+ consecutive digits in free text.
_ACCT_RE = re.compile(r"\b\d{8,}\b")

# Credit-card / PAN candidate: a 13-19 digit number, optionally written in the
# conventional groups of digits separated by a single space or hyphen
# (e.g. "4111 1111 1111 1111" or "4111-1111-1111-1111"). We bound the run with a
# non-digit lookaround so a card embedded in a longer digit blob is not partially
# matched. The full match may contain separators; the caller strips them before
# validating with Luhn.
_CARD_RE = re.compile(
    r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"
)
# Valid PAN lengths after stripping separators. Real card networks issue
# 13-19 digit numbers; we accept that whole range and let Luhn do the gating.
_CARD_MIN_LEN = 13
_CARD_MAX_LEN = 19

# ABA weighted-checksum coefficients, applied positionally to the 9 digits.
_ABA_WEIGHTS = (3, 7, 1, 3, 7, 1, 3, 7, 1)

# IBAN (ISO 13616) candidate. Two presentations are accepted:
#   - contiguous: a single 15-34 char run (e.g. DE89370400440532013000); and
#   - grouped:    space-separated blocks of up to four alphanumerics, the
#                 human-readable form (e.g. DE89 3704 0044 0532 0130 00).
# Both start with two letters (country code) and two digits (check digits). The
# run is bounded by a non-alphanumeric lookaround so an IBAN embedded in a longer
# blob is not partially matched. The grouped form requires each space to be
# *inside* a block sequence -- a trailing space followed by a normal word will
# not be swallowed, because a group is a run of alnum, not a single char. The
# caller strips spaces and validates country/length/mod-97 before reporting.
_IBAN_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[A-Za-z]{2}\d{2}"
    r"(?:"
    r"[A-Za-z0-9]{11,30}"            # contiguous BBAN
    r"|"
    r"[A-Za-z0-9]{0,2}(?: [A-Za-z0-9]{1,4}){2,8}"  # grouped (blocks of <=4)
    r")"
    r"(?![A-Za-z0-9])"
)
# Per-country total IBAN length (ISO 13616 registry). The mod-97 checksum alone
# does not prove an IBAN is real; pairing it with the registered length for the
# declared country code makes a coincidental alphanumeric run vanishingly
# unlikely to validate. Countries omitted here are simply not length-checked
# beyond the generic 15-34 range, so the registry can grow without code changes
# while still gating on country + checksum.
_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28,
    "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24,
    "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18,
    "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23,
    "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32,
    "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
    "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24,
    "XK": 20,
}
# Generic ISO 13616 bounds for country codes not in the registry table.
_IBAN_MIN_LEN = 15
_IBAN_MAX_LEN = 34

# LEI (ISO 17442 / Legal Entity Identifier) candidate: a 20-character run of an
# 18-character alphanumeric entity portion plus two trailing decimal check
# digits. The run is bounded by a non-alphanumeric lookaround so an LEI embedded
# in a longer alphanumeric blob is not partially matched, and the trailing
# ``\d{2}`` requires the two check positions to be decimal (they always are, by
# spec). The caller validates the ISO 7064 mod-97-10 check digits before
# reporting. LEIs are case-insensitive and conventionally upper-case.
_LEI_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{18}\d{2}(?![A-Za-z0-9])")
# LEIs are always exactly 20 characters (18 entity + 2 check digits).
_LEI_LEN = 20

# BIC / SWIFT (ISO 9362) candidate: an 8-character base -- four letters (the
# institution/bank code), two letters (an ISO 3166-1 alpha-2 country code), and a
# two-character alphanumeric location code -- optionally followed by a
# three-character alphanumeric branch code (total 11). The run is bounded by a
# non-alphanumeric lookaround so a BIC embedded in a longer alphanumeric blob is
# not partially matched. The match is deliberately UPPER-CASE only: a BIC is an
# ISO 9362 code always transmitted in upper case, while an all-letter BIC shape is
# otherwise dangerously easy to collide with an ordinary lower-case English word
# (e.g. "beneficiary" -> B-E-N-E-F[FI]-... ). Restricting the regex to upper case
# is the precision lever that keeps prose out of the BIC channel; the
# ``_bic_valid`` helper itself stays case-insensitive so it is safe to reuse. The
# caller validates the structure, the country code against the ISO 3166-1
# registry, and the ISO 9362 location-code rules before reporting.
_BIC_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![A-Za-z0-9])"
)
# A BIC is exactly 8 (bank + country + location) or 11 (+ branch) characters.
_BIC_LENGTHS = (8, 11)
# ISO 3166-1 alpha-2 country codes -- the set a BIC's 5th-6th characters must be
# drawn from. Gating on the registered country code (exactly as the IBAN gate
# does) is the primary precision lever that keeps an ordinary 8-letter word from
# being misread as a BIC: it must end in a real country code AND satisfy the
# location-code rules below. The list is the full ISO 3166-1 alpha-2 assignment.
_ISO_3166_1 = frozenset(
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ "
    "BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR "
    "CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR "
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU "
    "ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ "
    "LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ "
    "MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF "
    "PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI "
    "SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR "
    "TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW".split()
)

# ISIN (ISO 6166) candidate: a 12-character run of two letters (country / "XS"
# for international issues), nine alphanumeric NSIN characters, and one trailing
# Luhn check digit. The run is bounded by a non-alphanumeric lookaround so an
# ISIN embedded in a longer alphanumeric blob is not partially matched. The
# caller validates the ISO 6166 check digit before reporting.
_ISIN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}[A-Z0-9]{9}\d(?![A-Za-z0-9])")
# ISINs are always exactly 12 characters.
_ISIN_LEN = 12

# CUSIP (CUSIP Global Services / ISO 6166 NSIN for US & Canada) candidate: a
# 9-character run of an 8-character alphanumeric base plus one trailing decimal
# check digit. We deliberately require at least one LETTER in the base (the
# regex forces a letter somewhere in the first eight characters) so a purely
# numeric 9-digit run -- which belongs to the ABA routing-number space -- is
# never misclassified as a CUSIP. The run is bounded by a non-alphanumeric
# lookaround so a CUSIP embedded in a longer alphanumeric blob is not partially
# matched. The caller validates the CUSIP modulus-10 check digit before
# reporting. CUSIPs are case-insensitive and conventionally upper-case.
_CUSIP_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?=[A-Za-z0-9*@#]{8}\d)"        # 8-char base + 1 check digit, ...
    r"[A-Za-z0-9*@#]*[A-Za-z][A-Za-z0-9*@#]*\d"  # ... with a letter in the base
    r"(?![A-Za-z0-9])"
)
# CUSIPs are always exactly 9 characters (8 base + 1 check digit).
_CUSIP_LEN = 9
# CUSIP character-to-value table for the modulus-10 check digit. Digits map to
# themselves, letters A=10 ... Z=35, and the three legacy special characters
# carry their own fixed values.
_CUSIP_SPECIAL = {"*": 36, "@": 37, "#": 38}

# SEDOL (Stock Exchange Daily Official List -- the UK/Ireland NSIN, issued by the
# London Stock Exchange) candidate: a 7-character run of a 6-character base plus
# one trailing decimal check digit. SEDOLs deliberately exclude the vowels
# (A, E, I, O, U) from the base, which both defines them and sharply cuts the
# false-positive rate against random 7-char runs. We additionally require at
# least one LETTER in the base (modern post-2004 SEDOLs are alphanumeric and
# start with a letter) so a purely numeric 7-digit run -- a common coincidental
# value -- is never misclassified as a SEDOL. The run is bounded by a
# non-alphanumeric lookaround so a SEDOL embedded in a longer alphanumeric blob
# is not partially matched. The caller validates the SEDOL weighted check digit
# before reporting.
_SEDOL_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?=[0-9B-DF-HJ-NP-TV-Z]{6}\d)"          # 6 non-vowel base chars + check digit
    r"[0-9B-DF-HJ-NP-TV-Z]*[B-DF-HJ-NP-TV-Z][0-9B-DF-HJ-NP-TV-Z]*\d"  # letter in base
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# SEDOLs are always exactly 7 characters (6 base + 1 check digit).
_SEDOL_LEN = 7
# SEDOL positional weights, applied to the 6 base characters' values. The
# trailing check digit is not weighted.
_SEDOL_WEIGHTS = (1, 3, 1, 7, 3, 9)
# Vowels are never valid in a SEDOL base -- a defining structural rule.
_SEDOL_VOWELS = frozenset("AEIOU")

# UK sort code candidate: the canonical six-digit routing code written in three
# hyphen-separated pairs (``NN-NN-NN``, e.g. ``20-00-00`` for Barclays). The
# hyphenated presentation is the defining shape -- and the precision lever: it is
# distinct from any contiguous digit run, so it never collides with the
# account-number (``\d{8,}``), routing (``\d{9}``), or card scanners, and ordinary
# prose almost never contains an ``NN-NN-NN`` token. The run is bounded by a
# non-digit/non-hyphen lookaround so a sort code embedded in a longer
# digit-and-hyphen blob is not partially matched. A sort code has no published,
# self-contained check digit (the VocaLink modulus check requires the paired
# account number), so precision comes from the hyphenated structure plus the
# assigned clearing-range prefix below. The caller validates both before
# reporting.
_UK_SORT_CODE_RE = re.compile(r"(?<![\d-])\d{2}-\d{2}-\d{2}(?![\d-])")
# UK sort codes are issued from the clearing range whose leading pair is 01-97.
# 00 is unassigned; 98 and 99 are reserved (Bank of England / non-clearing and
# test ranges), and the all-zeros and all-nines values are never live sort codes.
# Gating the leading pair to the assigned range is the structural precision lever
# that keeps a coincidental NN-NN-NN token (a date written 12-05-26, a stylised
# reference) from being misread as a sort code.
_UK_SORT_FIRST_MIN = 1
_UK_SORT_FIRST_MAX = 97

# Canadian routing number candidate -- the MICR (cheque-encoding) presentation,
# written ``TTTTT-III``: a five-digit branch *transit* number, a hyphen, and a
# three-digit financial-*institution* number (the Payments Canada assigned bank
# id, e.g. 003 = RBC, 004 = TD, 010 = CIBC). This is the value a Canadian
# Interac e-Transfer / EFT / PAD payment is routed against -- the Canadian
# domestic equivalent of an ABA routing number or a UK sort code. The MICR
# hyphenated 5-3 shape is the defining presentation and the precision lever: it
# is distinct from any contiguous digit run, so it never competes with the
# account-number (``\d{8,}``), routing (``\d{9}``), or card scanners; it is also
# distinct from the UK sort code (a 2-2-2 split) and the SSN (a 3-2-4 split), so
# the three hyphenated detectors never collide. The run is bounded by a
# non-digit/non-hyphen lookaround so a routing number embedded in a longer
# digit-and-hyphen blob is not partially matched. The caller validates the shape
# and the institution number against the Payments Canada assigned ranges before
# reporting.
_CA_ROUTING_RE = re.compile(r"(?<![\d-])\d{5}-\d{3}(?![\d-])")
# Payments Canada assigns the three-digit institution number from documented
# ranges. 000 is never a live institution; 001-039 are the chartered Schedule I
# banks (001 BMO, 002 Scotiabank, 003 RBC, 004 TD, 006 National Bank, 010 CIBC,
# 016 HSBC Canada, 030 Canadian Western, 039 Laurentian, etc.); 100-399 are
# foreign-bank (Schedule II/III) and Bank of Canada / federal-government members;
# 600-699 are the federally regulated trust/loan and other deposit-taking
# institutions; 800-899 are the central/credit-union groups (815 Desjardins,
# 809/828/839/849/879/889 the provincial credit-union centrals). Gating the
# institution number to these assigned ranges (and rejecting 000) is the
# structural precision lever that keeps a coincidental TTTTT-III token from being
# misread as a routing number. Ranges are kept coarse on purpose so the table can
# stay correct as individual institution numbers are reassigned within them.
_CA_INSTITUTION_RANGES = (
    (1, 39),     # Schedule I chartered banks
    (100, 399),  # Schedule II/III foreign banks, Bank of Canada, federal gov't
    (600, 699),  # trust and loan companies
    (800, 899),  # central credit-union / caisse-populaire groups
)

# Australian BSB (Bank-State-Branch) code candidate -- the canonical six-digit
# routing code written ``NNN-NNN``: a leading bank/financial-institution prefix,
# a state identifier, and a branch number. This is the value an Australian BECS
# direct-entry / PayTo / direct-debit payment is routed against (paired with an
# account number) -- the Australian domestic equivalent of an ABA routing number,
# a UK sort code, or a Canadian routing number. The hyphenated 3-3 split is the
# defining presentation and the precision lever: it is distinct from any
# contiguous digit run (so it never competes with the account-number ``\d{8,}``,
# routing ``\d{9}``, or card scanners), and distinct from every other hyphenated
# detector -- the SSN's 3-2-4 split, the UK sort code's 2-2-2, and the Canadian
# routing number's 5-3 -- so none of the hyphenated detectors ever collide. The
# run is bounded by a non-digit/non-hyphen lookaround so a BSB embedded in a
# longer digit-and-hyphen blob is not partially matched. A BSB has no published,
# self-contained arithmetic check digit, so precision comes from the hyphenated
# structure plus the assigned bank-prefix gate below. The caller validates both
# before reporting.
_AU_BSB_RE = re.compile(r"(?<![\d-])\d{3}-\d{3}(?![\d-])")
# AusPayNet (the Australian Payments Network, formerly APCA) assigns the leading
# digits of a BSB to a financial institution. The first two digits are the bank
# code and the third is (broadly) the state. ``00`` is never an assigned bank
# prefix, and the assigned space runs through the major banks and the mutual /
# credit-union / building-society blocks. We gate on the assigned leading-pair
# ranges below: the big-four and other ADIs occupy 01-19, the special
# Reserve-Bank / government and other-ADI blocks occupy 20-79, and 80-89 is the
# Cuscal-sponsored mutual / credit-union / fintech block. 00 (unassigned) and the
# 90-99 reserved range are rejected. Gating the leading pair to the assigned
# ranges is the structural precision lever that keeps a coincidental NNN-NNN token
# (a stylised reference, a part number) from being misread as a BSB.
_AU_BSB_PREFIX_RANGES = (
    (1, 19),   # the big-four and other authorised deposit-taking institutions
    (20, 79),  # Reserve Bank / government / other-ADI institution blocks
    (80, 89),  # Cuscal-sponsored mutuals, credit unions, building societies, fintechs
)

# Indian IFSC (Indian Financial System Code) candidate -- the RBI-defined
# 11-character routing code that identifies a specific bank branch and is the
# value a NEFT / RTGS / IMPS / UPI transfer is routed against, the Indian
# domestic equivalent of an ABA routing number, a UK sort code, an Australian
# BSB, or a Canadian routing number. Its canonical presentation is
# ``BBBB0BRANCH``: a four-letter bank code (e.g. ``SBIN`` State Bank of India,
# ``HDFC``, ``ICIC``, ``PUNB``), a single reserved character that is always
# ``0`` (set aside by the RBI for future use), and a six-character alphanumeric
# branch code. The structure is the precision lever: the mandatory zero in the
# fifth position is a hard structural gate that almost no coincidental 11-char
# token satisfies, and the match is restricted to UPPER-CASE (an IFSC is always
# transmitted upper-case, while an 11-character all-letter shape is otherwise
# easy to collide with ordinary mixed-case prose). The run is bounded by a
# non-alphanumeric lookaround so an IFSC embedded in a longer alphanumeric blob
# is not partially matched. The caller validates the full structure before
# reporting.
_IFSC_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])"
)
# An IFSC is exactly 11 characters (4 bank + 1 reserved zero + 6 branch).
_IFSC_LEN = 11

# Mexican CLABE (Clave Bancaria Estandarizada) candidate -- the 18-digit
# standardized bank-account number that drives every domestic SPEI / interbank
# transfer in Mexico. Its structure is a 3-digit bank (institution) code, a
# 3-digit branch/plaza code, an 11-digit account number, and one trailing
# control digit. The whole value is a contiguous 18-digit run, so -- unlike the
# hyphenated routing codes -- it WOULD be claimed by the generic account-number
# scanner (8+ digits); we therefore check it first and reserve the run. The run
# is bounded by a non-digit lookaround so a CLABE embedded in a longer digit blob
# is not partially matched. Unlike the UK/CA/AU/IN routing codes, a CLABE carries
# a public, self-contained control digit, so precision comes from a real
# arithmetic checksum plus the non-zero bank code -- on a par with the
# IBAN/ABA/Luhn-gated identifiers. The caller validates both before reporting.
_CLABE_RE = re.compile(r"(?<!\d)\d{18}(?!\d)")
# A CLABE is exactly 18 digits.
_CLABE_LEN = 18
# CLABE control-digit weights, applied positionally and repeating across the
# first 17 digits (the 18th is the control digit being checked).
_CLABE_WEIGHTS = (3, 7, 1)

# South Korean Giro number candidate -- the seven-digit payee-routing code
# printed on a Korean utility / tax / insurance bill, written in its canonical
# grouped presentation ``NNNNN-NN``: a five-digit block, a hyphen, and a final
# two-digit block (the last of which is a mod-10 weighted check digit). The Giro
# (지로) system, operated by the Korea Financial Telecommunications & Clearings
# Institute, is how a payer routes a domestic bill payment to a registered
# biller, so a Giro number echoed into a statement memo discloses the
# biller/payee routing of a payment -- the South Korean companion to the ABA /
# UK sort code / Canadian routing / Australian BSB / Indian IFSC detectors. The
# hyphenated 5-2 split is the defining presentation and the first precision
# lever: it is distinct from any contiguous digit run (so it never competes with
# the account-number ``\d{8,}``, routing ``\d{9}``, or card scanners), and
# distinct from every other hyphenated detector -- the SSN's 3-2-4, the UK sort
# code's 2-2-2, the Canadian routing number's 5-3, and the Australian BSB's 3-3
# -- so none of the hyphenated detectors ever collide. The run is bounded by a
# non-digit/non-hyphen lookaround so a Giro number embedded in a longer
# digit-and-hyphen blob is not partially matched. Unlike the hyphenated routing
# codes above, a Giro number carries a public, self-contained mod-10 weighted
# check digit, so precision comes from a real arithmetic checksum plus the
# non-zero payee block -- on a par with the IBAN / ABA / Luhn / CLABE-gated
# identifiers. The caller validates both before reporting.
_KR_GIRO_RE = re.compile(r"(?<![\d-])\d{5}-\d{2}(?![\d-])")
# Korean Giro check-digit weights, applied positionally to the first six digits
# of the seven-digit number. The trailing seventh digit is the check digit being
# verified.
_KR_GIRO_WEIGHTS = (3, 1, 3, 1, 3, 1)

# Thai PromptPay national-ID candidate -- the 13-digit Thai citizen identification
# number (เลขประจำตัวประชาชน) that is the most common PromptPay registration
# "proxy id": a payer routes an instant interbank PromptPay transfer to a payee by
# their national ID (or phone number), so a national ID echoed into a statement
# memo discloses the exact value needed to push funds to that person -- a direct,
# high-value Thai PII / payment-routing leak. Its canonical printed presentation
# is the grouped ``N-NNNN-NNNNN-NN-N`` (1-4-5-2-1 split) seen on every Thai ID
# card. The hyphenated 1-4-5-2-1 shape is the defining presentation and the first
# precision lever: it is distinct from every other hyphenated detector -- the
# SSN's 3-2-4, the UK sort code's 2-2-2, the Canadian routing number's 5-3, the
# Australian BSB's 3-3, and the South Korean Giro's 5-2 -- so none of the
# hyphenated detectors ever collide. Unlike the routing codes a national ID
# carries a public, self-contained mod-11 weighted check digit, so precision comes
# from a real arithmetic checksum plus a valid category digit -- on a par with the
# IBAN / ABA / Luhn / CLABE / Giro-gated identifiers. The whole token, when its
# single-character separators are read as the conventional digit grouping, also
# satisfies the 13-19-digit credit-card matcher, so -- like the CLABE -- we check
# it first and reserve the compact run under the card / account / routing
# namespaces so the same leak is never re-reported as a slice. The run is bounded
# by a non-digit/non-hyphen lookaround so an ID embedded in a longer
# digit-and-hyphen blob is not partially matched. The caller validates the
# structure, the category digit, and the check digit before reporting.
_TH_NATID_RE = re.compile(
    r"(?<![\d-])\d-\d{4}-\d{5}-\d{2}-\d(?![\d-])"
)
# A Thai national ID is exactly 13 digits.
_TH_NATID_LEN = 13
# Mod-11 check-digit weights, applied positionally to the first twelve digits of
# the thirteen-digit number (the leading digit gets weight 13, descending to 2).
# The trailing thirteenth digit is the check digit being verified.
_TH_NATID_WEIGHTS = (13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2)

# Brazilian CPF (Cadastro de Pessoas Físicas) candidate -- the 11-digit individual
# taxpayer registry number every Brazilian resident carries, and the most common
# Pix payee "chave" (key) a payer routes an instant interbank transfer against, so
# a CPF echoed into a statement memo discloses the exact value needed to push funds
# to that person -- a direct, high-value Brazilian PII / payment-routing leak. Its
# canonical printed presentation is the dotted-and-dashed ``NNN.NNN.NNN-NN``
# (3.3.3-2 split) seen on every CPF card and Pix receipt. The dotted presentation
# is the defining shape and the dominant precision lever: it is the ONLY detector
# that uses ``.`` separators, so it is distinct from every hyphenated detector --
# the SSN's 3-2-4, the UK sort code's 2-2-2, the Canadian routing number's 5-3, the
# Australian BSB's 3-3, the South Korean Giro's 5-2, and the Thai national ID's
# 1-4-5-2-1 -- and from any contiguous digit run, so the detectors never collide.
# Unlike the routing codes a CPF carries TWO public, self-contained mod-11 weighted
# check digits, so precision comes from a real double checksum plus an
# all-same-digit rejection (the eleven repeated-digit values pass the checksum but
# are well-known invalid placeholder CPFs) -- on a par with the IBAN / ABA / Luhn /
# CLABE / Giro / national-ID-gated identifiers. The run is bounded by a
# non-digit/non-dot/non-hyphen lookaround so a CPF embedded in a longer
# digit-and-separator blob is not partially matched. The caller validates the
# structure, the all-same-digit rejection, and both check digits before reporting.
_BR_CPF_RE = re.compile(
    r"(?<![\d.\-])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\d.\-])"
)
# A Brazilian CPF is exactly 11 digits.
_BR_CPF_LEN = 11

# Mexican CURP (Clave Única de Registro de Población) candidate -- the 18-character
# unique population-registry key every Mexican resident carries. It is a direct,
# high-value piece of PII: unlike a routing or account number, the CURP *encodes*
# the person -- four name initials, the full birth date, the sex, and the birth
# state are all readable from the value itself, so a CURP echoed into a statement
# memo discloses a named individual's identity, not merely an account. Its
# canonical presentation is a single contiguous 18-character run::
#
#     AAAA NNNNNN S EE CCC H D
#     ^^^^                      4 name initials (3 consonants + a leading vowel/X)
#          ^^^^^^               YYMMDD birth date (6 digits)
#                 ^             sex: ``H`` (hombre/male) or ``M`` (mujer/female)
#                   ^^          2-letter birth-state code (the 31 states + ``DF`` +
#                               ``NE`` for foreign-born)
#                      ^^^      3 internal consonants of the names
#                          ^    homoclave -- a disambiguator: ``0``-``9`` for people
#                               born before 2000, ``A``-``Z`` for 2000 onward
#                            ^  check digit (mod-10 over a base-37 alphabet)
#
# The leading four LETTERS make the contiguous 18-character shape distinct from the
# Mexican CLABE (18 *digits*), so the two 18-character Mexican identifiers never
# collide. The run is bounded by a non-alphanumeric lookaround so a CURP embedded
# in a longer alphanumeric blob is not partially matched, and the match is
# restricted to UPPER-CASE (a CURP is always transmitted upper-case, while an
# 18-character mixed shape is otherwise far too easy to collide with prose). The
# caller validates the structure, the embedded birth date, the sex marker, the
# registered state code, AND the public mod-10 check digit before reporting -- on a
# par with the CPF / national-ID / IBAN-gated identifiers.
_CURP_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[A-Z]{4}\d{6}[HM][A-Z]{2}[A-Z]{3}[A-Z0-9]\d"
    r"(?![A-Za-z0-9])"
)
# A CURP is exactly 18 characters.
_CURP_LEN = 18
# The base-37 alphabet the CURP check digit is computed over. Position in this
# string IS the character's value (``0``=0 ... ``9``=9, ``A``=10 ... ``Z``=36),
# with ``Ñ`` deliberately interposed at index 23 (between ``N`` and ``O``) exactly
# as RENAPO defines it. A CURP never actually contains ``Ñ`` in the eighteen
# positions the regex matches (the matcher only admits ``A``-``Z`` and digits), but
# the alphabet is kept faithful so the positional values of every later letter are
# correct.
_CURP_ALPHABET = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ"
# The two-letter birth-state codes RENAPO assigns: the 31 states, ``DF`` for what
# is now Mexico City, and ``NE`` (nacido en el extranjero) for the foreign-born.
# Gating the 12th-13th characters to this registered set is a strong precision
# lever -- exactly as the BIC gate uses the ISO 3166-1 country set -- that keeps a
# coincidental 18-character token from validating as a CURP.
_CURP_STATES = frozenset(
    "AS BC BS CC CL CM CS CH DF DG GT GR HG JC MC MN MS NT NL OC PL QT QR "
    "SP SL SR TC TS TL VZ YN ZS NE".split()
)


def _curp_check_digit(first17: str) -> int:
    """Return the RENAPO mod-10 check digit for a CURP's first 17 characters.

    Each character is mapped to its value via its position in the base-37
    ``_CURP_ALPHABET`` (``0``=0 ... ``9``=9, ``A``=10 ... ``Z``=36), multiplied by
    a descending positional weight (18 for the first character down to 2 for the
    seventeenth), the products are summed, and the check digit is
    ``(10 - (sum mod 10)) mod 10``. A character outside the alphabet raises
    ``ValueError`` via ``str.index``; the caller has already restricted the input
    to ``A``-``Z`` and digits, so this never fires in practice.
    """
    total = 0
    for i, ch in enumerate(first17):
        total += _CURP_ALPHABET.index(ch) * (18 - (i + 1))
    return (10 - (total % 10)) % 10


def _luhn_valid(digits: str) -> bool:
    """Return ``True`` if a digit string passes the Luhn (mod-10) checksum.

    Luhn is the public, dependency-free check digit algorithm used by every
    major payment-card network (Visa, Mastercard, Amex, Discover, ...). Starting
    from the rightmost digit and moving left, every second digit is doubled
    (subtracting 9 if the result exceeds 9); the total of all digits must be a
    multiple of ten::

        sum(luhn_transform(d_i)) mod 10 == 0

    A 13-19 digit run that passes Luhn is a near-certain real PAN; one that fails
    is almost always a coincidental digit run (an order number, a long account
    id). Non-numeric input returns ``False`` so the helper is safe to reuse.
    """
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _aba_checksum_valid(digits: str) -> bool:
    """Return ``True`` if a 9-digit string passes the ABA routing checksum.

    The ABA (American Bankers Association) routing number checksum is a public,
    dependency-free weighted sum over the nine digits using the repeating
    ``3-7-1`` weighting::

        (3*d1 + 7*d2 + d3 + 3*d4 + 7*d5 + d6 + 3*d7 + 7*d8 + d9) mod 10 == 0

    A 9-digit run that passes this is a near-certain real routing number; one
    that fails is almost always a coincidental digit run (zip+4, phone number,
    order number, EIN-shaped value). Non-numeric or wrong-length input returns
    ``False`` -- the caller has already matched exactly nine digits, but we stay
    defensive so the helper is safe to reuse.
    """
    if len(digits) != 9 or not digits.isdigit():
        return False
    total = sum(w * int(d) for w, d in zip(_ABA_WEIGHTS, digits))
    return total % 10 == 0


def _iban_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid IBAN (ISO 13616).

    Three independent gates, all public and dependency-free:

    1. **Shape** -- after stripping spaces, the value is 15-34 characters: two
       letters (country code), two digits (check digits), then an alphanumeric
       BBAN.
    2. **Country length** -- if the declared country code is in the ISO 13616
       registry, the total length must match exactly (e.g. a ``DE`` IBAN is
       always 22 characters). Unknown country codes fall back to the generic
       15-34 bound, so the registry can grow without code changes.
    3. **Mod-97 checksum** -- move the first four characters to the end, map each
       letter to a two-digit number (``A``=10 ... ``Z``=35), and the resulting
       integer must be ``== 1 (mod 97)``.

    A run that clears all three is a near-certain real IBAN; a coincidental
    alphanumeric blob fails one of them with overwhelming probability. Any
    malformed input returns ``False`` so the helper is safe to reuse.
    """
    iban = candidate.replace(" ", "").upper()
    if not (_IBAN_MIN_LEN <= len(iban) <= _IBAN_MAX_LEN):
        return False
    if not (iban[:2].isalpha() and iban[2:4].isdigit()):
        return False
    if not iban[4:].isalnum():
        return False
    country = iban[:2]
    expected = _IBAN_LENGTHS.get(country)
    if expected is not None and len(iban) != expected:
        return False
    # Rearrange: move the first four chars (country code + check digits) to the
    # end, then translate letters to numbers and take the value mod 97.
    rearranged = iban[4:] + iban[:4]
    digits = "".join(
        str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged
    )
    return int(digits) % 97 == 1


def _trim_to_valid_iban(candidate: str) -> str | None:
    """Return the longest valid IBAN prefix of a captured run, or ``None``.

    The grouped-IBAN regex can over-capture trailing space-separated words
    (``"DE89 3704 ... 0130 00 on file"``) because short words look like IBAN
    blocks. We resolve the ambiguity at validation time: try the whole run, then
    progressively drop trailing space-separated tokens until the remainder
    validates (country code + registered length + mod-97). The first length-aware
    validating prefix is the real IBAN. Contiguous (space-free) candidates are
    validated directly. Returns the validating string (original spacing kept) or
    ``None`` if no prefix is a valid IBAN.
    """
    if " " not in candidate:
        return candidate if _iban_valid(candidate) else None
    tokens = candidate.split(" ")
    for end in range(len(tokens), 0, -1):
        prefix = " ".join(tokens[:end])
        if _iban_valid(prefix):
            return prefix
    return None


def _lei_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid LEI (ISO 17442).

    An LEI (Legal Entity Identifier) is the global, public identifier for a
    legal entity that is party to a financial transaction -- a counterparty,
    issuer, or fund manager. It is twenty characters: an 18-character
    alphanumeric entity portion (a 4-char LOU prefix, a 2-char reserved field,
    and a 12-char entity-specific part) followed by two ISO 7064 mod-97-10 check
    digits. Its public, dependency-free check is::

        1. Shape  -- exactly 20 characters: 18 alphanumerics then 2 decimal
           check digits.
        2. Check digits -- expand every letter to its two-digit value
           (``A``=10 ... ``Z``=35), concatenate to a pure digit string (check
           digits included), interpret as an integer, and verify it is
           ``== 1 (mod 97)``.

    The same ISO 7064 mod-97-10 scheme as the IBAN, but applied to the whole
    20-character value with no rearrangement (the check digits already sit at
    the end). A run that clears both gates is a near-certain real LEI; a
    coincidental 20-char alphanumeric blob fails the check digits with
    overwhelming probability. We deliberately do NOT gate on the reserved
    positions 4-5 being ``00`` -- that was the convention for the earliest
    ROC-assigned prefixes but is not honoured by all later LOUs, so enforcing it
    would reject real LEIs. Any malformed input returns ``False`` so the helper
    is safe to reuse.
    """
    lei = candidate.strip().upper()
    if len(lei) != _LEI_LEN:
        return False
    if not (lei[:18].isalnum() and lei[18:].isdigit()):
        return False
    # Expand letters to numbers, then take the whole value mod 97. ISO 7064
    # mod-97-10: a valid identifier (check digits included) is congruent to 1.
    digits = "".join(
        str(ord(ch) - 55) if ch.isalpha() else ch for ch in lei
    )
    return int(digits) % 97 == 1


def _redact_lei(lei: str) -> str:
    """Redact an LEI, preserving only the four-character LOU prefix for triage.

    The leading four characters identify the issuing Local Operating Unit
    (useful context for a report) while the entity-specific portion and the
    check digits -- the part that pins the leak to a specific legal entity --
    are masked.
    """
    lei = lei.upper()
    return lei[:4] + "X" * (len(lei) - 4)


def _bic_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid BIC (ISO 9362).

    A BIC (Bank/Business Identifier Code, the value carried in a SWIFT message
    and printed alongside an IBAN) is the public identifier for a financial
    institution. Unlike the account/security identifiers, ISO 9362 defines no
    arithmetic checksum -- its precision comes instead from a strict structure
    plus a registered country code:

        1. **Shape** -- exactly 8 or 11 characters. The first four are letters
           (the institution / bank code), the next two are letters (the country
           code), the next two are alphanumeric (the location code), and -- for
           the 11-character form -- the final three are alphanumeric (the branch
           code).
        2. **Country** -- the 5th-6th characters must be a registered ISO 3166-1
           alpha-2 country code. This is the primary precision lever (mirroring
           the IBAN gate): an ordinary 8-letter word will almost never end in a
           real country code AND satisfy the location rules below.
        3. **Location code** -- per ISO 9362, the first location character must
           not be ``0`` or ``1`` (those are reserved) and the second must not be
           the letter ``O`` (to avoid confusion with zero).

    A run that clears all three is a near-certain real BIC; a coincidental
    alphanumeric blob fails one of them with overwhelming probability. Any
    malformed input returns ``False`` so the helper is safe to reuse.
    """
    bic = candidate.strip().upper()
    if len(bic) not in _BIC_LENGTHS:
        return False
    # Bank code (4) + country code (2) must be letters; the rest alphanumeric.
    if not (bic[:6].isalpha() and bic[6:].isalnum()):
        return False
    if bic[4:6] not in _ISO_3166_1:
        return False
    # Location code rules (ISO 9362): pos 7 not in {0,1}; pos 8 not 'O'.
    if bic[6] in "01" or bic[7] == "O":
        return False
    return True


def _redact_bic(bic: str) -> str:
    """Redact a BIC, preserving only the bank + country prefix for triage.

    The leading six characters (institution code + country) identify the bank
    and jurisdiction -- useful context for a report -- while the location and
    branch codes, which pin the leak to a specific office, are masked.
    """
    bic = bic.upper()
    return bic[:6] + "X" * (len(bic) - 6)


def _isin_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid ISIN (ISO 6166).

    An ISIN (International Securities Identification Number) is the global
    identifier for a security -- the value that legitimately lives in an OFX
    investment ``SECID``. Its public, dependency-free check is::

        1. Shape  -- exactly 12 characters: two letters (ISO 3166 country code,
           or ``XS`` for international issues), nine alphanumeric NSIN
           characters, and one trailing decimal check digit.
        2. Check digit -- expand every letter to its two-digit value
           (``A``=10 ... ``Z``=35), concatenate to a pure digit string, then
           verify the whole string (check digit included) passes the Luhn
           (mod-10) checksum.

    A run that clears both gates is a near-certain real ISIN; a coincidental
    alphanumeric blob fails the check digit with overwhelming probability. Any
    malformed input returns ``False`` so the helper is safe to reuse.
    """
    isin = candidate.strip().upper()
    if len(isin) != _ISIN_LEN:
        return False
    if not (isin[:2].isalpha() and isin[2:11].isalnum() and isin[11].isdigit()):
        return False
    # Expand letters to numbers, then Luhn over the whole (including check digit).
    digits = "".join(
        str(ord(ch) - 55) if ch.isalpha() else ch for ch in isin
    )
    return _luhn_valid(digits)


def _cusip_char_value(ch: str) -> int | None:
    """Map a single CUSIP character to its numeric value, or ``None``.

    Digits map to themselves, letters ``A``=10 ... ``Z``=35, and the three
    legacy special characters ``*``=36, ``@``=37, ``#``=38. Anything else is not
    a valid CUSIP character and returns ``None``.
    """
    if ch.isdigit():
        return int(ch)
    if ch.isalpha():
        return ord(ch.upper()) - 55
    return _CUSIP_SPECIAL.get(ch)


def _cusip_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid CUSIP.

    A CUSIP (the US/Canada NSIN issued by CUSIP Global Services) is a public,
    dependency-free identifier with a built-in check digit. Its modulus-10
    "double-add-double" algorithm mirrors the Luhn idea:

        1. Shape -- exactly 9 characters: an 8-character base (digits, letters
           A-Z, or the legacy specials ``*`` ``@`` ``#``) plus one trailing
           decimal check digit.
        2. Check digit -- map each of the first eight characters to its value
           (digit-as-itself, ``A``=10 ... ``Z``=35, ``*``=36 ``@``=37 ``#``=38);
           double every value in an even 1-based position; sum the *digits* of
           each (doubled) value; the check digit is ``(10 - (sum mod 10)) mod 10``.

    A run that clears both gates is a near-certain real CUSIP; a coincidental
    alphanumeric blob fails the check digit with overwhelming probability. Any
    malformed input returns ``False`` so the helper is safe to reuse.
    """
    cusip = candidate.strip().upper()
    if len(cusip) != _CUSIP_LEN:
        return False
    if not cusip[8].isdigit():
        return False
    total = 0
    for i, ch in enumerate(cusip[:8]):
        value = _cusip_char_value(ch)
        if value is None:
            return False
        # Positions are 1-based for the doubling rule: double the value of
        # every character in an even position (the 2nd, 4th, 6th, 8th).
        if (i + 1) % 2 == 0:
            value *= 2
        # Sum the decimal digits of the (possibly doubled) value.
        total += value // 10 + value % 10
    check = (10 - (total % 10)) % 10
    return check == int(cusip[8])


def _sedol_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid SEDOL.

    A SEDOL (Stock Exchange Daily Official List number, the UK/Ireland NSIN
    issued by the London Stock Exchange) is a public, dependency-free identifier
    with a built-in weighted check digit:

        1. Shape -- exactly 7 characters: a 6-character base of digits or
           consonants (the vowels A, E, I, O, U are never used in a SEDOL base)
           plus one trailing decimal check digit.
        2. Check digit -- map each of the first six characters to its value
           (digit-as-itself, ``B``=11 ... ``Z``=35, the same ``ord-55`` letter
           expansion used by ISIN/CUSIP); multiply by the positional weights
           ``(1, 3, 1, 7, 3, 9)``; the check digit is
           ``(10 - (weighted_sum mod 10)) mod 10``.

    A run that clears both gates is a near-certain real SEDOL; a coincidental
    alphanumeric blob fails the no-vowel rule or the check digit with
    overwhelming probability. Any malformed input returns ``False`` so the helper
    is safe to reuse.
    """
    sedol = candidate.strip().upper()
    if len(sedol) != _SEDOL_LEN:
        return False
    if not sedol[6].isdigit():
        return False
    total = 0
    for weight, ch in zip(_SEDOL_WEIGHTS, sedol[:6]):
        if ch.isdigit():
            value = int(ch)
        elif ch.isalpha() and ch not in _SEDOL_VOWELS:
            # Same letter expansion as ISIN/CUSIP: A=10 ... Z=35. Vowels are
            # structurally invalid in a SEDOL base and are rejected above.
            value = ord(ch) - 55
        else:
            return False
        total += weight * value
    check = (10 - (total % 10)) % 10
    return check == int(sedol[6])


def _uk_sort_code_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid UK sort code.

    A UK sort code is the six-digit routing code that identifies a UK bank and
    branch -- the domestic equivalent of an ABA routing number, and the value
    that (paired with an account number) drives a Faster Payments / BACS / CHAPS
    transfer. It is conventionally written in three hyphen-separated pairs,
    ``NN-NN-NN``. Unlike the ABA number it has no published, self-contained check
    digit -- the VocaLink modulus check that validates a sort code requires the
    paired account number and a weight table -- so precision comes from two
    public, dependency-free structural gates:

        1. **Shape** -- exactly ``NN-NN-NN``: three hyphen-separated pairs of
           decimal digits.
        2. **Clearing-range prefix** -- the leading pair (the bank/clearing
           identifier) must be in the assigned range 01-97. ``00`` is unassigned
           and ``98``/``99`` are reserved (Bank of England / non-clearing and
           test ranges), so an all-zeros, all-nines, or otherwise out-of-range
           leading pair is never a live sort code.

    The hyphenated shape is itself the dominant precision lever: it is distinct
    from any contiguous digit run, so the gate never competes with the account /
    routing / card scanners, and prose almost never contains an ``NN-NN-NN``
    token. Any malformed input returns ``False`` so the helper is safe to reuse.
    """
    code = candidate.strip()
    parts = code.split("-")
    if len(parts) != 3:
        return False
    if not all(len(p) == 2 and p.isdigit() for p in parts):
        return False
    return _UK_SORT_FIRST_MIN <= int(parts[0]) <= _UK_SORT_FIRST_MAX


def _redact_uk_sort_code(code: str) -> str:
    """Redact a UK sort code, preserving only the leading bank pair for triage.

    The first pair identifies the clearing bank (useful context for a report)
    while the branch-identifying middle and final pairs -- the part that pins the
    leak to a specific account's routing -- are masked.
    """
    return code[:2] + "-XX-XX"


def _ca_routing_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid Canadian routing number.

    A Canadian routing number is the value a domestic Interac e-Transfer / EFT /
    pre-authorized-debit payment is routed against -- the Canadian equivalent of
    an ABA routing number or a UK sort code. Its cheque-printed MICR presentation
    is ``TTTTT-III``: a five-digit branch *transit* number, a hyphen, and a
    three-digit financial-*institution* number. Like the UK sort code it carries
    no published, self-contained arithmetic checksum (the only validation is the
    bank's own account-modulus check, which needs the paired account number), so
    precision comes from two public, dependency-free structural gates:

        1. **Shape** -- exactly ``TTTTT-III``: five decimal digits, a hyphen, and
           three decimal digits.
        2. **Assigned institution number** -- the three-digit institution number
           must fall in a Payments Canada assigned range (1-39 chartered banks,
           100-399 foreign-bank / federal members, 600-699 trust & loan, 800-899
           credit-union centrals). ``000`` is never a live institution, and an
           out-of-range value (e.g. 999) is the classic decoy.

    The hyphenated 5-3 shape is itself the dominant precision lever: it is
    distinct from any contiguous digit run and from the UK sort code's 2-2-2 split
    and the SSN's 3-2-4 split, so the gate never competes with the account /
    routing / card scanners nor the other hyphenated detectors. Any malformed
    input returns ``False`` so the helper is safe to reuse.
    """
    code = candidate.strip()
    parts = code.split("-")
    if len(parts) != 2:
        return False
    transit, institution = parts
    if not (len(transit) == 5 and transit.isdigit()):
        return False
    if not (len(institution) == 3 and institution.isdigit()):
        return False
    inst = int(institution)
    return any(low <= inst <= high for low, high in _CA_INSTITUTION_RANGES)


def _redact_ca_routing(code: str) -> str:
    """Redact a Canadian routing number, preserving only the institution number.

    The trailing three-digit institution number identifies the bank (useful
    context for a report -- 003 = RBC, 004 = TD, and so on) while the five-digit
    branch transit number, which pins the leak to a specific branch, is masked.
    """
    institution = code.split("-")[1]
    return "XXXXX-" + institution


def _au_bsb_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid Australian BSB code.

    An Australian BSB (Bank-State-Branch) code is the six-digit routing code that
    identifies an Australian bank, state, and branch -- the value that (paired
    with an account number) drives a BECS direct-entry / PayTo / direct-debit
    payment, the domestic equivalent of an ABA routing number, a UK sort code, or
    a Canadian routing number. It is conventionally written in two
    hyphen-separated triples, ``NNN-NNN``. Like the UK sort code and the Canadian
    routing number it carries no published, self-contained arithmetic check digit,
    so precision comes from two public, dependency-free structural gates:

        1. **Shape** -- exactly ``NNN-NNN``: two hyphen-separated triples of
           decimal digits.
        2. **Assigned bank prefix** -- the leading two digits (the AusPayNet bank
           code) must fall in an assigned range (01-19 the big-four / other ADIs,
           20-79 the Reserve-Bank / government / other-ADI blocks, 80-89 the
           Cuscal-sponsored mutual / credit-union / fintech block). ``00`` is
           never assigned and the 90-99 range is reserved, so an all-zeros or an
           out-of-range leading pair is never a live BSB.

    The hyphenated 3-3 shape is itself the dominant precision lever: it is
    distinct from any contiguous digit run and from the SSN's 3-2-4 split, the UK
    sort code's 2-2-2, and the Canadian routing number's 5-3, so the gate never
    competes with the account / routing / card scanners nor the other hyphenated
    detectors. Any malformed input returns ``False`` so the helper is safe to
    reuse.
    """
    code = candidate.strip()
    parts = code.split("-")
    if len(parts) != 2:
        return False
    if not all(len(p) == 3 and p.isdigit() for p in parts):
        return False
    prefix = int(parts[0][:2])
    return any(low <= prefix <= high for low, high in _AU_BSB_PREFIX_RANGES)


def _redact_au_bsb(code: str) -> str:
    """Redact an Australian BSB code, preserving only the leading bank pair.

    The first two digits identify the bank/financial institution (useful context
    for a report) while the state digit and the three branch digits -- the part
    that pins the leak to a specific branch's routing -- are masked.
    """
    return code[:2] + "X-XXX"


def _ifsc_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid Indian IFSC code.

    An IFSC (Indian Financial System Code) is the RBI-defined 11-character code
    that identifies a specific bank branch -- the value a domestic NEFT / RTGS /
    IMPS / UPI transfer is routed against, the Indian equivalent of an ABA
    routing number, a UK sort code, an Australian BSB, or a Canadian routing
    number. Like those it carries no published, self-contained arithmetic check
    digit, so precision comes from a strict, public, dependency-free structure:

        1. **Shape** -- exactly 11 characters: ``BBBB0BRANCH``.
        2. **Bank code** -- the first four characters are letters (the
           institution code, e.g. ``SBIN``/``HDFC``/``ICIC``).
        3. **Reserved zero** -- the fifth character is always the digit ``0``
           (reserved by the RBI for future use). This mandatory zero is the
           dominant precision lever: almost no coincidental 11-character token
           carries a ``0`` in exactly the fifth position.
        4. **Branch code** -- the final six characters are alphanumeric (the
           branch identifier).

    A run that clears all four gates is a near-certain real IFSC; a coincidental
    11-character alphanumeric blob fails the reserved-zero or the letter-prefix
    gate with overwhelming probability. Any malformed input returns ``False`` so
    the helper is safe to reuse.
    """
    code = candidate.strip().upper()
    if len(code) != _IFSC_LEN:
        return False
    if not code[:4].isalpha():
        return False
    if code[4] != "0":
        return False
    return code[5:].isalnum()


def _redact_ifsc(code: str) -> str:
    """Redact an IFSC, preserving only the four-letter bank code for triage.

    The leading four characters identify the bank (useful context for a report
    -- ``SBIN`` State Bank of India, ``HDFC``, and so on) while the reserved
    zero and the six-character branch code -- the part that pins the leak to a
    specific branch's routing -- are masked.
    """
    code = code.upper()
    return code[:4] + "X" * (len(code) - 4)


def _clabe_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid Mexican CLABE.

    A CLABE (Clave Bancaria Estandarizada) is the 18-digit standardized
    bank-account number that every domestic SPEI / interbank transfer in Mexico
    is routed against -- the Mexican equivalent of an IBAN, and the value (on its
    own) needed to receive funds into a specific account. Unlike the UK / Canadian
    / Australian / Indian routing codes it carries a public, self-contained
    arithmetic control digit, so precision comes from two public, dependency-free
    gates:

        1. **Shape** -- exactly 18 decimal digits: a 3-digit bank (institution)
           code, a 3-digit branch/plaza code, an 11-digit account number, and one
           trailing control digit.
        2. **Bank code** -- the leading three digits (the Banxico-assigned bank
           code) must be non-zero. ``000`` is never an assigned institution, so an
           all-zeros or zero-prefixed leading code is never a live CLABE.
        3. **Control digit** -- multiply each of the first 17 digits by the
           repeating weights ``(3, 7, 1)``, take each product *mod 10*, sum those,
           and the control digit is ``(10 - (sum mod 10)) mod 10``. The 18th digit
           must equal that control digit.

    A run that clears all three gates is a near-certain real CLABE; a coincidental
    18-digit run fails the control digit with overwhelming probability. Any
    malformed input returns ``False`` so the helper is safe to reuse.
    """
    clabe = candidate.strip()
    if len(clabe) != _CLABE_LEN or not clabe.isdigit():
        return False
    if int(clabe[:3]) == 0:
        return False
    total = 0
    for i, ch in enumerate(clabe[:17]):
        total += (int(ch) * _CLABE_WEIGHTS[i % 3]) % 10
    control = (10 - (total % 10)) % 10
    return control == int(clabe[17])


def _redact_clabe(clabe: str) -> str:
    """Redact a CLABE, preserving only the leading bank code for triage.

    The first three digits identify the bank/institution (useful context for a
    report -- 002 Banamex, 012 BBVA, 014 Santander, and so on) while the
    branch/plaza code, the account number, and the control digit -- the part that
    pins the leak to a specific account -- are masked.
    """
    return clabe[:3] + "X" * (len(clabe) - 3)


def _kr_giro_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid South Korean Giro number.

    A South Korean Giro number is the seven-digit payee-routing code printed on a
    Korean utility / tax / insurance bill -- the value a domestic Giro bill
    payment is routed against, the South Korean companion to an ABA routing
    number, a UK sort code, an Australian BSB, an Indian IFSC, or a Canadian
    routing number. Its canonical bill presentation is the grouped ``NNNNN-NN``
    (5-2 split). Precision comes from three public, dependency-free gates:

        1. **Shape** -- exactly ``NNNNN-NN``: five decimal digits, a hyphen, and
           two decimal digits.
        2. **Non-zero payee block** -- the first six digits (the biller/payee
           block) must not be all zeros; ``000000`` is never a live Giro payee.
        3. **Check digit** -- multiply each of the first six digits by the
           repeating weights ``(3, 1, 3, 1, 3, 1)``, sum the products, and the
           seventh (final) digit must equal ``(10 - (sum mod 10)) mod 10``.

    The hyphenated 5-2 shape is itself a precision lever: it is distinct from any
    contiguous digit run and from the SSN's 3-2-4 split, the UK sort code's
    2-2-2, the Canadian routing number's 5-3, and the Australian BSB's 3-3, so
    the gate never competes with the account / routing / card scanners nor the
    other hyphenated detectors. A run that clears all three gates is a
    near-certain real Giro number; a coincidental ``NNNNN-NN`` token fails the
    check digit with overwhelming probability. Any malformed input returns
    ``False`` so the helper is safe to reuse.
    """
    code = candidate.strip()
    parts = code.split("-")
    if len(parts) != 2:
        return False
    head, tail = parts
    if not (len(head) == 5 and head.isdigit()):
        return False
    if not (len(tail) == 2 and tail.isdigit()):
        return False
    digits = head + tail
    if int(digits[:6]) == 0:
        return False
    total = sum(w * int(d) for w, d in zip(_KR_GIRO_WEIGHTS, digits[:6]))
    check = (10 - (total % 10)) % 10
    return check == int(digits[6])


def _redact_kr_giro(code: str) -> str:
    """Redact a South Korean Giro number, preserving only the leading pair.

    The first two digits hint at the biller category (useful context for a
    report) while the rest of the payee block and the check digit -- the part
    that pins the leak to a specific biller -- are masked. The hyphen is
    preserved so the masked shape still reads as a Giro number::

        12345-67 -> 12XXX-XX
    """
    return code[:2] + "XXX-XX"


def _th_natid_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid Thai national ID.

    A Thai national ID number (เลขประจำตัวประชาชน) is the 13-digit citizen
    identification number every Thai resident carries -- and the most common
    PromptPay "proxy id" a payer routes an instant interbank transfer against, so
    a national ID echoed into a statement memo discloses the exact value needed to
    push funds to that person. Its canonical card presentation is the grouped
    ``N-NNNN-NNNNN-NN-N`` (1-4-5-2-1 split). Unlike the UK / Canadian / Australian
    / Indian routing codes it carries a public, self-contained arithmetic check
    digit, so precision comes from three public, dependency-free gates:

        1. **Shape** -- exactly ``N-NNNN-NNNNN-NN-N``: thirteen decimal digits in
           the 1-4-5-2-1 hyphen grouping.
        2. **Category digit** -- the leading digit (the registration category) is
           1-8. ``0`` and ``9`` are not issued first digits, so a leading ``0`` or
           ``9`` is never a live national ID -- the structural lever that rejects a
           coincidental run.
        3. **Check digit** -- multiply each of the first twelve digits by the
           descending weights ``13, 12, ... , 2``, sum the products, and the
           thirteenth (final) digit must equal ``(11 - (sum mod 11)) mod 10``.

    The hyphenated 1-4-5-2-1 shape is itself a precision lever: it is distinct
    from every other hyphenated detector -- the SSN's 3-2-4, the UK sort code's
    2-2-2, the Canadian routing number's 5-3, the Australian BSB's 3-3, and the
    South Korean Giro's 5-2 -- so the detectors never collide. A run that clears
    all three gates is a near-certain real national ID; a coincidental token fails
    the check digit with overwhelming probability. Any malformed input returns
    ``False`` so the helper is safe to reuse.
    """
    code = candidate.strip()
    parts = code.split("-")
    if len(parts) != 5:
        return False
    if [len(p) for p in parts] != [1, 4, 5, 2, 1]:
        return False
    if not all(p.isdigit() for p in parts):
        return False
    digits = "".join(parts)
    if not (1 <= int(digits[0]) <= 8):
        return False
    total = sum(w * int(d) for w, d in zip(_TH_NATID_WEIGHTS, digits[:12]))
    check = (11 - (total % 11)) % 10
    return check == int(digits[12])


def _redact_th_natid(code: str) -> str:
    """Redact a Thai national ID, preserving only the leading category digit.

    The first digit hints at the registration category (useful context for a
    report) while the rest of the number and the check digit -- the part that pins
    the leak to a specific person -- are masked. The hyphen grouping is preserved
    so the masked shape still reads as a national ID::

        1-1017-00522-00-8 -> 1-XXXX-XXXXX-XX-X
    """
    return code[0] + "-XXXX-XXXXX-XX-X"


def _br_cpf_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid Brazilian CPF.

    A CPF (Cadastro de Pessoas Físicas) is the 11-digit individual taxpayer
    registry number every Brazilian resident carries -- and the most common Pix
    "chave" (key) a payer routes an instant interbank transfer against, so a CPF
    echoed into a statement memo discloses the exact value needed to push funds to
    that person. Its canonical card / receipt presentation is the
    dotted-and-dashed ``NNN.NNN.NNN-NN`` (3.3.3-2 split). Unlike the UK / Canadian
    / Australian / Indian routing codes it carries TWO public, self-contained
    arithmetic check digits, so precision comes from three public,
    dependency-free gates:

        1. **Shape** -- exactly ``NNN.NNN.NNN-NN``: eleven decimal digits in the
           3.3.3-2 dotted-and-dashed grouping.
        2. **All-same-digit rejection** -- the eleven repeated-digit values
           (``000.000.000-00`` ... ``999.999.999-99``) all satisfy the checksum
           arithmetic but are well-known invalid placeholder CPFs that the official
           validator rejects. Rejecting them is the precision lever that keeps a
           coincidental repeated-digit run from being reported.
        3. **Check digits** -- the first check digit is computed over the first
           nine digits with descending weights ``10, 9, ... , 2``; the second over
           the first ten digits with descending weights ``11, 10, ... , 2``. For
           each, ``r = (weighted_sum mod 11)`` and the check digit is ``0`` when
           ``r < 2`` else ``11 - r``. Both must match.

    A run that clears all three gates is a near-certain real CPF; a coincidental
    token fails the all-same-digit gate or one of the check digits with
    overwhelming probability. Any malformed input returns ``False`` so the helper
    is safe to reuse.
    """
    code = candidate.strip()
    # Enforce the canonical dotted-and-dashed NNN.NNN.NNN-NN grouping exactly --
    # three dot-separated triples then a dash and the two check digits. The
    # structure is validated here (not only in the regex) so the helper rejects a
    # contiguous, hyphenated, or wrong-split run on its own.
    dash_parts = code.split("-")
    if len(dash_parts) != 2:
        return False
    body, check_block = dash_parts
    if not (len(check_block) == 2 and check_block.isdigit()):
        return False
    triples = body.split(".")
    if len(triples) != 3:
        return False
    if not all(len(t) == 3 and t.isdigit() for t in triples):
        return False
    digits = "".join(triples) + check_block
    if len(digits) != _BR_CPF_LEN:
        return False
    # Eleven repeated-digit CPFs pass the checksum arithmetic but are invalid
    # placeholders -- the official validator rejects them.
    if len(set(digits)) == 1:
        return False
    for n in (9, 10):
        total = sum(int(d) * (n + 1 - i) for i, d in enumerate(digits[:n]))
        remainder = total % 11
        check = 0 if remainder < 2 else 11 - remainder
        if check != int(digits[n]):
            return False
    return True


def _redact_br_cpf(code: str) -> str:
    """Redact a Brazilian CPF, preserving only the leading block for triage.

    The first three digits (and the dotted-and-dashed shape) survive so a reporter
    can tell two distinct leaks apart, while the rest of the number and both check
    digits -- the part that pins the leak to a specific person -- are masked::

        111.444.777-35 -> 111.XXX.XXX-XX
    """
    return code[:3] + ".XXX.XXX-XX"


def _curp_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid Mexican CURP.

    A CURP (Clave Única de Registro de Población) is the 18-character unique
    population-registry key every Mexican resident carries -- and a direct piece
    of identity PII: the value *encodes* the person (name initials, full birth
    date, sex, and birth state), so a CURP echoed into a statement memo discloses
    a named individual, not merely an account. Precision comes from four public,
    dependency-free gates:

        1. **Shape** -- exactly 18 characters: four letters (name initials), six
           digits (``YYMMDD`` birth date), a sex marker (``H`` or ``M``), a
           two-letter state code, three letters (internal consonants), an
           alphanumeric homoclave, and a final decimal check digit.
        2. **Birth date** -- the six date digits must form a real ``MM`` (01-12)
           and ``DD`` (01-31) pair. A coincidental token with an impossible month
           or day (``00``/``13``+ month, ``00``/``32``+ day) is never a live CURP.
        3. **State code** -- the 12th-13th characters must be one of the RENAPO
           registered codes (the 31 states + ``DF`` + ``NE`` for foreign-born).
           This is the dominant precision lever, mirroring the BIC's ISO 3166-1
           country gate: an arbitrary 18-character token almost never carries a
           real state code in exactly those two positions.
        4. **Check digit** -- the public RENAPO mod-10 check digit, computed over
           the first 17 characters with the base-37 alphabet and descending
           positional weights, must equal the 18th character.

    A run that clears all four gates is a near-certain real CURP; a coincidental
    18-character token fails the date, state, or check-digit gate with
    overwhelming probability. Any malformed input returns ``False`` so the helper
    is safe to reuse.
    """
    curp = candidate.strip().upper()
    if len(curp) != _CURP_LEN:
        return False
    # Shape: AAAA NNNNNN S EE CCC X D
    if not (
        curp[:4].isalpha()
        and curp[4:10].isdigit()
        and curp[10] in "HM"
        and curp[11:13].isalpha()
        and curp[13:16].isalpha()
        and curp[16].isalnum()
        and curp[17].isdigit()
    ):
        return False
    # Birth date: a real MM (01-12) and DD (01-31). The two-digit year is
    # ambiguous across centuries (the homoclave disambiguates in practice), so we
    # do not gate on it -- but an impossible month or day is never a live CURP.
    month = int(curp[6:8])
    day = int(curp[8:10])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    if curp[11:13] not in _CURP_STATES:
        return False
    return _curp_check_digit(curp[:17]) == int(curp[17])


def _redact_curp(curp: str) -> str:
    """Redact a CURP, preserving only the leading name initials for triage.

    The first four characters (the name initials) survive so a reporter can tell
    two distinct leaks apart, while the birth date, sex, state, internal
    consonants, homoclave, and check digit -- the part that pins the leak to a
    specific identified person -- are masked::

        HEGG560427MVZRRL08 -> HEGGXXXXXXXXXXXXXX
    """
    curp = curp.upper()
    return curp[:4] + "X" * (len(curp) - 4)


def _redact_sedol(sedol: str) -> str:
    """Redact a SEDOL, preserving only the leading character for triage.

    The first character hints at the issuing exchange family (useful for a
    report) while the rest of the base and the check digit -- the part that pins
    the leak to a specific security -- are masked.
    """
    sedol = sedol.upper()
    return sedol[:1] + "X" * (len(sedol) - 1)


def _redact_cusip(cusip: str) -> str:
    """Redact a CUSIP, preserving only the leading two characters for triage.

    The first two characters narrow down the issuer family (useful for a report)
    while the rest of the base and the check digit -- the part that pins the leak
    to a specific security -- are masked.
    """
    cusip = cusip.upper()
    return cusip[:2] + "X" * (len(cusip) - 2)


def _redact_isin(isin: str) -> str:
    """Redact an ISIN, preserving only the two-letter country/issuer prefix.

    The leading two letters identify the jurisdiction (useful for a report)
    while the NSIN body and check digit -- the part that pins the holding to a
    specific security -- are masked.
    """
    isin = isin.upper()
    return isin[:2] + "X" * (len(isin) - 2)


def _redact_email(email: str) -> str:
    """Redact an email address, preserving only enough for triage.

    We keep the first character of the local part and the domain (so a reporter
    can tell two distinct leaks apart and see the provider) while masking the
    rest of the local part -- the part that identifies the individual. For a
    single-character local part nothing of it survives::

        john.doe@example.com -> j*******@example.com
        a@example.com        -> *@example.com
    """
    local, _, domain = email.partition("@")
    if not domain:
        return email  # not actually an address; leave untouched
    if len(local) <= 1:
        masked = "*"
    else:
        masked = local[0] + "*" * (len(local) - 1)
    return f"{masked}@{domain}"


def _itin_valid(candidate: str) -> bool:
    """Return ``True`` if a string is a structurally valid US ITIN.

    An ITIN (Individual Taxpayer Identification Number) is the nine-digit tax
    processing number the IRS issues to people who must file a US tax return but
    are not eligible for an SSN -- a high-value piece of US tax PII, and the
    direct counterpart to the SSN for the non-citizen / resident-alien
    population a fintech serves. It shares the SSN ``NNN-NN-NNNN`` presentation,
    so a plain SSN-shaped matcher cannot tell the two apart; the distinction is
    purely structural and public (IRS Publication 4757):

        1. **Area** -- the first three digits are always ``900``-``999``. An SSN
           area never begins with ``9``, so a leading ``9`` is what cleanly
           separates an ITIN from a real SSN with no overlap.
        2. **Middle group** -- the 4th-5th digits fall only in the IRS-assigned
           ranges ``50``-``65``, ``70``-``88``, ``90``-``92``, or ``94``-``99``.
           The gaps (``66``-``69``, ``89``, ``93``) are reserved for other
           programs (``93`` is the ATIN range) and never assigned to an ITIN.

    A run that clears both gates is a near-certain real ITIN; an SSN (area not
    ``9XX``) or a coincidental ``9XX-NN-NNNN`` token with an out-of-range middle
    group fails one of them and is left to the SSN detector or dropped. Any
    malformed input returns ``False`` so the helper is safe to reuse.
    """
    digits = re.sub(r"[-\s]", "", candidate.strip())
    if len(digits) != 9 or not digits.isdigit():
        return False
    area = int(digits[:3])
    if not (900 <= area <= 999):
        return False
    middle = int(digits[3:5])
    return any(low <= middle <= high for low, high in _ITIN_MIDDLE_RANGES)


def _redact_itin(text: str) -> str:
    return _ITIN_RE.sub("9XX-XX-XXXX", text)


def _redact_ssn(text: str) -> str:
    return _SSN_RE.sub("XXX-XX-XXXX", text)


def _redact_digits(text: str) -> str:
    return re.sub(r"\d", "X", text)


def _redact_iban(iban: str) -> str:
    """Redact an IBAN, preserving only the country code for triage.

    The two-letter country code identifies the jurisdiction (useful for a
    report) while the check digits and the entire BBAN -- the part that is the
    actual account secret -- are masked. Spaces in the original presentation are
    preserved so the masked shape still reads as an IBAN.
    """
    out = []
    seen_alnum = 0
    for ch in iban:
        if ch == " ":
            out.append(" ")
        elif ch.isalnum():
            seen_alnum += 1
            out.append(ch if seen_alnum <= 2 else "X")
        else:
            out.append(ch)
    return "".join(out)


def _scan_text(
    text: str | None,
    *,
    location: str,
    findings: list[Finding],
    seen: set[tuple[str, str]],
) -> None:
    """Scan a single free-text field for leaked secrets."""
    if not text:
        return

    # ITINs (US Individual Taxpayer Identification Number) -- check BEFORE the
    # SSN detector. An ITIN shares the exact ``NNN-NN-NNNN`` presentation of an
    # SSN, but it is a structurally distinct identifier (area always 900-999,
    # IRS-assigned middle group). We claim a valid ITIN here and reserve its run
    # under the ``ssn`` namespace so the SSN detector below never re-reports the
    # same value as a generic "SSN-shaped" finding. A real SSN (area not 9XX)
    # fails the ITIN gate and falls through to the SSN detector unchanged.
    for m in _ITIN_RE.finditer(text):
        if not _itin_valid(m.group(0)):
            continue
        key = ("ssn", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="itin",
                severity="critical",
                message="US Individual Taxpayer Identification Number (ITIN, "
                "valid 9XX area and IRS-assigned middle group) leaking into a "
                "free-text field -- direct US tax PII.",
                location=location,
                evidence=_redact_itin(m.group(0)),
            )
        )

    for m in _SSN_RE.finditer(text):
        key = ("ssn", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="ssn",
                severity="critical",
                message="SSN-shaped value found in a free-text field.",
                location=location,
                evidence=_redact_ssn(m.group(0)),
            )
        )

    # Email addresses -- a direct, high-precision PII leak. An email is
    # structurally unambiguous (``local@domain`` with a dotted, letter-TLD
    # domain), so it never overlaps the numeric/identifier detectors below and
    # needs no dedupe coordination with them. We dedupe case-insensitively so the
    # same address written in different cases collapses to one finding per field.
    for m in _EMAIL_RE.finditer(text):
        email = m.group(0)
        key = ("email_address", email.lower())
        if key in seen:
            continue
        seen.add(key)
        # An address can carry a long digit run in its local part (e.g. a numeric
        # user id) that the account / card / routing scanners below would
        # otherwise re-report as a separate finding. Reserve every digit run in
        # the address so the same leak is counted once, as the email it is.
        for run in re.findall(r"\d+", email):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="email_address",
                severity="high",
                message="Email address leaking into a free-text field -- direct "
                "PII (GDPR/CCPA personal data) that should not travel in a "
                "statement export.",
                location=location,
                evidence=_redact_email(email),
            )
        )

    # IBANs (ISO 13616) -- check before the credit-card and account-number runs.
    # An IBAN is an alphanumeric run, so it can embed long digit sequences that
    # the card / account / routing scanners would otherwise misclassify. We gate
    # on the country code, the registered length, AND the mod-97 checksum, so a
    # coincidental alphanumeric blob is vanishingly unlikely to be reported.
    for m in _IBAN_RE.finditer(text):
        candidate = _trim_to_valid_iban(m.group(0))
        if candidate is None:
            continue
        compact = candidate.replace(" ", "").upper()
        key = ("iban", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve every digit run inside the IBAN under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # leak as a separate finding.
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="iban",
                severity="high",
                message="International Bank Account Number (IBAN, valid "
                "country/length/mod-97 checksum) leaking into a free-text field.",
                location=location,
                evidence=_redact_iban(candidate),
            )
        )

    # LEIs (ISO 17442) -- check before the shorter securities identifiers and the
    # credit-card / account-number runs. An LEI is a 20-char alphanumeric run that
    # can embed long digit tails the account / card scanners would otherwise
    # misclassify. We gate on the exact 20-char shape AND the ISO 7064 mod-97-10
    # check digits, so a coincidental alphanumeric blob is vanishingly unlikely to
    # be reported. An LEI discloses the legal entity (counterparty / issuer / fund
    # manager) behind a transaction -- a counterparty-confidentiality leak.
    for m in _LEI_RE.finditer(text):
        candidate = m.group(0)
        if not _lei_valid(candidate):
            continue
        compact = candidate.upper()
        key = ("lei", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve any digit run inside the LEI under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # identifier as a separate finding.
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="lei",
                severity="high",
                message="Legal Entity Identifier (LEI, valid ISO 17442 "
                "mod-97-10 check digits) leaking into a free-text field -- "
                "discloses the legal entity behind a transaction.",
                location=location,
                evidence=_redact_lei(compact),
            )
        )

    # BICs / SWIFT codes (ISO 9362) -- check before the securities identifiers and
    # the credit-card / account-number runs. A BIC is an 8- or 11-char run that is
    # mostly letters and is gated on its strict structure, a registered ISO 3166-1
    # country code, AND the ISO 9362 location-code rules -- there is no arithmetic
    # checksum, but the country gate plus the location rules make a coincidental
    # word vanishingly unlikely to validate. A BIC discloses the financial
    # institution behind a transaction (and pairs with an IBAN to fully identify a
    # bank account), so an echo into free text is a counterparty-confidentiality
    # leak.
    for m in _BIC_RE.finditer(text):
        candidate = m.group(0)
        if not _bic_valid(candidate):
            continue
        compact = candidate.upper()
        key = ("bic", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve any digit run inside the BIC under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # identifier (a BIC's location/branch code may contain digits).
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="bic",
                severity="high",
                message="Bank Identifier Code (BIC/SWIFT, valid ISO 9362 "
                "structure and country code) leaking into a free-text field -- "
                "identifies the financial institution behind a transaction.",
                location=location,
                evidence=_redact_bic(compact),
            )
        )

    # ISINs (ISO 6166) -- check before the credit-card and account-number runs.
    # An ISIN is a 12-char alphanumeric run that can embed a long digit tail the
    # account / card scanners would otherwise misclassify. We gate on the exact
    # 12-char shape AND the ISO 6166 Luhn check digit, so a coincidental
    # alphanumeric blob is vanishingly unlikely to be reported.
    for m in _ISIN_RE.finditer(text):
        candidate = m.group(0)
        if not _isin_valid(candidate):
            continue
        compact = candidate.upper()
        key = ("isin", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve any digit run inside the ISIN under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # identifier as a separate finding.
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="isin",
                severity="high",
                message="International Securities Identification Number (ISIN, "
                "valid ISO 6166 check digit) leaking into a free-text field.",
                location=location,
                evidence=_redact_isin(compact),
            )
        )

    # CUSIPs (US/Canada securities identifier) -- check after the 12-char ISIN
    # (a US ISIN embeds a CUSIP as its NSIN, so the longer match wins there) and
    # before the credit-card / account / routing scanners. We require a letter in
    # the base (enforced by the regex) so a purely numeric 9-digit value -- which
    # lives in the ABA routing-number space -- is never reclassified here. A
    # match is gated on the public CUSIP modulus-10 check digit, so a coincidental
    # 9-char alphanumeric run is vanishingly unlikely to be reported.
    for m in _CUSIP_RE.finditer(text):
        candidate = m.group(0)
        if not _cusip_valid(candidate):
            continue
        compact = candidate.upper()
        key = ("cusip", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve any digit run inside the CUSIP under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # identifier as a separate finding.
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="cusip",
                severity="high",
                message="CUSIP securities identifier (valid check digit) "
                "leaking into a free-text field -- discloses a customer's "
                "securities holding.",
                location=location,
                evidence=_redact_cusip(compact),
            )
        )

    # SEDOLs (UK/Ireland securities identifier) -- check after the longer ISIN
    # and CUSIP identifiers (so the longest match wins for an overlapping run)
    # and before the credit-card / account / routing scanners. The regex forbids
    # vowels in the base and requires at least one letter, so a purely numeric
    # 7-digit run is never reclassified here. A match is gated on the public
    # SEDOL weighted modulus-10 check digit, so a coincidental 7-char alphanumeric
    # run is vanishingly unlikely to be reported.
    for m in _SEDOL_RE.finditer(text):
        candidate = m.group(0)
        if not _sedol_valid(candidate):
            continue
        compact = candidate.upper()
        key = ("sedol", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve any digit run inside the SEDOL under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # identifier as a separate finding.
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="sedol",
                severity="high",
                message="SEDOL securities identifier (valid check digit) "
                "leaking into a free-text field -- discloses a customer's "
                "securities holding.",
                location=location,
                evidence=_redact_sedol(compact),
            )
        )

    # UK sort codes (NN-NN-NN) -- the hyphenated UK routing code. The hyphenated
    # shape is distinct from any contiguous digit run, so this scan neither
    # competes with nor is double-counted against the card / account / routing
    # scanners below (those match contiguous digits; a sort code's hyphens break
    # the run into three two-digit pieces, none of which the 8+/9-digit scanners
    # will match). We gate on the hyphenated shape AND the assigned clearing-range
    # leading pair, so a coincidental NN-NN-NN token is unlikely to be reported. A
    # sort code echoed into free text discloses the UK bank/branch routing of an
    # account -- the domestic equivalent of an ABA routing-number leak.
    for m in _UK_SORT_CODE_RE.finditer(text):
        candidate = m.group(0)
        if not _uk_sort_code_valid(candidate):
            continue
        key = ("uk_sort_code", candidate)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="uk_sort_code",
                severity="high",
                message="UK sort code (valid NN-NN-NN structure and assigned "
                "clearing-range prefix) leaking into a free-text field -- "
                "discloses the bank/branch routing of an account.",
                location=location,
                evidence=_redact_uk_sort_code(candidate),
            )
        )

    # Canadian routing numbers (TTTTT-III, the MICR cheque-encoding form) -- the
    # Canadian domestic routing code. Like the UK sort code its hyphenated shape
    # is distinct from any contiguous digit run, so this scan neither competes
    # with nor is double-counted against the card / account / routing scanners
    # below (those match contiguous digits; the hyphen breaks the token into a
    # five- and a three-digit piece, neither of which the 8+/9-digit scanners
    # match). Its 5-3 split is also distinct from the UK sort code's 2-2-2 and the
    # SSN's 3-2-4, so the three hyphenated detectors never collide. We gate on the
    # MICR shape AND the Payments Canada assigned institution number, so a
    # coincidental TTTTT-III token is unlikely to be reported. A Canadian routing
    # number echoed into free text discloses the bank/branch routing of an
    # account -- the Canadian-domestic companion to the ABA and UK-sort-code
    # detectors.
    for m in _CA_ROUTING_RE.finditer(text):
        candidate = m.group(0)
        if not _ca_routing_valid(candidate):
            continue
        key = ("ca_routing_number", candidate)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="ca_routing_number",
                severity="high",
                message="Canadian routing number (valid TTTTT-III MICR structure "
                "and assigned institution number) leaking into a free-text field "
                "-- discloses the bank/branch routing of an account.",
                location=location,
                evidence=_redact_ca_routing(candidate),
            )
        )

    # Australian BSB codes (NNN-NNN, the canonical Bank-State-Branch form) -- the
    # Australian domestic routing code. Like the UK sort code and the Canadian
    # routing number its hyphenated shape is distinct from any contiguous digit
    # run, so this scan neither competes with nor is double-counted against the
    # card / account / routing scanners below (those match contiguous digits; the
    # hyphen breaks the token into two three-digit pieces, neither of which the
    # 8+/9-digit scanners match). Its 3-3 split is also distinct from the SSN's
    # 3-2-4, the UK sort code's 2-2-2, and the Canadian routing number's 5-3, so
    # the four hyphenated detectors never collide. We gate on the NNN-NNN shape AND
    # the assigned AusPayNet bank prefix, so a coincidental NNN-NNN token is
    # unlikely to be reported. A BSB echoed into free text discloses the
    # bank/branch routing of an account -- the Australian-domestic companion to the
    # ABA, UK-sort-code, and Canadian-routing detectors.
    for m in _AU_BSB_RE.finditer(text):
        candidate = m.group(0)
        if not _au_bsb_valid(candidate):
            continue
        key = ("au_bsb", candidate)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="au_bsb",
                severity="high",
                message="Australian BSB code (valid NNN-NNN structure and "
                "assigned bank prefix) leaking into a free-text field -- "
                "discloses the bank/branch routing of an account.",
                location=location,
                evidence=_redact_au_bsb(candidate),
            )
        )

    # Indian IFSC codes (BBBB0BRANCH) -- the Indian domestic branch-routing code.
    # An IFSC is an 11-char alphanumeric run that can embed a digit tail in its
    # branch code, so we check it before the account / card scanners and reserve
    # those digits so the same leak is never re-reported as a slice. Its
    # mandatory letter prefix and reserved fifth-position zero make the structure
    # distinct from the hyphenated routing codes above and from any contiguous
    # digit run, so the detectors never collide. We gate on the strict structure,
    # so a coincidental 11-char token is vanishingly unlikely to be reported. An
    # IFSC echoed into free text discloses the bank/branch routing of an account
    # -- the Indian-domestic companion to the ABA, UK-sort-code, Canadian-routing,
    # and Australian-BSB detectors.
    for m in _IFSC_RE.finditer(text):
        candidate = m.group(0)
        if not _ifsc_valid(candidate):
            continue
        compact = candidate.upper()
        key = ("ifsc", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve any digit run inside the IFSC under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # identifier (an IFSC branch code may contain digits).
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="ifsc",
                severity="high",
                message="Indian Financial System Code (IFSC, valid BBBB0BRANCH "
                "structure) leaking into a free-text field -- discloses the "
                "bank/branch routing of an account.",
                location=location,
                evidence=_redact_ifsc(compact),
            )
        )

    # Mexican CLABE numbers (18 contiguous digits) -- the Mexican standardized
    # bank-account number. Unlike the hyphenated routing codes a CLABE is a
    # contiguous digit run, so it would otherwise be claimed by the credit-card
    # (13-19 digit) and the account-number (8+ digit) scanners below. We check it
    # first, gate on the non-zero bank code AND the public mod-10 weighted control
    # digit, and reserve the run under every numeric namespace so the same leak is
    # never re-reported as a card or a generic account number. A CLABE echoed into
    # free text is a near-certain Mexican bank-account leak -- on its own it is the
    # value needed to route a SPEI transfer into the account.
    for m in _CLABE_RE.finditer(text):
        digits = m.group(0)
        if not _clabe_valid(digits):
            continue
        key = ("clabe", digits)
        if key in seen:
            continue
        seen.add(key)
        # Reserve the run under the card / account / routing namespaces so the
        # scanners below never re-report a slice of the same CLABE.
        seen.add(("credit_card", digits))
        seen.add(("account_number", digits))
        seen.add(("routing_number", digits))
        findings.append(
            Finding(
                check="pii",
                type="clabe",
                severity="high",
                message="Mexican CLABE (valid 18-digit structure, non-zero bank "
                "code, and mod-10 control digit) leaking into a free-text field "
                "-- discloses a bank account routable for a SPEI transfer.",
                location=location,
                evidence=_redact_clabe(digits),
            )
        )

    # Mexican CURP (18 contiguous characters, AAAA NNNNNN S EE CCC X D) -- the
    # Mexican population-registry identity key. Unlike the CLABE (18 *digits*) a
    # CURP leads with four LETTERS, so the two 18-character Mexican identifiers
    # never collide, and the only contiguous digit run inside a CURP is the
    # six-digit birth date -- too short for the account (8+) / routing (9) / card
    # (13+) scanners to claim -- so it neither competes with nor is double-counted
    # against them. We still reserve every digit run under the numeric namespaces
    # for robustness, exactly as the IFSC / LEI scans do. We gate on the strict
    # structure, a real embedded birth date, the registered state code, AND the
    # public mod-10 check digit, so a coincidental 18-character token is
    # vanishingly unlikely to be reported. A CURP echoed into free text discloses a
    # named individual's identity -- a direct, high-value Mexican PII leak, the
    # identity-key companion to the CLABE's account-routing leak.
    for m in _CURP_RE.finditer(text):
        candidate = m.group(0)
        if not _curp_valid(candidate):
            continue
        compact = candidate.upper()
        key = ("curp", compact)
        if key in seen:
            continue
        seen.add(key)
        # Reserve any digit run inside the CURP under the account/card/routing
        # namespaces so the scanners below never re-report a slice of the same
        # identifier (the embedded birth date and the homoclave may be digits).
        for run in re.findall(r"\d+", compact):
            seen.add(("account_number", run))
            seen.add(("credit_card", run))
            seen.add(("routing_number", run))
        findings.append(
            Finding(
                check="pii",
                type="curp",
                severity="high",
                message="Mexican CURP (valid 18-char structure, birth date, "
                "registered state code, and mod-10 check digit) leaking into a "
                "free-text field -- discloses a named individual's identity.",
                location=location,
                evidence=_redact_curp(compact),
            )
        )

    # South Korean Giro numbers (NNNNN-NN, the canonical 5-2 grouped form) -- the
    # South Korean domestic biller-routing code. Like the UK sort code / Canadian
    # routing number / Australian BSB its hyphenated shape is distinct from any
    # contiguous digit run, so this scan neither competes with nor is
    # double-counted against the card / account / routing scanners below (those
    # match contiguous digits; the hyphen breaks the token into a five- and a
    # two-digit piece, neither of which the 8+/9-digit scanners match). Its 5-2
    # split is also distinct from the SSN's 3-2-4, the UK sort code's 2-2-2, the
    # Canadian routing number's 5-3, and the Australian BSB's 3-3, so the five
    # hyphenated detectors never collide. We gate on the NNNNN-NN shape, the
    # non-zero payee block, AND the public mod-10 weighted check digit, so a
    # coincidental NNNNN-NN token is vanishingly unlikely to be reported. A Giro
    # number echoed into free text discloses the biller/payee routing of a
    # payment -- the South Korean-domestic companion to the ABA, UK-sort-code,
    # Canadian-routing, Australian-BSB, and Indian-IFSC detectors.
    for m in _KR_GIRO_RE.finditer(text):
        candidate = m.group(0)
        if not _kr_giro_valid(candidate):
            continue
        key = ("kr_giro", candidate)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="kr_giro",
                severity="high",
                message="South Korean Giro number (valid NNNNN-NN structure, "
                "non-zero payee block, and mod-10 check digit) leaking into a "
                "free-text field -- discloses the biller/payee routing of a "
                "payment.",
                location=location,
                evidence=_redact_kr_giro(candidate),
            )
        )

    # Thai national IDs (N-NNNN-NNNNN-NN-N, the canonical 1-4-5-2-1 grouped form)
    # -- the Thai PromptPay payee proxy id. The hyphenated 1-4-5-2-1 split is
    # distinct from every other hyphenated detector (the SSN's 3-2-4, the UK sort
    # code's 2-2-2, the Canadian routing number's 5-3, the Australian BSB's 3-3,
    # and the South Korean Giro's 5-2), so the detectors never collide. BUT the
    # whole token, with its single-dash separators read as the conventional digit
    # grouping, also satisfies the 13-19-digit credit-card matcher below -- so,
    # like the CLABE, we check it FIRST and reserve the compact 13-digit run under
    # the card / account / routing namespaces so the same leak is never re-reported
    # as a card or a generic account number. We gate on the 1-4-5-2-1 shape, the
    # 1-8 category digit, AND the public mod-11 weighted check digit, so a
    # coincidental token is vanishingly unlikely to be reported. A national ID
    # echoed into free text discloses the PromptPay proxy id a payer routes an
    # instant transfer against -- a direct Thai PII / payment-routing leak.
    for m in _TH_NATID_RE.finditer(text):
        candidate = m.group(0)
        if not _th_natid_valid(candidate):
            continue
        key = ("th_natid", candidate)
        if key in seen:
            continue
        seen.add(key)
        # Reserve the compact 13-digit run under the card / account / routing
        # namespaces so the scanners below never re-report a slice of the same ID.
        compact = candidate.replace("-", "")
        seen.add(("credit_card", compact))
        seen.add(("account_number", compact))
        seen.add(("routing_number", compact))
        findings.append(
            Finding(
                check="pii",
                type="th_natid",
                severity="high",
                message="Thai national ID / PromptPay proxy id (valid "
                "N-NNNN-NNNNN-NN-N structure, category digit, and mod-11 check "
                "digit) leaking into a free-text field -- discloses the proxy id "
                "a PromptPay transfer routes against.",
                location=location,
                evidence=_redact_th_natid(candidate),
            )
        )

    # Brazilian CPFs (NNN.NNN.NNN-NN, the canonical 3.3.3-2 dotted-and-dashed
    # form) -- the Brazilian individual taxpayer registry number and Pix payee
    # key. The dotted presentation is the ONLY detector that uses ``.``
    # separators, so it is distinct from every hyphenated detector (the SSN's
    # 3-2-4, the UK sort code's 2-2-2, the Canadian routing number's 5-3, the
    # Australian BSB's 3-3, the South Korean Giro's 5-2, and the Thai national
    # ID's 1-4-5-2-1) and from any contiguous digit run, so the detectors never
    # collide. We gate on the 3.3.3-2 shape, the all-same-digit rejection, AND the
    # two public mod-11 weighted check digits, so a coincidental token is
    # vanishingly unlikely to be reported. A CPF echoed into free text discloses
    # the Pix key a payer routes an instant transfer against -- a direct Brazilian
    # PII / payment-routing leak. We reserve the compact 11-digit run under the
    # account / routing namespaces so the digit scanners below never re-report a
    # slice of the same id (the dotted presentation already breaks the run, but
    # the reservation keeps the guarantee explicit and robust).
    for m in _BR_CPF_RE.finditer(text):
        candidate = m.group(0)
        if not _br_cpf_valid(candidate):
            continue
        key = ("br_cpf", candidate)
        if key in seen:
            continue
        seen.add(key)
        compact = re.sub(r"[.\-]", "", candidate)
        seen.add(("account_number", compact))
        seen.add(("routing_number", compact))
        findings.append(
            Finding(
                check="pii",
                type="br_cpf",
                severity="high",
                message="Brazilian CPF (valid NNN.NNN.NNN-NN structure, "
                "all-same-digit rejection, and two mod-11 check digits) leaking "
                "into a free-text field -- discloses the taxpayer id / Pix key a "
                "payer routes a transfer against.",
                location=location,
                evidence=_redact_br_cpf(candidate),
            )
        )

    # Credit-card / PAN numbers -- check before the generic account-number run
    # so a Luhn-valid card is reported as the (critical) PCI-DSS leak it is, not
    # downgraded to a plain account-number finding. A card may be written with
    # the conventional space/dash grouping, so we strip separators before
    # validating the Luhn checksum and recording the run for dedupe. Runs that
    # fail Luhn are left untouched here and fall through to the account-number /
    # routing-number scanners below.
    for m in _CARD_RE.finditer(text):
        compact = re.sub(r"[ -]", "", m.group(0))
        if not (_CARD_MIN_LEN <= len(compact) <= _CARD_MAX_LEN):
            continue
        if not _luhn_valid(compact):
            continue
        # Dedupe on the compact digits so the same card written two different
        # ways (spaced vs unspaced) is reported once, and so the account-number
        # scanner below skips a run it has already claimed.
        key = ("credit_card", compact)
        if key in seen:
            continue
        seen.add(key)
        # Also reserve the compact digits under the account_number namespace so
        # the 8+-digit scanner never re-reports the same run as an account
        # number (it matches on contiguous digits, which the card may contain
        # when written without separators).
        seen.add(("account_number", compact))
        findings.append(
            Finding(
                check="pii",
                type="credit_card",
                severity="critical",
                message="Payment-card number (passing the Luhn checksum) "
                "leaking into a free-text field -- PCI-DSS sensitive.",
                location=location,
                evidence=_redact_digits(m.group(0)),
            )
        )

    # Routing numbers (exactly 9 digits) -- check before generic account runs.
    # Gate the high-severity finding behind the ABA weighted checksum: a run
    # that passes is a near-certain routing-number leak; one that fails is most
    # likely a coincidental 9-digit value (zip+4, phone, order/EIN-shaped) and
    # is downgraded to an informational ``probable_routing_number`` so we keep
    # visibility without flooding reports with high-severity false positives.
    for m in _ROUTING_RE.finditer(text):
        digits = m.group(0)
        # Use a single dedupe namespace so the same 9-digit run is never both
        # classified as a routing/probable finding and an account-number run.
        key = ("routing_number", digits)
        if key in seen:
            continue
        seen.add(key)
        if _aba_checksum_valid(digits):
            findings.append(
                Finding(
                    check="pii",
                    type="routing_number",
                    severity="high",
                    message="9-digit ABA routing number (valid checksum) "
                    "leaking into free text.",
                    location=location,
                    evidence=_redact_digits(digits),
                )
            )
        else:
            findings.append(
                Finding(
                    check="pii",
                    type="probable_routing_number",
                    severity="info",
                    message="9-digit value shaped like a routing number but "
                    "failing the ABA checksum (likely a coincidental run).",
                    location=location,
                    evidence=_redact_digits(digits),
                )
            )

    # Account-number-shaped runs (8+ digits), excluding ones already counted
    # as a 9-digit routing number.
    for m in _ACCT_RE.finditer(text):
        if len(m.group(0)) == 9:
            continue  # already classified as routing above
        key = ("account_number", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="account_number",
                severity="high",
                message="Account-number-shaped digit run leaking into free text.",
                location=location,
                evidence=_redact_digits(m.group(0)),
            )
        )


def _scan_secid(
    secid: str | None,
    *,
    location: str,
    findings: list[Finding],
    seen: set[tuple[str, str]],
) -> None:
    """Scan an investment security id for leaked PII.

    A security identifier is a CUSIP (9 alphanumeric chars) or ISIN (12 chars).
    Both are *expected* to be short, fixed-length codes, so we deliberately do
    NOT run the generic free-text scanner here -- a perfectly normal 9-digit
    numeric CUSIP would otherwise trip the routing-number heuristic on every
    investment statement. Instead we only flag the two patterns that are
    unambiguous leaks in this field:

    - an SSN-shaped value (``NNN-NN-NNNN``) -- structurally impossible for a real
      security id, so any match is a leak; and
    - a digit run of 10 or more characters -- longer than any CUSIP/ISIN, so it
      is an account-number-shaped value smuggled into the security id.
    """
    if not secid:
        return

    # ITINs -- checked before the SSN detector, sharing the ``ssn`` dedupe
    # namespace, exactly as in the free-text scanner. A valid ITIN smuggled into
    # a security id is reported as the ITIN it is; a real SSN falls through.
    for m in _ITIN_RE.finditer(secid):
        if not _itin_valid(m.group(0)):
            continue
        key = ("ssn", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="itin",
                severity="critical",
                message="US Individual Taxpayer Identification Number (ITIN, "
                "valid 9XX area and IRS-assigned middle group) found in an "
                "investment security id -- direct US tax PII.",
                location=location,
                evidence=_redact_itin(m.group(0)),
            )
        )

    for m in _SSN_RE.finditer(secid):
        key = ("ssn", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="ssn",
                severity="critical",
                message="SSN-shaped value found in an investment security id.",
                location=location,
                evidence=_redact_ssn(m.group(0)),
            )
        )

    for m in re.finditer(r"\b\d{10,}\b", secid):
        key = ("account_number", m.group(0))
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                check="pii",
                type="account_number",
                severity="high",
                message="Account-number-shaped digit run leaking into an "
                "investment security id.",
                location=location,
                evidence=_redact_digits(m.group(0)),
            )
        )


def check_pii(raw: bytes) -> list[Finding]:
    """Scan well-formed OFX bytes for PII exposure in free-text fields."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for s_idx, stmt in enumerate(parse_statements(raw)):
        for t_idx, tx in enumerate(stmt.transactions):
            base = f"statement[{s_idx}].transaction[{t_idx}]"
            fitid = f" (fitid {tx.fitid})" if tx.fitid else ""
            _scan_text(
                tx.name,
                location=f"{base}.name{fitid}",
                findings=findings,
                seen=seen,
            )
            _scan_text(
                tx.memo,
                location=f"{base}.memo{fitid}",
                findings=findings,
                seen=seen,
            )
            # Investment transactions expose a security identifier (CUSIP/ISIN
            # via UNIQUEID). A legitimate CUSIP is a 9-character alphanumeric
            # code, but a backend that echoes an SSN- or account-shaped value
            # into the security id is leaking PII through a field a bank/credit
            # statement does not even have -- so we scan it too.
            if tx.is_investment and tx.secid:
                _scan_secid(
                    tx.secid,
                    location=f"{base}.secid{fitid}",
                    findings=findings,
                    seen=seen,
                )

    return findings
