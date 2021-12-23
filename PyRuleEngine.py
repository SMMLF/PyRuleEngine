"""
Library to implement hashcat style rule engine.
"""
import re

# based on hashcat rules from
# https://hashcat.net/wiki/doku.php?id=rule_based_attack
from typing import Tuple, List


def i36(string):
    """Shorter way of converting base 36 string to integer"""
    return int(string, 36)


def rule_regex_gen():
    """Generates regex to parse rules"""
    __rules__ = [
        ':', 'l', 'u', 'c', 'C', 't', r'T\w', 'r', 'd', r'p\w', 'f', '{',
        '}', '$.', '^.', '[', ']', r'D\w', r'x\w\w', r'O\w\w', r'i\w.',
        r'o\w.', r"'\w", 's..', '@.', r'z\w', r'Z\w', 'q',
    ]
    __rules__ += [r'X\w\w\w', '4', '6', 'M']
    for i, func in enumerate(__rules__):
        __rules__[i] = func[0] + func[1:].replace(r'\w', '[a-zA-Z0-9]')
    rule_regex = '|'.join(['%s%s' % (re.escape(a[0]), a[1:]) for a in __rules__])
    return re.compile(rule_regex)


__rule_regex__ = rule_regex_gen()

function_map = {
    ':': lambda x, i: x,
    'l': lambda x, i: x.lower(),
    'u': lambda x, i: x.upper(),
    'c': lambda x, i: x.capitalize(),
    'C': lambda x, i: x.capitalize().swapcase(),
    't': lambda x, i: x.swapcase()
}


def T(x, i):
    number = i36(i)
    return ''.join((x[:number], x[number].swapcase(), x[number + 1:]))


function_map['T'] = T
function_map['r'] = lambda x, i: x[::-1]
function_map['d'] = lambda x, i: x + x
function_map['p'] = lambda x, i: x * (i36(i) + 1)
function_map['f'] = lambda x, i: x + x[::-1]
function_map['{'] = lambda x, i: x[1:] + x[0]
function_map['}'] = lambda x, i: x[-1] + x[:-1]
function_map['$'] = lambda x, i: x + i
function_map['^'] = lambda x, i: i + x
function_map['['] = lambda x, i: x[1:]
function_map[']'] = lambda x, i: x[:-1]
function_map['D'] = lambda x, i: x[:i36(i) - 1] + x[i36(i):]
function_map['x'] = lambda x, i: x[i36(i[0]):i36(i[1])]
function_map['O'] = lambda x, i: x[:i36(i[0])] + x[i36(i[1]) + 1:]
function_map['i'] = lambda x, i: x[:i36(i[0])] + i[1] + x[i36(i[0]):]
function_map['o'] = lambda x, i: x[:i36(i[0])] + i[1] + x[i36(i[0]) + 1:]
function_map["'"] = lambda x, i: x[:i36(i)]
function_map['s'] = lambda x, i: x.replace(i[0], i[1])
function_map['@'] = lambda x, i: x.replace(i, '')
function_map['z'] = lambda x, i: x[0] * i36(i) + x
function_map['Z'] = lambda x, i: x + x[-1] * i36(i)
function_map['q'] = lambda x, i: ''.join([a * 2 for a in x])

__memorized__ = ['']


def extract_memory(string, args):
    """Insert section of stored string into current string"""
    pos, length, i = map(i36, args)
    string = list(string)
    string.insert(i, __memorized__[0][pos:pos + length])
    return ''.join(string)


function_map['X'] = extract_memory
function_map['4'] = lambda x, i: x + __memorized__[0]
function_map['6'] = lambda x, i: __memorized__[0] + x


def memorize(string, _):
    """Store current string in memory"""
    __memorized__[0] = string
    return string


function_map['M'] = memorize


class RuleEngine(object):
    """
    Rules must be sequence of strings which are Hashcat style rules. Invalid
    rules will be ignored, and won't raise exceptions. Whitespace will be
    ignored if it is between individual functions in a rule, but if whitespace
    is put where the arguments would be then the whitespace will be tret as if
    it was the argument.
    e.g. '$l' will append letter 'l', but '$ l' will append ' ' and then
    lowercase the whole string. (Below I added an l append 'y' just to make it
    clear that a space was added)
    >>> for i in RuleEngine(['$l $y', '$ l$y']).apply('PASSWORD'):
    ...        print(i)
    PASSWORDly
    password y

    Initiate with the rules you want to apply and then call .apply for each
    string you want to apply the rules to.
    >>> engine=RuleEngine([':', '$1', 'ss$'])
    >>> for i in engine.apply('password'):
    ...        print(i)
    password
    password1
    pa$$word
    >>> for i in engine.apply('princess'):
    ...        print(i)
    princess
    princess1
    prince$$
    """

    def __init__(self, rules=None):
        if rules is None:
            rules = [':']
        self.rules = tuple(map(__rule_regex__.findall, rules))

    def apply(self, string: str) -> Tuple[str, List[str]]:
        """
        Apply saved rules to given string. It returns a generator object, so you
        can't use list indexes on it. """
        for rule in self.rules:
            word = string
            for function in rule:
                try:
                    key = function[0]
                    func = function_map[key]
                    remain = function[1:]
                    word = func(word, remain)
                except IndexError:
                    """Some operation like T8 could raise IndexError because the password could be too short."""
            yield word, rule

    def change_rules(self, new_rules):
        """Replace current rules with new_rules"""
        self.rules = tuple(map(__rule_regex__.findall, new_rules))


if __name__ == "__main__":
    pass
