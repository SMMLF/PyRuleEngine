"""
Library to implement hashcat style ``reversed`` rule engine.
"""
import re

# based on hashcat rules from
# https://hashcat.net/wiki/doku.php?id=rule_based_attack
from typing import Tuple, List

__p__ = [0]


def i36(string):
    """Shorter way of converting base 36 string to integer"""
    if string == 'p':
        return __p__[0]
    return int(string, 36)


__memorized__ = ['']


def memorize(string, _):
    """Store current string in memory"""
    __memorized__[0] = string
    return string


def rule_regex_gen():
    """Parsing functions"""
    functions = [
        # for PasswordPro and John the Ripper
        ':', 'l', 'u', 'c', 'C', 't', r'T\w', 'r', 'd', r'p\w', 'f', '{',
        '}', '$.', '^.', '[', ']', r'D\w', r'x\w\w', r'O\w\w', r'i\w.',
        r'o\w.', r"'\w", 's..', '@.', r'z\w', r'Z\w', 'q',
        # Memory
        r'X\w\w\w', '4', '6', 'M',
        # only for hashcat
        'k', 'K', r'*\w\w', r'L\w', r'R\w', r'+\w', r'-\w',
        r'.\w', r',\w', r'y\w', r'Y\w', 'E', 'e.', r'3\w.'
    ]
    for i, func in enumerate(functions):
        functions[i] = re.escape(func[0]) + func[1:].replace(r'\w', '[a-zA-Z0-9]')
    rule_regex = '|'.join(functions)
    return re.compile(rule_regex)


__functions_regex__ = rule_regex_gen()

"""
Note that we reverse all operations
"""


def not_implemented(x, i):
    raise NotImplementedError(f"{x}, {i} not implemented")


def T(x, i):
    number = i36(i)
    return ''.join((x[:number], x[number].swapcase(), x[number + 1:]))


def delete_at_n(word, indices):
    n, x = indices
    n = i36(n)
    if n >= len(word) or word[n] != x:
        return word
    return word[:n] + word[n + 1:]


def delete_first_same_n(word, indices):
    n, = indices
    n = i36(n)
    if n <= len(word) and word[:n] == word[0] * n:
        return word[n:]
    return word


def delete_last_same_n(word, indices):
    n, = indices
    n = i36(n)
    if n <= len(word) and word[-n:] == word[-1] * n:
        return word[:-n]
    return word


def delete_doubled(word, _):
    res = []
    for i in range(0, len(word), 2):
        if word[i] == word[i + 1]:
            res.append(word[i])
        else:
            return word
    return "".join(res)


def delete_extracted_memory():
    """Insert section of stored string into current string"""
    saved = __memorized__[0]
    return saved


function_map = {
    ':': lambda x, i: x,
    # 'l' will lower all characters in the word. Therefore, could we
    # generate a word list whose words are all lowered. Thus, we could
    # know that some words are equal to the target word when they apply
    # the function of 'l'.
    # === For rules with a single function. ===
    'l': not_implemented,
    # Similar to 'l', find lowered target word in the lowered word list
    'u': not_implemented,
    # Similar to 'l', a lowered word list, and we find the lowered
    # target word.
    'c': not_implemented,  # x.capitalize(),
    # Same with 'c'
    'C': not_implemented,  # x.capitalize().swapcase(),
    't': lambda x, i: x.swapcase(),
    'T': T,
    'r': lambda x, i: x[::-1],
    'd': lambda x, i: x[:len(x) // 2],
    'p': lambda x, i: x[:len(x) // (i36(i) + 1)],
    'f': lambda x, i: x[:len(x) // 2],
    '{': lambda x, i: x[-1] + x[:-1],
    '}': lambda x, i: x[1:] + x[0],
    '$': lambda x, i: x[:-1] if x[-1] == i[0] else x,
    '^': lambda x, i: x[1:] if x[0] == i[0] else x,
    '[': not_implemented,
    ']': not_implemented,
    'D': not_implemented,
    'x': not_implemented,
    'O': not_implemented,
    'i': delete_at_n,
    'o': not_implemented,
    "'": not_implemented,
    's': lambda x, i: x.replace(i[1], i[0]),
    '@': not_implemented,
    'z': delete_first_same_n,
    'Z': delete_last_same_n,
    'q': delete_doubled,
    'M': not_implemented,
    'X': not_implemented,
    '4': not_implemented,
    '6': not_implemented,
}


class ReversionEngine(object):
    """
    Execute the rule from right to left

    """

    def __init__(self, rules=None):
        if rules is None:
            rules = [':']
        parsed_rules = tuple(map(__functions_regex__.findall, rules))
        self.rules = parsed_rules
        self.reversed_rules = tuple(rule[::-1] for rule in parsed_rules)
        self.indices = range(0, len(self.reversed_rules))

    def apply(self, string: str) -> Tuple[str, List[str]]:
        """
        Apply saved rules to given string. It returns a generator object, so you
        can't use list indexes on it. """
        for idx in self.indices:
            reversed_rule = self.reversed_rules[idx]
            target = string
            for function in reversed_rule:
                try:
                    key = function[0]
                    func = function_map[key]
                    remain = function[1:]
                    target = func(target, remain)
                except IndexError:
                    """Some operation like T8 could raise IndexError because the password could be too short."""
                except NotImplementedError:
                    """Some operation could be hard to reverse"""
            yield target, self.rules[idx]

    def change_rules(self, new_rules):
        """Replace current rules with new_rules"""
        self.rules = tuple(map(__functions_regex__.findall, new_rules))
        self.reversed_rules = tuple(rule[::-1] for rule in self.rules)
        self.indices = range(0, len(self.rules))

    def change_indices(self, new_indices):
        self.indices = new_indices
