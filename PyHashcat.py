from collections import defaultdict
from typing import Dict, List, Generator, Tuple

import PyRuleEngine


def read_rules(rule_path) -> List[str]:
    with open(rule_path, 'r') as f_rule:
        raw_rules = [r.strip() for r in f_rule]
        rules = [r for r in raw_rules if r and r[0] != '#']
    return rules


def read_words(words_path) -> Generator[Tuple[int, str]]:
    with open(words_path, 'r') as f_words:
        idx = 0
        for line in f_words:
            line = line.strip('\r\n')
            yield idx, line
            idx += 1


def read_target(target_path) -> Dict[str, int]:
    pwd_set = defaultdict(int)
    with open(target_path, 'r') as f_target:
        for line in f_target:
            line = line.strip('\r\n')
            pwd_set[line] += 1
        pass
    return pwd_set


def py_hashcat(words_path: str, rules_path: str, target_path: str):
    word_list = read_words(words_path=words_path)
    rules = read_rules(rule_path=rules_path)
    targets = read_target(target_path=target_path)
    engine = PyRuleEngine.RuleEngine(rules=rules)
    guess_number = 0
    for i, word in word_list:
        n = 0
        for guess, rule in engine.apply(word):
            n += 1
            if guess in targets:
                yield word, guess, rule, guess_number + n
        guess_number += n
    pass
