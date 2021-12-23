import random
import string
import time
from collections import defaultdict

import PyRuleEngine


def read_rules(rule_path):
    with open(rule_path, 'r') as f_rule:
        raw_rules = [r.strip() for r in f_rule]
        rules = [r for r in raw_rules if r and r[0] != '#']
    return rules


def wrapper(rules_path, log_path):
    input_list = [''.join(random.choice(string.printable) for _ in range(10))
                  for _ in range(1000000)]
    engines = []
    rules = read_rules(rules_path)
    for rule in rules:
        engines.append((rule, PyRuleEngine.RuleEngine([rule])))
    for rule, engine in engines:
        start = time.time()
        for base in input_list:
            list(engine.apply(base))
        log_path.write('%s%s%s\n' % (rule, ' ' * (10 - len(rule)),
                                     round(time.time() - start, 4)))


def read_words(words_path):
    words = []
    with open(words_path, 'r') as f_words:
        for line in f_words:
            line = line.strip('\r\n')
            words.append(line)
    return words


def read_target(target_path):
    pwd_set = defaultdict(int)
    with open(target_path, 'r') as f_target:
        for line in f_target:
            line = line.strip('\r\n')
            pwd_set[line] += 1
        pass
    return pwd_set


def py_hashcat_wrapper(words_path, rules_path, log_path, target_path):
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    max_len = 16
    pwd_num = 10000
    if words_path is not None:
        word_list = read_words(words_path)
    else:
        word_list = [''.join(random.choice(chars) for _ in range(max_len)) for _ in range(pwd_num)]
    rules = read_rules(rule_path=rules_path)
    targets = read_target(target_path) if target_path else defaultdict(int)
    engine = PyRuleEngine.RuleEngine(rules=rules)
    very_start = time.time()
    guesses = 0
    for i, base in enumerate(word_list):
        n = 0
        for pwd in engine.apply(base):
            n += 1
            if pwd in targets:
                # do something
                pass
            pass
        guesses += n
        if i % 2048 == 0:
            acc = time.time() - very_start
            avg = guesses / acc
            log_path.write(f"PW: {i + 1:7}; G: {guesses:10}; avg: {avg:10.2f}g/s; acc: {acc:10.4f}s\n")
            log_path.flush()
        pass

    very_end = time.time()
    acc = very_end - very_start
    avg = guesses / acc
    log_path.write(f"PW: {len(word_list):7}; G: {guesses:10}; avg: {avg:10.2f}g/s; acc: {acc:10.4f}s\n")


if __name__ == '__main__':
    with open("bench2.log", 'w') as f_log:
        py_hashcat_wrapper(None, 'InsidePro-PasswordsPro.rule', f_log, None)
    pass
