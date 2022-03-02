import unittest
from PyReversionEngine import ReversionEngine

reversion_engine = ReversionEngine()


def apply(word, rule):
    """Apply the rule to the given word"""
    reversion_engine.change_rules([rule])
    return list(reversion_engine.apply(word))[0][0]


class ReversionTest(unittest.TestCase):
    def test_toggle_case(self):
        self.assertEqual(apply('P@SSw0RD', 't'), 'p@ssW0rd')

    def test_toggle_n(self):
        self.assertEqual(apply('p@sSW0rd', 'T3'), 'p@ssW0rd')

    def test_reverse(self):
        self.assertEqual(apply('dr0Wss@p', 'r'), 'p@ssW0rd')

    def test_duplicate(self):
        self.assertEqual(apply('p@ssW0rdp@ssW0rd', 'd'), 'p@ssW0rd')

    def test_duplicate_n(self):
        self.assertEqual(apply('p@ssW0rdp@ssW0rdp@ssW0rd', 'p2'), 'p@ssW0rd')

    def test_reflect(self):
        self.assertEqual(apply('p@ssW0rddr0Wss@p', 'f'), 'p@ssW0rd')


if __name__ == '__main__':
    unittest.main()
