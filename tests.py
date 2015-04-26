#!/usr/bin/env python
import unittest
from instarecon import *
import ipaddress as ipa
class TestHostMethods(unittest.TestCase):
    
    def test_network(self):
        net = ipa.ip_network(u'8.8.8.0/26',strict=False)
        network = Network([net])
        network.reverse_lookup_on_related_cidrs(True)
    
    # def test_upper(self):
    #     self.assertEqual('foo'.upper(), 'FOO')

    # def test_isupper(self):
    #     self.assertTrue('FOO'.isupper())
    #     self.assertFalse('Foo'.isupper())

    # def test_split(self):
    #     s = 'hello world'
    #     self.assertEqual(s.split(), ['hello', 'world'])
    #     # check that s.split fails when the separator is not a string
    #     with self.assertRaises(TypeError):
    #         s.split(2)

if __name__ == '__main__':
    unittest.main()