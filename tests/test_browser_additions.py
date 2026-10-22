import unittest
from hotturkey.browser_additions import site_target
from hotturkey.model import PolicyError,matches

class BrowserAdditionTargets(unittest.TestCase):
    def test_domain_has_no_private_url_components(self):
        self.assertEqual(site_target('https://Sub.Example.com:8443/a?secret=value#token','domain'),'sub.example.com')
    def test_decoded_page_prefix_matches_without_saving_query(self):
        url='https://example.com/%E4%B8%AD%E6%96%87/a%20b?secret=x#key'
        target=site_target(url,'page')
        self.assertEqual(target,'https://example.com/中文/a b');self.assertTrue(matches(target,url))
    def test_fully_qualified_domain_matches(self):
        url='https://example.com./a';self.assertTrue(matches(site_target(url,'domain'),url))
    def test_international_domain_matches(self):
        url='https://例子.中国/a';target=site_target(url,'domain')
        self.assertEqual(target,'xn--fsqu00a.xn--fiqs8s');self.assertTrue(matches(target,url))
    def test_ipv6_supported_by_existing_matcher(self):
        url='http://[::1]:8080/a?secret=x'
        for scope in ['domain','page']:self.assertTrue(matches(site_target(url,scope),url))
    def test_rejects_credentials_internal_pages_and_invalid_urls(self):
        for url in ['https://user:secret@example.com/a','edge://settings','file:///tmp/a','javascript:alert(1)','https://','https://example.com:bad/a','https://exam*ple.com','https://example.com/\n','x'*8193,None]:
            with self.subTest(url=url),self.assertRaises(PolicyError):site_target(url,'domain')
    def test_page_does_not_create_wildcards_or_control_characters(self):
        for path in ['/a*','/a%2A','/a%0A']:
            with self.assertRaises(PolicyError):site_target('https://example.com'+path,'page')
        with self.assertRaises(PolicyError):site_target('https://example.com','arbitrary')
