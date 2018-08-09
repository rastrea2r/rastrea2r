
#import rastrea2r
import unittest


class BasicTestCase(unittest.TestCase):
    ''' Basic test cases '''

    def test_basic(self):
        ''' check True is True '''
        self.assertTrue(True)

    @unittest.skip("Temporary skipping")
    def test_version(self):
        ''' check rastrea2r exposes a version attribute '''
        self.assertTrue(hasattr(rastrea2r, '__version__'))
        self.assertIsInstance(rastrea2r.__version__, str)


if __name__ == '__main__':
    unittest.main()
