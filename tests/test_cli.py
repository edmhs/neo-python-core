from unittest import TestCase
from neocore.bin import cli
import subprocess
import warnings
import neocore

from io import StringIO
from unittest.mock import patch


class CliTestCase(TestCase):

    @classmethod
    def setUpClass(cls):
        parser = cli.create_parser()
        cls.parser = parser

    def test_main(self):

        with self.assertRaises(SystemExit) as cm:
            cli.main()

        warnings.filterwarnings('ignore', category=ResourceWarning)  # filters warnings about subprocess files still being open

        version = subprocess.Popen(['np-utils', '--version'], stdout=subprocess.PIPE)
        self.assertIn(neocore.__version__, version.stdout.read().decode('utf-8'))

        print_help = subprocess.Popen(['np-utils', '--h'], stdout=subprocess.PIPE)
        self.assertIn("help", print_help.stdout.read().decode('utf-8'))


class CliArgFunctionTest(CliTestCase):

    def test_address_to_scripthash(self):
        args = self.parser.parse_args(['--address-to-scripthash', 'AG67szmqEToCuZVdPk4VaJM8kVSBrwe4M9'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertIn("0x32708958636c2c7c37388053ad447b5f425e7303", result.getvalue().strip())
            self.assertIn("03735e425f7b44ad538038377c2c6c6358897032", result.getvalue().strip())

    def test_address_to_scripthash_error(self):
        args = self.parser.parse_args(['--address-to-scripthash', 'abc'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_scripthash_to_address_1(self):
        args = self.parser.parse_args(['--scripthash-to-address', '32708958636c2c7c37388053ad447b5f425e7303'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertIn("ALNaFGDy2MNd8xBnhxgngTczkyiVDtGFP5", result.getvalue().strip())
            self.assertIn("0x03735e425f7b44ad538038377c2c6c6358897032", result.getvalue().strip())

    def test_scripthash_to_address_2(self):
        args = self.parser.parse_args(['--scripthash-to-address', '0x32708958636c2c7c37388053ad447b5f425e7303'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual("AG67szmqEToCuZVdPk4VaJM8kVSBrwe4M9", result.getvalue().strip())

    def test_scripthash_to_address_error(self):
        args = self.parser.parse_args(['--scripthash-to-address', 'abc'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_create_wallet(self):
        args = self.parser.parse_args(['--create-wallet'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertIn("private_key", result.getvalue().strip())
            self.assertIn("address", result.getvalue().strip())
            self.assertIn("script_hash", result.getvalue().strip())
            self.assertIn("public_key", result.getvalue().strip())

    def test_wif_to_wallet(self):
        args = self.parser.parse_args(['--wif-to-wallet', 'L4qYtZTHMMVkVrTrhHNKMpm1ebPKVJecKzFYh5NQQEXJsd2UDrxk'])

        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertIn("L4qYtZTHMMVkVrTrhHNKMpm1ebPKVJecKzFYh5NQQEXJsd2UDrxk", result.getvalue().strip())
            self.assertIn("AG67szmqEToCuZVdPk4VaJM8kVSBrwe4M9", result.getvalue().strip())
            self.assertIn("0x32708958636c2c7c37388053ad447b5f425e7303", result.getvalue().strip())
            self.assertIn("03b1205ad46fdaf853478d40b5d22aa8c04881c20353a706dd352b203df4a73e50", result.getvalue().strip())

    def test_wif_to_wallet_address(self):
        args = self.parser.parse_args(['--wif-to-wallet', 'abc'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_wif_to_private_key(self):
        args = self.parser.parse_args(['--wif-to-private-key', 'L4qYtZTHMMVkVrTrhHNKMpm1ebPKVJecKzFYh5NQQEXJsd2UDrxk'])

        # convert to string
        priv_string = str(b'\xe3L\x91\xb5i\xf3\xc0\xe0IW\xc1o\x12 `?\xa7\x8c\xf2\xfa=k\xb3\x17\xb05\x02&\xe2C\xff\x88')

        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual(priv_string, result.getvalue().strip())

    def test_wif_to_private_key_error(self):
        args = self.parser.parse_args(['--wif-to-private-key', 'abc'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_wif_to_nep2(self):
        args = self.parser.parse_args(['--wif-to-nep2', 'L4qYtZTHMMVkVrTrhHNKMpm1ebPKVJecKzFYh5NQQEXJsd2UDrxk', 'test'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual("6PYLodtrt42v3R4NiyMoDEkcNMS4b8eVoYqDzAwjrfGAYQHqv1jdcqR2jp", result.getvalue().strip())

    def test_wif_to_nep2_error(self):
        args = self.parser.parse_args(['--wif-to-nep2', 'abc', 'test'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_wif_to_address(self):
        args = self.parser.parse_args(['--wif-to-address', 'L4qYtZTHMMVkVrTrhHNKMpm1ebPKVJecKzFYh5NQQEXJsd2UDrxk'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual("AG67szmqEToCuZVdPk4VaJM8kVSBrwe4M9", result.getvalue().strip())

    def test_wif_to_address_system_error(self):
        args = self.parser.parse_args(['--wif-to-address', 'abc'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_wif_to_public_key(self):
        args = self.parser.parse_args(['--wif-to-public-key', 'L4qYtZTHMMVkVrTrhHNKMpm1ebPKVJecKzFYh5NQQEXJsd2UDrxk'])

        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual("03b1205ad46fdaf853478d40b5d22aa8c04881c20353a706dd352b203df4a73e50", result.getvalue().strip())

    def test_wif_to_public_key_error(self):
        args = self.parser.parse_args(['--wif-to-public-key', 'abc'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_wif_to_scripthash(self):
        args = self.parser.parse_args(['--wif-to-scripthash', 'L4qYtZTHMMVkVrTrhHNKMpm1ebPKVJecKzFYh5NQQEXJsd2UDrxk'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual("0x32708958636c2c7c37388053ad447b5f425e7303", result.getvalue().strip())

    def test_wif_to_scripthash_error(self):
        args = self.parser.parse_args(['--wif-to-scripthash', 'abc'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_nep2_to_wif(self):
        args = self.parser.parse_args(['--nep2-to-wif', '6PYLodtrt42v3R4NiyMoDEkcNMS4b8eVoYqDzAwjrfGAYQHqv1jdcqR2jp', 'test'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual("L4qYtZTHMMVkVrTrhHNKMpm1ebPKVJecKzFYh5NQQEXJsd2UDrxk", result.getvalue().strip())

    def test_nep2_to_wif_error(self):
        args = self.parser.parse_args(['--nep2-to-wif', 'abc', 'test'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_nep2_to_wallet(self):
        args = self.parser.parse_args(['--nep2-to-wallet', '6PYLodtrt42v3R4NiyMoDEkcNMS4b8eVoYqDzAwjrfGAYQHqv1jdcqR2jp', 'test'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertIn("L4qYtZTHMMVkVrTrhHNKMpm1ebPKVJecKzFYh5NQQEXJsd2UDrxk", result.getvalue().strip())
            self.assertIn("AG67szmqEToCuZVdPk4VaJM8kVSBrwe4M9", result.getvalue().strip())
            self.assertIn("0x32708958636c2c7c37388053ad447b5f425e7303", result.getvalue().strip())
            self.assertIn("03b1205ad46fdaf853478d40b5d22aa8c04881c20353a706dd352b203df4a73e50", result.getvalue().strip())

    def test_nep2_to_wallet_error(self):
        args = self.parser.parse_args(['--nep2-to-wallet', 'abc', 'test'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_nep2_to_address(self):
        args = self.parser.parse_args(['--nep2-to-address', '6PYLodtrt42v3R4NiyMoDEkcNMS4b8eVoYqDzAwjrfGAYQHqv1jdcqR2jp', 'test'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual("AG67szmqEToCuZVdPk4VaJM8kVSBrwe4M9", result.getvalue().strip())

    def test_nep2_to_address_error(self):
        args = self.parser.parse_args(['--nep2-to-address', 'abc', 'test'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_nep2_to_public_key(self):
        args = self.parser.parse_args(['--nep2-to-public-key', '6PYLodtrt42v3R4NiyMoDEkcNMS4b8eVoYqDzAwjrfGAYQHqv1jdcqR2jp', 'test'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual("03b1205ad46fdaf853478d40b5d22aa8c04881c20353a706dd352b203df4a73e50", result.getvalue().strip())

    def test_nep2_to_public_key_error(self):
        args = self.parser.parse_args(['--nep2-to-public-key', 'abc', 'test'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    def test_nep2_to_script_hash(self):
        args = self.parser.parse_args(['--nep2-to-scripthash', '6PYLodtrt42v3R4NiyMoDEkcNMS4b8eVoYqDzAwjrfGAYQHqv1jdcqR2jp', 'test'])
        with patch('sys.stdout', new=StringIO()) as result:
            cli.cli_functions(args)
            self.assertEqual("0x32708958636c2c7c37388053ad447b5f425e7303", result.getvalue().strip())

    def test_nep2_to_script_hash_error(self):
        args = self.parser.parse_args(['--nep2-to-scripthash', 'abc', 'test'])
        with self.assertRaises(SystemExit) as cm:
            cli.cli_functions(args)
            self.assertEqual(cm.exception, "ValueError")

    if __name__ == "__main__":
        cli.main()
