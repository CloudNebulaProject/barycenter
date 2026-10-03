import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

loader = importlib.machinery.SourceFileLoader('admin', str(Path(__file__).parents[1] / 'barycenter-admin'))
spec = importlib.util.spec_from_loader(loader.name, loader)
admin = importlib.util.module_from_spec(spec)
loader.exec_module(admin)

class AdminTests(unittest.TestCase):
    def receipt(self):
        return {'username': 'alice', 'email': 'alice@example.test', 'expires_at': int(time.time()) + 600,
                'onboarding_url': 'https://auth.example.test/onboarding#token=' + 'a' * 64}

    def test_transport_and_recipient_validation(self):
        config = {'public_url': 'https://auth.example.test'}
        admin.validate_receipt(config, self.receipt())
        for url in ['http://external.test', 'https://user:secret@example.test', 'https://example.test?token=x']:
            with self.assertRaises(admin.Failure): admin.endpoint(url)
        receipt = self.receipt(); receipt['onboarding_url'] = receipt['onboarding_url'].replace('auth.example.test', 'attacker.test')
        with self.assertRaises(admin.Failure): admin.validate_receipt(config, receipt)
        receipt = self.receipt(); receipt['expires_at'] = 0
        with self.assertRaises(admin.Failure): admin.validate_receipt(config, receipt)

    def test_private_receipt_and_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = admin.save_receipt({'receipt_dir': directory}, self.receipt())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(admin.private_json(path), self.receipt())
            path.chmod(0o644)
            with self.assertRaises(admin.Failure): admin.private_json(path)

    def test_smtp_uses_verified_starttls_and_receipt_token(self):
        config = {'public_url': 'https://auth.example.test', 'smtp': {'host': 'smtp.example.test', 'from': 'notes@example.test', 'username': 'notes', 'password_file': 'not-read'}}
        client = MagicMock(); client.__enter__.return_value = client; client.send_message.return_value = {}
        with patch.object(admin.smtplib, 'SMTP', return_value=client), patch.object(admin, 'secret', return_value='private-password'):
            admin.send(config, self.receipt())
        client.starttls.assert_called_once()
        self.assertEqual(client.starttls.call_args.kwargs['context'].verify_mode, admin.ssl.CERT_REQUIRED)
        message = client.send_message.call_args.args[0]
        self.assertIn(self.receipt()['onboarding_url'], message.get_content())

    def test_failed_send_keeps_receipt_without_reissuing(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config.json'
            config.write_text(json.dumps({'public_url': 'https://auth.example.test', 'receipt_dir': str(Path(directory) / 'receipts'), 'smtp': {'password_file': 'not-read'}})); config.chmod(0o600)
            with patch.object(admin, 'request', return_value=self.receipt()) as request, patch.object(admin, 'secret', return_value='private-password'), patch.object(admin, 'send', side_effect=admin.Failure('SMTP failed')):
                self.assertEqual(admin.main(['--config', str(config), 'invite', 'alice@example.test', '--username', 'alice']), 1)
                receipt = next((Path(directory) / 'receipts').glob('*.json'))
                self.assertEqual(request.call_count, 1)
            with patch.object(admin, 'request') as request, patch.object(admin, 'send'):
                self.assertEqual(admin.main(['--config', str(config), 'send', '--receipt', str(receipt)]), 0)
                request.assert_not_called()

    def reset_receipt(self):
        r = self.receipt(); r['kind'] = 'password-reset'
        r['reset_url'] = r.pop('onboarding_url').replace('/onboarding', '/password-reset')
        return r

    def test_reset_email_is_sent_only_to_server_verified_recipient(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config.json'
            config.write_text(json.dumps({'public_url': 'https://auth.example.test', 'receipt_dir': str(Path(directory) / 'receipts'), 'smtp': {'password_file': 'not-read'}})); config.chmod(0o600)
            with patch.object(admin, 'request', return_value=self.reset_receipt()) as request, patch.object(admin, 'secret', return_value='private-password'), patch.object(admin, 'send') as send:
                self.assertEqual(admin.main(['--config', str(config), 'reset-password', 'alice']), 0)
                self.assertEqual(request.call_args.args[2], '/admin/password-resets')
                self.assertEqual(request.call_args.args[3], {'username': 'alice', 'expires_in': 3600})
                self.assertEqual(send.call_args.args[1]['email'], 'alice@example.test')
                self.assertEqual(send.call_args.args[1]['kind'], 'password-reset')

    def test_reset_receipt_cannot_be_repurposed_as_invitation(self):
        config = {'public_url': 'https://auth.example.test'}
        r = self.reset_receipt(); admin.validate_receipt(config, r)
        r['reset_url'] = r['reset_url'].replace('/password-reset', '/onboarding')
        with self.assertRaises(admin.Failure): admin.validate_receipt(config, r)
        r['kind'] = 'unknown'
        with self.assertRaises(admin.Failure): admin.validate_receipt(config, r)

    def test_redirects_never_forward_admin_credential(self):
        with self.assertRaises(admin.Failure): admin.NoRedirect().redirect_request(None, None, None, None, None, None)

if __name__ == '__main__': unittest.main()
