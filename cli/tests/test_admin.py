import importlib.machinery
import importlib.util
import json
import io
import contextlib
import shlex
import ssl
import urllib.error
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
        self.assertEqual(message['Subject'], 'Set up your illumos and OpenIndiana account')
        self.assertLess(message.get_content().index(self.receipt()['onboarding_url']), message.get_content().index('sign in'))
        self.assertIn('Your sign-in username is: alice\n', message.get_content())
        self.assertIn('Use this username and your chosen password to sign in.', message.get_content())

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

class DiagnosticTests(unittest.TestCase):
    receipt = AdminTests.receipt
    reset_receipt = AdminTests.reset_receipt

    def http_error(self, payload, status=409):
        return urllib.error.HTTPError('https://admin.example.test', status, 'failure', {}, io.BytesIO(payload))

    def test_structured_diagnostic_survives_request_and_json_output(self):
        body = {'code': 'barycenter::account::invitation_pending',
                'message': 'Account has not been activated.', 'help': 'Use the invitation.',
                'request_id': 'req-123', 'private_extra': 'never-print-this'}
        opener = MagicMock()
        opener.open.side_effect = self.http_error(json.dumps(body).encode())
        with patch.object(admin, 'secret', return_value='private-token'), patch.object(admin.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaises(admin.Failure) as caught:
                admin.request({'admin_url': 'https://admin.example.test', 'admin_token_file': 'not-read'},
                              'POST', '/admin/password-resets', {'username': 'tm'})
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            admin.report(caught.exception, 'reset-password for tm', 'json')
        diagnostic = json.loads(output.getvalue())
        self.assertEqual(diagnostic['code'], body['code'])
        self.assertEqual(diagnostic['help'], body['help'])
        self.assertEqual(diagnostic['status'], 409)
        self.assertEqual(diagnostic['request_id'], 'req-123')
        self.assertNotIn('never-print-this', output.getvalue())
        self.assertNotIn('private-token', output.getvalue())

    def test_legacy_conflict_explains_requirements_without_inventing_state(self):
        error = admin.api_failure(self.http_error(b'Account is not eligible for email recovery'),
                                  'POST', '/admin/password-resets')
        self.assertIn('not eligible', str(error))
        self.assertIn('existing, enabled account', error.help)
        self.assertIn('If the account', error.help)
        self.assertNotIn('invitation_pending', error.code)

    def test_bad_bodies_fall_back_without_echoing_them(self):
        for body in (b'<html>private-secret</html>', b'{', b'null', b'[]', b'\xff',
                     b'private-secret' * 2000,
                     b'{"code":5,"message":"private-secret"}',
                     b'{"code":"barycenter::bad","message":[]}',
                     json.dumps({'code': 'barycenter::bad', 'message': 'x' * 2049}).encode()):
            with self.subTest(body=body[:40]):
                error = admin.api_failure(self.http_error(body), 'POST', '/admin/password-resets')
                self.assertEqual(error.code, 'barycenter::api::http')
                self.assertEqual(error.status, 409)
                self.assertNotIn('private-secret', str(error))

    def test_terminal_controls_are_removed(self):
        error = admin.Failure('bad\x1b[2J\nmessage', help='help\rtext', request_id='id\x1b')
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            admin.report(error, 'operation', 'text')
        self.assertNotIn('\x1b', output.getvalue())
        self.assertNotIn('\r', output.getvalue())
        self.assertEqual(len(output.getvalue().splitlines()), 4)

    def test_transport_errors_keep_distinct_codes_without_raw_secrets(self):
        for reason, code in ((ssl.SSLCertVerificationError('private-secret'), 'tls'),
                             (TimeoutError('private-secret'), 'connection')):
            opener = MagicMock()
            opener.open.side_effect = urllib.error.URLError(reason)
            with patch.object(admin, 'secret', return_value='private-token'), patch.object(admin.urllib.request, 'build_opener', return_value=opener):
                with self.assertRaises(admin.Failure) as caught:
                    admin.request({'admin_url': 'https://admin.example.test', 'admin_token_file': 'not-read'}, 'POST', '/admin/password-resets')
            self.assertEqual(caught.exception.code, 'barycenter::api::' + code)
            self.assertNotIn('private-secret', str(caught.exception))

    def test_partial_delivery_has_exact_quoted_retry_and_preserves_token(self):
        with tempfile.TemporaryDirectory(prefix='receipt test ') as directory:
            config = Path(directory) / 'custom config.json'
            config.write_text(json.dumps({'public_url': 'https://auth.example.test',
                                         'receipt_dir': str(Path(directory) / 'receipts'),
                                         'smtp': {'password_file': 'unused'}}))
            config.chmod(0o600)
            output = io.StringIO()
            with patch.object(admin, 'request', return_value=self.reset_receipt()) as request, patch.object(admin, 'secret', return_value='private-password'), patch.object(admin, 'send', side_effect=admin.Failure('Delivery may be ambiguous.', code='barycenter::smtp::delivery')), contextlib.redirect_stderr(output), contextlib.redirect_stdout(io.StringIO()):
                result = admin.main(['--config', str(config), '--error-format', 'json', 'reset-password', 'alice'])
            self.assertEqual(result, 1)
            request.assert_called_once()
            diagnostic = json.loads(output.getvalue())
            self.assertIn('Link created and saved', diagnostic['context'])
            receipt_path = next((Path(directory) / 'receipts').glob('*.json'))
            command = diagnostic['help'].split('existing receipt: ', 1)[1]
            self.assertEqual(shlex.split(command), ['barycenter-admin', '--config', str(config), 'send', '--receipt', str(receipt_path)])
            self.assertEqual(admin.private_json(receipt_path)['reset_url'], self.reset_receipt()['reset_url'])
            self.assertNotIn('a' * 64, output.getvalue())

    def test_receipt_save_failure_reports_issuance_without_delivery(self):
        output = io.StringIO()
        with patch.object(admin, 'private_json', return_value={'public_url': 'https://auth.example.test'}), patch.object(admin, 'request', return_value=self.reset_receipt()), patch.object(admin, 'save_receipt', side_effect=OSError('private-secret')), patch.object(admin, 'send') as send, contextlib.redirect_stderr(output):
            result = admin.main(['--error-format', 'json', 'reset-password', 'alice', '--no-send'])
        self.assertEqual(result, 1)
        send.assert_not_called()
        diagnostic = json.loads(output.getvalue())
        self.assertIn('link created', diagnostic['context'])
        self.assertIn('No email was sent', diagnostic['help'])
        self.assertNotIn('private-secret', output.getvalue())

    def test_expired_reset_does_not_suggest_invitation_or_resend(self):
        receipt = self.reset_receipt(); receipt['expires_at'] = 0
        output = io.StringIO()
        with patch.object(admin, 'private_json', side_effect=[{'public_url': 'https://auth.example.test'}, receipt]), patch.object(admin, 'send') as send, contextlib.redirect_stderr(output):
            result = admin.main(['--error-format', 'json', 'send', '--receipt', 'receipt.json'])
        self.assertEqual(result, 1)
        send.assert_not_called()
        diagnostic = json.loads(output.getvalue())
        self.assertEqual(diagnostic['code'], 'barycenter::receipt::expired')
        self.assertIn('new password reset', diagnostic['help'])
        self.assertNotIn('send --receipt', diagnostic['help'])

    def test_invalid_receipt_field_types_never_escape_as_tracebacks(self):
        for field, value in (('reset_url', []), ('email', 4), ('username', None), ('expires_at', 'tomorrow')):
            receipt = self.reset_receipt(); receipt[field] = value
            with self.subTest(field=field), self.assertRaises(admin.Failure) as caught:
                admin.validate_receipt({'public_url': 'https://auth.example.test'}, receipt)
            self.assertEqual(caught.exception.code, 'barycenter::receipt::invalid')

    def test_smtp_categories_do_not_expose_raw_server_errors(self):
        config = {'public_url': 'https://auth.example.test', 'smtp': {
            'host': 'smtp.example.test', 'from': 'notes@example.test',
            'username': 'notes', 'password_file': 'unused'}}
        for exception, code in ((admin.smtplib.SMTPAuthenticationError(535, b'private-secret'), 'authentication'),
                                (ssl.SSLCertVerificationError('private-secret'), 'tls'),
                                (admin.smtplib.SMTPRecipientsRefused({'alice@example.test': (550, b'private-secret')}), 'recipient'),
                                (TimeoutError('private-secret'), 'delivery')):
            with self.subTest(code=code), patch.object(admin.smtplib, 'SMTP', side_effect=exception):
                with self.assertRaises(admin.Failure) as caught:
                    admin.send(config, self.reset_receipt())
                self.assertEqual(caught.exception.code, 'barycenter::smtp::' + code)
                self.assertNotIn('private-secret', str(caught.exception))

    def test_missing_config_and_invalid_json_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            with self.assertRaises(admin.Failure) as caught:
                admin.private_json(path)
            self.assertEqual(caught.exception.code, 'barycenter::config::read')
            path.write_text('{"private-secret":'); path.chmod(0o600)
            with self.assertRaises(admin.Failure) as caught:
                admin.private_json(path)
            self.assertEqual(caught.exception.code, 'barycenter::config::json')
            self.assertNotIn('private-secret', str(caught.exception))

if __name__ == '__main__': unittest.main()
