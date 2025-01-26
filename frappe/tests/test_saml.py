# Copyright (c) 2022, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE

import base64
import os
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, unquote, urljoin, urlparse
import zlib

from requests import Request

from frappe.integrations.doctype.saml_login_key.saml_login_key import SamlLoginKey
import requests
from werkzeug.test import TestResponse

import frappe
from frappe.integrations.oauth2 import encode_params
from frappe.tests import IntegrationTestCase
from frappe.tests.test_api import get_test_client, make_request, suppress_stdout
from frappe.tests.utils import make_test_records

if TYPE_CHECKING:
	from frappe.integrations.doctype.social_login_key.social_login_key import SocialLoginKey

from onelogin.saml2.auth import OneLogin_Saml2_Auth,OneLogin_Saml2_Utils
import json
from os.path import dirname, join, exists

class TestSaml(IntegrationTestCase):
    # settings_path = "/workspace/development/castlecraft-bench/apps/frappe/frappe/tests/settings"
    app_path = frappe.get_app_path('frappe')
    settings_path = os.path.join(app_path, 'tests', 'settings')

    def loadSettingsJSON(self, name="settings1.json"):
        filename = join(self.settings_path, name)
        if exists(filename):
            stream = open(filename, "r")
            settings = json.load(stream)
            stream.close()
            return settings

    def testSAMLRequest(self):
        settings_info = self.loadSettingsJSON()
        saml_key= frappe.get_doc(settings_info).insert()
        saml_settings = {
			"sp": {
				"entityId": saml_key.sp_entity_id,
				"assertionConsumerService": {
					"url": frappe.utils.get_url(f"/api/method/frappe.integrations.saml2.acs?provider={saml_key.name}"),
					"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
				},
				"privateKey":saml_key.get_password('sp_private_key'),
				"x509cert": saml_key.sp_x509cert,
			},
			"idp": {
				"entityId": saml_key.idp_entity_id,
				"singleSignOnService": {
					"url": saml_key.idp_sso_url,
					"binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
				},
				"x509cert": saml_key.idp_x509cert,
			},
			"security": {
				"authnRequestsSigned": True,  # Sign SAML authentication requests
				"signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
				"digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
				"rejectUnsolicitedResponsesWithInResponseTo": False,
			}
		}
        request_data={
			"http_host":"saml.localhost",
			"script_name":frappe.utils.get_url(f"/api/method/frappe.integrations.saml2.acs?provider={saml_key.name}"),
			"query_string":f"provider={saml_key.name}",
		}
        client = OneLogin_Saml2_Auth(request_data, saml_settings)
        redirect_url = client.login()
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)
        SAMLRequest = unquote(query_params['SAMLRequest'][0])
        self.assertTrue(OneLogin_Saml2_Utils.decode_base64_and_inflate(SAMLRequest))