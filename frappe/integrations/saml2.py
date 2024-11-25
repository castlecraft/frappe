import os
import frappe
from frappe import _
from onelogin.saml2.auth import OneLogin_Saml2_Auth

@frappe.whitelist(allow_guest=True)
def login(provider):
    # Fetch the SAML provider settings
    saml_key = frappe.get_doc('Saml Login Key', provider)
    if not saml_key:
        frappe.throw(_("SAML provider settings not found"))
    # Create the SAML settings dictionary
    saml_settings = {
        "sp": {
            "entityId": saml_key.sp_entity_id,
            "assertionConsumerService": {
                "url": frappe.utils.get_url(f"/api/method/frappe.integrations.saml2.acs?provider={provider}"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "privateKey": saml_key.sp_private_key,
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
    request_data = {
        "http_host": frappe.local.request.host,
        "server_port": frappe.local.request.environ.get("SERVER_PORT"),
        "script_name": frappe.utils.get_url(f"/api/method/frappe.integrations.saml2.acs?provider={provider}"),
        "query_string": frappe.local.request.environ.get("QUERY_STRING"),
        "https": "on" if frappe.local.request.scheme == "https" else "off",
    }
    

    client = OneLogin_Saml2_Auth(request_data, saml_settings)
    redirect_url = client.login()
    frappe.local.response["type"] = "redirect"
    frappe.local.response["location"] = redirect_url

@frappe.whitelist(allow_guest=True)
def acs():
    try:
        # Handle the SAML response
        post_data = dict(frappe.request.form.copy())
        query_data = dict(frappe.request.args.copy())
        request_data = {
            "http_host": frappe.local.request.host,
            "server_port": frappe.local.request.environ.get("SERVER_PORT"),
            "script_name": frappe.local.request.environ.get("PATH_INFO"),
            "post_data": post_data,
            "https": "on" if frappe.local.request.scheme == "https" else "off",
        }

        saml_key = frappe.get_doc("Saml Login Key", query_data.get("provider"))
        if not saml_key:
            frappe.respond_as_web_page(_("SAML Login Failed"), _("SAML configuration missing"), http_status_code=500)
            return

        # Create the SAML settings dictionary
        saml_settings = {
            "sp": {
                "entityId": saml_key.sp_entity_id,
                "assertionConsumerService": {
                    "url": frappe.utils.get_url("/api/method/frappe.integrations.saml2.acs"),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "signatureAlgorithm": "RSA_SHA256",
            },
            "idp": {
                "entityId": saml_key.idp_entity_id,
                "singleSignOnService": {
                    "url": saml_key.idp_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": saml_key.idp_x509cert,
            }
        }

        client = OneLogin_Saml2_Auth(request_data, saml_settings)
        client.process_response()

        errors = client.get_errors()
        if errors:
            frappe.respond_as_web_page(_("SAML Login Failed"), _("Invalid SAML response: ") + ", ".join(errors), http_status_code=403)
            return

        if not client.is_authenticated():
            frappe.respond_as_web_page(_("SAML Login Failed"), _("User not authenticated"), http_status_code=403)
            return

        # Extract user data
        user_email = client.get_nameid()
        if not user_email:
            frappe.respond_as_web_page(_("SAML Login Failed"), _("Email not found in SAML response"), http_status_code=403)
            return

        # Check if the user exists
        user = frappe.db.get_value("User", {"email": user_email})
        if not user:
            frappe.respond_as_web_page(_("SAML Login Failed"), _("User not found"), http_status_code=403)
            return

        # Log the user in
        frappe.local.login_manager.user = user
        frappe.local.login_manager.post_login()
        frappe.db.commit()

        # Redirect to workspace
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = frappe.utils.get_url("/app")
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), _("SAML Login Error"))
        frappe.respond_as_web_page(_("SAML Login Failed"), frappe.get_traceback(), http_status_code=500)