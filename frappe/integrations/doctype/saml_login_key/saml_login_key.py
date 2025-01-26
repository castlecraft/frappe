# Copyright (c) 2024, Frappe Technologies and contributors
# For license information, please see license.txt

# import frappe
import frappe
from frappe.model.document import Document


class SamlLoginKey(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		enable_saml_login: DF.Check
		idp_entity_id: DF.Data | None
		idp_sso_url: DF.Data | None
		idp_x509cert: DF.Text | None
		provider_name: DF.Data
		sp_entity_id: DF.Data | None
		sp_private_key: DF.Password | None
		sp_x509cert: DF.SmallText | None
	# end: auto-generated types

	def autoname(self):
		self.name = frappe.scrub(self.provider_name)
  
  
	@frappe.whitelist()
	def get_saml_login_provider(self, provider, initialize=False):
		providers = {}


		providers["Keycloak"] = {
			"enable_saml_login":1,
			"provider_name":"Keycloak",
			"sp_entity_id":"frappe-saml",
			"sp_x509cert":"MIICpTCCAY0CBgGTYflO/zANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAtmcmFwcGUtc2FtbDAeFw0yNDExMjUwNjE3MjhaFw0zNDExMjUwNjE5MDhaMBYxFDASBgNVBAMMC2ZyYXBwZS1zYW1sMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0lU9Kqx7zweAYQG6qlUWjvcEktaA3zUjSEbagYgZxzd70rr30eYbvQCXUsoGKtr/HN4pugpS6mGnILkLeHSKcs8R3zgY0hyaJRjg7r/LOBydF2PNbn56XaxEn2QG4QZRM9u3ZY0/hrLbXivp1lcDiQ4JVnGjj8Um47Jnt5mKskDXAKK4f5Y/7nbF53lYLNLSu6rQOt8xrmVif558T00ifrN59TnMPUKvvnqBuVws0Nd0E/8t2CPoAnC7ElvztScSMib7j4dCQqxH64LZ5/xwAtKqKwdxX7AMSf5LvfgFqU5t3s6iVpyotIFDeu1Dd289ApvKlhqkRYFQH3Y0UnVStwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCmlUB6wYePOoerKUTg5SVmR1h3ZFoWnb99I4DJmLbMx3Vv46satd2j2lCjl8RssuOYzsveN6vhtI05hUzZHqwymwQ9Q+6bYyWSlBA5cSEs72aXMkXI6wCg7Kf1KiC/P/aMjJ/J1MPKcMCEfSdIyjcvm7QQmM4RmixYBkoyGHBUHSdaAkFqEhUDoUioV4xZ39aJnWBTPu3FZKRJ2mw8N6ICBQuz1oQ27VUL3UoW0a7PK//UWKMHoET2uPK67J5PoTLBbs9saJYWEJY6pes57ZK0Jq2dGiTp9/lOfPMkuxiKbolc2RZUzyQOAuwJQOferZjJ4yLALb0AnKP0Bg1NcExB",
			"sp_private_key":"MIIEpAIBAAKCAQEA0lU9Kqx7zweAYQG6qlUWjvcEktaA3zUjSEbagYgZxzd70rr30eYbvQCXUsoGKtr/HN4pugpS6mGnILkLeHSKcs8R3zgY0hyaJRjg7r/LOBydF2PNbn56XaxEn2QG4QZRM9u3ZY0/hrLbXivp1lcDiQ4JVnGjj8Um47Jnt5mKskDXAKK4f5Y/7nbF53lYLNLSu6rQOt8xrmVif558T00ifrN59TnMPUKvvnqBuVws0Nd0E/8t2CPoAnC7ElvztScSMib7j4dCQqxH64LZ5/xwAtKqKwdxX7AMSf5LvfgFqU5t3s6iVpyotIFDeu1Dd289ApvKlhqkRYFQH3Y0UnVStwIDAQABAoIBAAKqcufZhd4xxaU1G9Yfs33cLlzTRtURqthg5tm+K0qJ/+uH/siQKtPEdGJFmwcjjpBlzWEewi1oYLWYbouvqFDk7ukWqPXf+yEZtIW5msfwhBogKCIIWXqeqG6IVlIdvdB3e0WcqZcoj6Np0QESsIYl8G3CJwcu0vEPH9arYWvxIH4TQCtd0gPaMlzE6xlZ9ktK+y1prVX1hJvrC+rIU9jptUZPxS52l7bLuniUpP9dlGwpnj8QFo8g+PwPqw3Nnm94rgsxZhAu8DtrgAYe+u84uBdY/Nqu0YNYwq8GmEkCaUVl/6tGqGmSFZ1K6fauj1cwuWxPThLtu61SvLBgZTUCgYEA6gkWsLpluumFceRz/0y5BHIU9DluPPaXVAs+TlF6o/ypglhYKZtk/68cgoXViyRQnAoBqaOupQ9IjlWpf2+ZIU0QwAhhVkcuoSV1kfkA/LQbHmQPDaN5CutEt8B5m2rENJ3WAfCwfP2GhLSNGjqpEGtTWsqSfY4byGIZXffLwMsCgYEA5hKs+8vulMGRHUQEADnr/lQ0j1vHKiYCql8Sg1U+kflA7EE4NdvTVtmyXG21gUd3E/27ZRKLq8s0YrPYhbbbTBVjGlVCHWxH3bUckHy7U/kyJ1sY1QHbCkcFttyqwErBh99NVv43OH8IOnZJYM6QucLfgFBzAOkd/D3wUR2flEUCgYEAg+HZQn/XgevEQjkN0OkoPcQX4MRYRcxj3H11f+bUaIKh9wzXqaKi2J6SP08x1fYB4tyUsUbGzMb/CQ5mtKRrs2NdNAnE6Dy2nyKfzUF3d+/6dDbIcNQVCr0nfTDelmEk7c2f4noCynyHiFLCTOyPhuwkDb6nrE8fgt0dFGHmFN8CgYAo4JCTfDw7edjKllcPozrmyRc9kVTljDNVCedEJlUjomGCmGPgTdpSyAMEoQlqmsPxbVdqMc1XDJeWIdYKi96SugoNl7BTgfWS0qbslPzDgrcCfxD+Z4H/ZXcCclp0J9QSy/31wt0U0J0ppfKLnKfiGVmUdra4JrMJKggUoWrE8QKBgQCdEmiWCW26E7YfOvQnWPXOkmbDB4cgEQFx8tI+yUeUrrpwBYJE6qLMiCaWIc7NRtuOc5hEjNXnOa/4htR5t6WUB57H8Jk0xhUNvuEwvOXmutLPul6m/KFFliNHhVaJDwEdp1L+43r9efD/JREC/RCQ0wtrQo0MMo+33MQwgsO0Jw==",
			"idp_entity_id":"http://localhost/realms/frappe",
			"idp_x509cert":"MIICmzCCAYMCBgGTYfZltzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZmcmFwcGUwHhcNMjQxMTI1MDYxNDE4WhcNMzQxMTI1MDYxNTU4WjARMQ8wDQYDVQQDDAZmcmFwcGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7jkbDqhYZeiBxSeCqDyim+WJk2j/ipBxBAj/Iv+RholFY9ZnkKE8ZKvLwfeumOk3GlwDdMfvQwX+PKf5ChlLlb4GxU51jb5a/2zZ6PoVz/dpWGywJe3FtoCcB6qQIX5hBxx8ciygz8kUT6H363ALRg2QlDMxHIk+Iv/vyF1ATzhvE1JjruJ+rrHZmr8JyXvpoohifTE3spHJVxXdzeF7eRwPGvKmB0F+pKidul4zOGd2H5G1gIpX/X/L4+CypqVP1xtspDh3NuVw3tZPnju4qni+SnnP1X4mNB5T6UHanEiAeXVWT6ZuHguE7lxrB7r7J9F/sCua/J/6ONfixEt3DAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABrwmmrlCNrrdSg7dGWartvjpbLtXAGUsZrZJS72mwnxdYyq7OWLVUi+0GqamWW3RaLOKNklz9+ZiY4UG2e23KlLGItf0AgLe50HhzcPW/ceD5GYmn/H2HMMz1x3BBf47pA8uGvNHk+6+3ttw5sihDr37N9bN/AvMvcrCR0s9VdQf/18sgnA0Z1pQF/9UzTdBNLEdmzVf07xHm3BQ+TA6z3JXcSQ/19gjWr5wRlMQC+B8AFkR5ck+xcBRIMU2FtZqUp4zAJEZVe6srxHD5rprz7iVaMQ9P1/ESWq0I/VsptJ1/uTTmrOorm/meAMNWpuCNqzyxDM/kaSlIjJM3ZuwDE=",
			"idp_sso_url":"http://localhost/realms/frappe/protocol/saml"
		}
		# Initialize the doc and return, used in patch
		# Or can be used for creating key from controller
		if initialize and provider:
			for k, v in providers[provider].items():
				setattr(self, k, v)
			return

		return providers.get(provider) if provider else providers