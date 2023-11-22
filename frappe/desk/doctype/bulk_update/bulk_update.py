# Copyright (c) 2015, Frappe Technologies and contributors
# License: MIT. See LICENSE

import frappe
from frappe import _
from frappe.core.doctype.submission_queue.submission_queue import queue_submission
from frappe.model.document import Document
from frappe.utils import cint
from frappe.utils.scheduler import is_scheduler_inactive


class BulkUpdate(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		condition: DF.SmallText | None
		document_type: DF.Link
		field: DF.Literal
		limit: DF.Int
		update_value: DF.SmallText
	# end: auto-generated types
	@frappe.whitelist()
	def bulk_update(self):
		self.check_permission("write")
		limit = self.limit if self.limit and cint(self.limit) < 500 else 500

		condition = ""
		if self.condition:
			if ";" in self.condition:
				frappe.throw(_("; not allowed in condition"))

			condition = f" where {self.condition}"

		docnames = frappe.db.sql_list(
			f"""select name from `tab{self.document_type}`{condition} limit {limit} offset 0"""
		)
		return submit_cancel_or_update_docs(
			self.document_type, docnames, "update", {self.field: self.update_value}
		)


@frappe.whitelist()
def submit_cancel_or_update_docs(doctype, docnames, action="submit", data=None):
	docnames = frappe.parse_json(docnames)

	if data:
		data = frappe.parse_json(data)

	failed = []

	for i, d in enumerate(docnames, 1):
		doc = frappe.get_doc(doctype, d)
		try:
			message = ""
			if action == "submit" and doc.docstatus.is_draft():
				if doc.meta.queue_in_background and not is_scheduler_inactive():
					queue_submission(doc, action)
					message = _("Queuing {0} for Submission").format(doctype)
				else:
					doc.submit()
					message = _("Submitting {0}").format(doctype)
			elif action == "cancel" and doc.docstatus.is_submitted():
				doc.cancel()
				message = _("Cancelling {0}").format(doctype)
			elif action == "update" and not doc.docstatus.is_cancelled():
				doc.update(data)
				doc.save()
				message = _("Updating {0}").format(doctype)
			else:
				failed.append(d)
			frappe.db.commit()
			show_progress(docnames, message, i, d)

		except Exception:
			failed.append(d)
			frappe.db.rollback()

	return failed


def show_progress(docnames, message, i, description):
	n = len(docnames)
	frappe.publish_progress(float(i) * 100 / n, title=message, description=description)
