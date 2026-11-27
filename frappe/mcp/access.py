# Copyright (c) 2026, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE
"""Site policy shared by MCP and OAuth clients registered for MCP."""

import frappe
from frappe.permissions import SYSTEM_USER_ROLE

MCP_ENDPOINT = "/api/v2/mcp"
MCP_SCOPE = "mcp"


def additional_roles() -> set[str]:
	return {row.role for row in frappe.get_system_settings("additional_mcp_roles") or ()}


def allows(roles: set[str]) -> bool:
	return SYSTEM_USER_ROLE in roles or not roles.isdisjoint(additional_roles())
