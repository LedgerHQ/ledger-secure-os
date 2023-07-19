/**
 * SPDX-FileCopyrightText: © 2023 Ledger SAS <opensource-os@ledger.fr>
 * SPDX-License-Identifier: LicenseRef-source-code-accessibility-1.0
 */

#define DASHBOARD_ENTRY_POINT_H

// Dashboard entry point.

// This prototype is actually a (generic) alias, and is
// the entry point of the dashboard when Bolos' scheduler
// create the associated task and switches to it.
void init_task(void);